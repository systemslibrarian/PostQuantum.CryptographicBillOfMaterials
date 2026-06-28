using PostQuantum.CryptographicBillOfMaterials.Analysis.Engine;
using PostQuantum.CryptographicBillOfMaterials.Configuration;
using PostQuantum.CryptographicBillOfMaterials.Diff;
using PostQuantum.CryptographicBillOfMaterials.Knowledge;
using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Reporting;
using PostQuantum.CryptographicBillOfMaterials.Scoring;

namespace PostQuantum.CryptographicBillOfMaterials.Cli;

/// <summary>Orchestrates a scan: resolve target → analyze → assemble CBOM → render → exit code.</summary>
internal static class ScanRunner
{
    public static async Task<int> RunAsync(ScanOptions options)
    {
        string target = Path.GetFullPath(options.Target);
        var diagnostics = new List<string>();

        CbomConfig? config = ConfigLoader.Load(options.ConfigPath, target, diagnostics);
        if (config is not null)
        {
            if (!options.FailOnSet && config.FailOn is not null)
                options.FailOn = Levels.ParseFailOn(config.FailOn);
            if (!options.FormatsSet && config.Formats is { Length: > 0 })
                options.Formats = config.Formats.ToList();
        }

        // Resolve the policy profile: CLI --profile wins, then config, else the conservative default.
        string? requestedProfile = options.Profile ?? config?.Profile;
        if (requestedProfile is not null && !PolicyProfile.IsKnown(requestedProfile))
            diagnostics.Add($"config: unknown profile '{requestedProfile}'; using 'general'. "
                + $"Known: {string.Join(", ", PolicyProfile.Names)}.");
        PolicyProfile profile = PolicyProfile.Get(requestedProfile);

        string baseDirectory = File.Exists(target) ? Path.GetDirectoryName(target) ?? "." : target;

        KnowledgeBase knowledgeBase = KnowledgeBase.LoadDefault();
        var registry = DetectorRegistry.CreateDefault(knowledgeBase);
        var engine = new ScanEngine(registry);

        if (config is not null)
            ValidateConfig(config, registry, diagnostics);

        ResolvedScan resolved;
        try
        {
            resolved = await TargetResolver.ResolveAsync(
                target, diagnostics, options.MsBuildProperties, options.Restore);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 3;
        }

        var projects = new List<ProjectInventory>();
        var frameworks = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var summaries = new List<AppliedConfigSummary>();
        int analyzed = 0, failed = 0;

        HashSet<string>? changedSet = options.ChangedFiles is { Count: > 0 }
            ? options.ChangedFiles.Select(NormalizePath).ToHashSet(StringComparer.OrdinalIgnoreCase)
            : null;
        if (changedSet is not null)
            diagnostics.Add($"PR mode: findings restricted to {changedSet.Count} changed file(s).");

        foreach (LoadedProject lp in resolved.Projects)
        {
            if (!lp.Ok || lp.Compilation is null)
            {
                failed++;
                diagnostics.Add($"project '{lp.Name}' NOT analyzed (treated as unknown, not clean): "
                    + (lp.FailureReason ?? "load failed; see workspace diagnostics above."));
                projects.Add(new ProjectInventory { Name = lp.Name, FilePath = lp.Path, Analyzed = false });
                continue;
            }

            analyzed++;
            foreach (string t in lp.TargetFrameworks)
                frameworks.Add(t);

            CompilationScanResult result = engine.Analyze(lp.Compilation);
            foreach (ScanDiagnostic d in result.Diagnostics)
                diagnostics.Add($"{lp.Name}/{d.Source}: {d.Message}");

            IReadOnlyList<CryptoFinding> roslyn =
                FindingPostProcessor.Relativize(result.Findings, baseDirectory);

            // Dependency-aware inventory from the package manifest complements source analysis.
            IReadOnlyList<CryptoFinding> pkg =
                PackageCryptoInventory.Inventory(lp.Path, baseDirectory, diagnostics);

            IReadOnlyList<CryptoFinding> findings = pkg.Count == 0 ? roslyn : roslyn.Concat(pkg).ToList();

            ConfigApplicationResult applied = ConfigApplication.Apply(findings, config, profile, diagnostics);
            summaries.Add(applied.Summary);
            findings = applied.Findings;

            if (changedSet is not null)
                findings = findings.Where(f => changedSet.Contains(NormalizePath(f.Location.FilePath))).ToList();

            ReadinessResult readiness = ReadinessCalculator.Calculate(findings);
            projects.Add(new ProjectInventory
            {
                Name = lp.Name,
                FilePath = lp.Path,
                Analyzed = true,
                Findings = findings,
                ReadinessScore = readiness.Score,
                ReadinessTrivial = readiness.Trivial,
            });
        }

        var allFindings = projects.SelectMany(p => p.Findings).ToList();
        ReadinessResult solutionReadiness = ReadinessCalculator.Calculate(allFindings);

        var document = new CbomDocument
        {
            Metadata = new ScanMetadata
            {
                ToolName = ToolInfo.Name,
                ToolVersion = ToolInfo.Version,
                ProfileVersion = ToolInfo.ProfileVersion,
                CycloneDxSpecVersion = ToolInfo.CycloneDxSpecVersion,
                Timestamp = DateTimeOffset.UtcNow,
                SolutionName = resolved.SolutionName,
                TargetFrameworks = frameworks.ToArray(),
                ProjectsAnalyzed = analyzed,
                ProjectsFailed = failed,
                PolicyProfile = profile.Name,
                KnowledgeBaseVersion = knowledgeBase.Version,
                AppliedConfig = MergeSummaries(summaries),
            },
            Projects = projects,
            SolutionReadinessScore = solutionReadiness.Score,
        };

        document = ApplyBaselineStatus(document, options, diagnostics);

        Directory.CreateDirectory(options.OutputDir);
        WriteReports(document, options, diagnostics);
        RunBaselineDiff(document, options, diagnostics);

        if (!options.Quiet)
            ConsoleSummary.Print(document, diagnostics, options);

        return ComputeExitCode(document, allFindings, options);
    }

    private static string NormalizePath(string path) => path.Replace('\\', '/').TrimStart('.', '/');

    private static AppliedConfigSummary MergeSummaries(IReadOnlyList<AppliedConfigSummary> summaries)
    {
        if (summaries.Count == 0)
            return new AppliedConfigSummary();

        var waivers = new Dictionary<string, WaiverRecord>(StringComparer.Ordinal);
        foreach (WaiverRecord w in summaries.SelectMany(s => s.Waivers))
        {
            waivers[w.RuleId] = waivers.TryGetValue(w.RuleId, out WaiverRecord? e)
                ? e with { Count = e.Count + w.Count }
                : w;
        }

        return new AppliedConfigSummary
        {
            SuppressedByDisabledRule = summaries.Sum(s => s.SuppressedByDisabledRule),
            SuppressedByPathFilter = summaries.Sum(s => s.SuppressedByPathFilter),
            ElevatedByDataSensitivity = summaries.Sum(s => s.ElevatedByDataSensitivity),
            ElevatedByPolicyProfile = summaries.Sum(s => s.ElevatedByPolicyProfile),
            Waivers = waivers.Values.ToList(),
            ConfiguredRuleIds = summaries.SelectMany(s => s.ConfiguredRuleIds)
                .Distinct(StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal).ToList(),
        };
    }

    private static readonly HashSet<string> ValidFailOn =
        new(StringComparer.OrdinalIgnoreCase) { "critical", "high", "medium", "low", "none" };

    private static void ValidateConfig(CbomConfig config, DetectorRegistry registry, List<string> diagnostics)
    {
        var known = registry.Detectors.Select(d => d.Metadata.RuleId).ToHashSet(StringComparer.Ordinal);
        known.Add(PackageCryptoInventory.RuleId); // manifest-based inventory rule (not a Roslyn detector)

        if (config.Rules is not null)
        {
            foreach ((string id, RuleConfig rc) in config.Rules)
            {
                if (!known.Contains(id))
                    diagnostics.Add($"config: unknown rule id '{id}'.");
                if (rc.SeverityFloor is { } sf && Levels.ParseLevel(sf) is null)
                    diagnostics.Add($"config: invalid severityFloor '{sf}' for rule '{id}'.");
            }
        }

        if (config.FailOn is { } failOn && !ValidFailOn.Contains(failOn))
            diagnostics.Add($"config: invalid failOn '{failOn}' (expected critical|high|medium|low|none).");
    }

    /// <summary>
    /// When a baseline is supplied, stamp each finding's remediation status: a finding whose bom-ref is new
    /// is <c>New</c>; one whose risk rose above the baseline is <c>Regressed</c>; otherwise <c>Unchanged</c>.
    /// A config waiver takes precedence and is left as <c>Waived</c>. (Fixed findings live only in the diff.)
    /// </summary>
    private static CbomDocument ApplyBaselineStatus(CbomDocument document, ScanOptions options, List<string> diagnostics)
    {
        if (options.BaselinePath is null || !File.Exists(options.BaselinePath))
            return document;

        Dictionary<string, RiskLevel> baseline;
        try
        {
            using FileStream stream = File.OpenRead(options.BaselinePath);
            CbomDocument baseDoc = CbomReader.Read(stream);
            baseline = new Dictionary<string, RiskLevel>(StringComparer.Ordinal);
            foreach (CryptoFinding bf in baseDoc.AllFindings)
                if (bf.BomRef is { } r)
                    baseline[r] = bf.RiskLevel;
        }
        catch (Exception ex)
        {
            diagnostics.Add($"Baseline status mapping skipped: {ex.Message}");
            return document;
        }

        var projects = document.Projects.Select(p => p with
        {
            Findings = p.Findings.Select(f =>
            {
                if (f.Status == RemediationStatus.Waived)
                    return f;
                if (f.BomRef is not { } r || !baseline.TryGetValue(r, out RiskLevel prior))
                    return f with { Status = RemediationStatus.New };
                return f with { Status = f.RiskLevel > prior ? RemediationStatus.Regressed : RemediationStatus.Unchanged };
            }).ToList(),
        }).ToList();

        return document with { Projects = projects };
    }

    private static void RunBaselineDiff(CbomDocument current, ScanOptions options, List<string> diagnostics)
    {
        if (options.BaselinePath is null)
            return;

        try
        {
            using FileStream baselineStream = File.OpenRead(options.BaselinePath);
            CbomDocument baseline = CbomReader.Read(baselineStream);
            CbomDiff diff = DiffEngine.Compare(baseline, current);

            string path = Path.Combine(options.OutputDir, "cbom.diff.md");
            using (FileStream diffStream = File.Create(path))
                DiffReporter.Render(diff, diffStream);

            if (!options.Quiet)
            {
                Console.WriteLine();
                Console.WriteLine(
                    $"Baseline: quantum-vulnerable {diff.BaselineQuantumVulnerable} -> {diff.CurrentQuantumVulnerable}; "
                    + $"readiness {diff.BaselineReadiness} -> {diff.CurrentReadiness}; "
                    + $"resolved {diff.ResolvedCount}, new {diff.NewCount}, regressed {diff.RegressedCount}.");
            }
        }
        catch (Exception ex)
        {
            diagnostics.Add($"Baseline diff failed: {ex.Message}");
        }
    }

    private static void WriteReports(CbomDocument document, ScanOptions options, List<string> diagnostics)
    {
        var renderers = new Dictionary<string, IReportRenderer>(StringComparer.OrdinalIgnoreCase)
        {
            ["cyclonedx"] = new CycloneDxReporter(),
            ["sarif"] = new SarifReporter(),
            ["markdown"] = new MarkdownReporter(),
            ["summary"] = new ExecutiveSummaryReporter(),
            ["html"] = new HtmlReporter(),
        };

        foreach (string format in options.Formats)
        {
            string key = format.ToLowerInvariant() switch
            {
                "md" => "markdown",
                "json" or "cbom" => "cyclonedx",
                var other => other,
            };

            if (!renderers.TryGetValue(key, out IReportRenderer? renderer))
            {
                diagnostics.Add($"Unknown output format '{format}' (skipped).");
                continue;
            }

            string path = Path.Combine(options.OutputDir, "cbom" + renderer.FileExtension);
            using FileStream stream = File.Create(path);
            renderer.Render(document, stream);
        }
    }

    private static int ComputeExitCode(CbomDocument document, List<CryptoFinding> findings, ScanOptions options)
    {
        // Fail-closed: a project that didn't analyze is a partial scan (exit 2) unless explicitly allowed.
        if (document.Metadata.ProjectsFailed > 0 && !options.AllowPartial)
            return 2;
        if (options.FailOn is { } gate && findings.Count > 0 && findings.Max(f => f.RiskLevel) >= gate)
            return 1;
        return 0;
    }
}
