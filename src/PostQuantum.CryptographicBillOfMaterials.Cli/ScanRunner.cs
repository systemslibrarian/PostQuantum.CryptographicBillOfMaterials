using PostQuantum.CryptographicBillOfMaterials.Analysis.Engine;
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

        KnowledgeBase knowledgeBase = KnowledgeBase.LoadDefault();
        var engine = new ScanEngine(DetectorRegistry.CreateDefault(knowledgeBase));

        ResolvedScan resolved;
        try
        {
            resolved = await TargetResolver.ResolveAsync(target, diagnostics);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 3;
        }

        var projects = new List<ProjectInventory>();
        var frameworks = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int analyzed = 0, failed = 0;

        foreach (LoadedProject lp in resolved.Projects)
        {
            if (!lp.Ok || lp.Compilation is null)
            {
                failed++;
                projects.Add(new ProjectInventory { Name = lp.Name, FilePath = lp.Path, Analyzed = false });
                continue;
            }

            analyzed++;
            foreach (string t in lp.TargetFrameworks)
                frameworks.Add(t);

            CompilationScanResult result = engine.Analyze(lp.Compilation);
            foreach (ScanDiagnostic d in result.Diagnostics)
                diagnostics.Add($"{lp.Name}/{d.Source}: {d.Message}");

            ReadinessResult readiness = ReadinessCalculator.Calculate(result.Findings);
            projects.Add(new ProjectInventory
            {
                Name = lp.Name,
                FilePath = lp.Path,
                Analyzed = true,
                Findings = result.Findings,
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
            },
            Projects = projects,
            SolutionReadinessScore = solutionReadiness.Score,
        };

        Directory.CreateDirectory(options.OutputDir);
        WriteReports(document, options, diagnostics);

        if (!options.Quiet)
            ConsoleSummary.Print(document, diagnostics, options);

        return ComputeExitCode(document, allFindings, options);
    }

    private static void WriteReports(CbomDocument document, ScanOptions options, List<string> diagnostics)
    {
        var renderers = new Dictionary<string, IReportRenderer>(StringComparer.OrdinalIgnoreCase)
        {
            ["cyclonedx"] = new CycloneDxReporter(),
            ["sarif"] = new SarifReporter(),
            ["markdown"] = new MarkdownReporter(),
            ["summary"] = new ExecutiveSummaryReporter(),
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
