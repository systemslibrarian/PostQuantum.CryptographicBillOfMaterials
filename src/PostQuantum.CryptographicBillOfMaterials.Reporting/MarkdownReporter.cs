using System.Text;
using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Reporting;

/// <summary>
/// Renders the CBOM as a human-readable Markdown report: scan metadata, coverage, readiness
/// scores, and findings grouped by project then by risk level (most severe first).
/// </summary>
public sealed class MarkdownReporter : IReportRenderer
{
    /// <summary>
    /// Honesty footer appended to every report: a clean scan is not proof of quantum safety.
    /// </summary>
    public const string Footer =
        "> A clean scan means \"no detectable issues in analyzed source,\" not \"the system is quantum-safe.\"";

    /// <inheritdoc />
    public string FormatName => "markdown";

    /// <inheritdoc />
    public string FileExtension => ".md";

    /// <inheritdoc />
    public void Render(CbomDocument document, Stream output)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(output);

        var sb = new StringBuilder();
        var m = document.Metadata;

        sb.AppendLine("# Cryptographic Bill of Materials");
        sb.AppendLine();

        sb.AppendLine("## Scan Metadata");
        sb.AppendLine();
        sb.AppendLine($"- **Tool:** {m.ToolName} {m.ToolVersion}");
        sb.AppendLine($"- **Profile version:** {m.ProfileVersion}");
        sb.AppendLine($"- **Policy profile:** {m.PolicyProfile}");
        if (m.KnowledgeBaseVersion is { } kb)
            sb.AppendLine($"- **Knowledge base:** {kb}");
        sb.AppendLine($"- **Timestamp:** {m.Timestamp:O}");
        var frameworks = m.TargetFrameworks.Count > 0 ? string.Join(", ", m.TargetFrameworks) : "(none)";
        sb.AppendLine($"- **Target frameworks:** {frameworks}");
        var totalProjects = m.ProjectsAnalyzed + m.ProjectsFailed;
        sb.AppendLine($"- **Coverage:** Analyzed {m.ProjectsAnalyzed} of {totalProjects} projects");
        sb.AppendLine();

        AppendTopActions(sb, document);
        AppendFindingsCountTable(sb, document);
        AppendWhatChanged(sb, document);
        AppendReadiness(sb, document);
        AppendFindings(sb, document);
        AppendWaivers(sb, document);

        sb.AppendLine(Footer);

        WriteToStream(sb, output);
    }

    private static void AppendTopActions(StringBuilder sb, CbomDocument document)
    {
        var actions = AuditInsights.TopActions(document, 10);
        if (actions.Count == 0)
            return;

        sb.AppendLine("## Top Migration Actions");
        sb.AppendLine();
        sb.AppendLine("| # | Severity | Project | Algorithm | Rule | Count | Action |");
        sb.AppendLine("| --- | --- | --- | --- | --- | --- | --- |");
        int n = 1;
        foreach (AuditInsights.MigrationAction a in actions)
        {
            sb.AppendLine($"| {n} | {a.Level} | {Escape(a.Project)} | {Escape(a.Algorithm)} | {a.RuleId} | {a.Count} | {Escape(a.Action)} |");
            n++;
        }
        sb.AppendLine();
    }

    private static void AppendWhatChanged(StringBuilder sb, CbomDocument document)
    {
        if (!AuditInsights.HasRemediationStatus(document))
            return;

        sb.AppendLine("## What Changed Since Baseline");
        sb.AppendLine();
        sb.AppendLine("| Status | Count |");
        sb.AppendLine("| --- | --- |");
        foreach ((RemediationStatus status, int count) in AuditInsights.StatusBreakdown(document))
            sb.AppendLine($"| {status} | {count} |");
        sb.AppendLine();
    }

    private static void AppendWaivers(StringBuilder sb, CbomDocument document)
    {
        var waivers = document.Metadata.AppliedConfig?.Waivers;
        if (waivers is null || waivers.Count == 0)
            return;

        sb.AppendLine("## Waivers");
        sb.AppendLine();
        sb.AppendLine("| Rule | Count | State | Expiry | Justification | Approver |");
        sb.AppendLine("| --- | --- | --- | --- | --- | --- |");
        foreach (WaiverRecord w in waivers)
        {
            string state = w.Expired ? "expired" : (w.Suppressed ? "suppressed" : "annotated");
            sb.AppendLine($"| {w.RuleId} | {w.Count} | {state} | {w.Expiry ?? "—"} | "
                + $"{Escape(w.Justification ?? "—")} | {Escape(w.Approver ?? "—")} |");
        }
        sb.AppendLine();
    }

    private static void AppendFindingsCountTable(StringBuilder sb, CbomDocument document)
    {
        sb.AppendLine("## Findings by Severity");
        sb.AppendLine();
        sb.AppendLine("| Severity | Count |");
        sb.AppendLine("| --- | --- |");

        var findings = document.AllFindings.ToList();
        foreach (var level in SeverityOrder())
        {
            var count = findings.Count(f => f.RiskLevel == level);
            sb.AppendLine($"| {level} | {count} |");
        }

        sb.AppendLine();
    }

    private static void AppendReadiness(StringBuilder sb, CbomDocument document)
    {
        sb.AppendLine("## PQC Readiness");
        sb.AppendLine();
        sb.AppendLine($"- **Solution Readiness:** {document.SolutionReadinessScore}/100");
        foreach (var project in document.Projects)
        {
            var trivial = project.ReadinessTrivial ? " (trivial: no quantum-relevant crypto)" : string.Empty;
            sb.AppendLine($"- **{project.Name}:** {project.ReadinessScore}/100{trivial}");
        }

        sb.AppendLine();
    }

    private static void AppendFindings(StringBuilder sb, CbomDocument document)
    {
        sb.AppendLine("## Findings");
        sb.AppendLine();

        bool showStatus = AuditInsights.HasRemediationStatus(document);

        foreach (var project in document.Projects)
        {
            sb.AppendLine($"### {project.Name}");
            sb.AppendLine();

            if (!project.Analyzed)
            {
                sb.AppendLine("_Not analyzed — treat as unknown, not clean._");
                sb.AppendLine();
                continue;
            }

            if (project.Findings.Count == 0)
            {
                sb.AppendLine("_No findings._");
                sb.AppendLine();
                continue;
            }

            string statusCol = showStatus ? " Status |" : string.Empty;
            string statusSep = showStatus ? " --- |" : string.Empty;
            sb.AppendLine($"| Severity | Rule | Algorithm | Location | Quantum |{statusCol} Recommendation |");
            sb.AppendLine($"| --- | --- | --- | --- | --- |{statusSep} --- |");

            var ordered = project.Findings
                .OrderByDescending(f => f.RiskLevel)
                .ThenBy(f => f.RuleId, StringComparer.Ordinal);

            foreach (var f in ordered)
            {
                var location = $"{f.Location.FilePath}:{f.Location.Line}";
                var quantum = f.QuantumVulnerability.ToString();
                var recommendation = Escape(f.Recommendation.Summary);
                string statusCell = showStatus ? $" {f.Status} |" : string.Empty;
                sb.AppendLine(
                    $"| {f.RiskLevel} | {f.RuleId} | {Escape(f.AlgorithmName)} | {Escape(location)} | {quantum} |{statusCell} {recommendation} |");
            }

            sb.AppendLine();
        }
    }

    private static IEnumerable<RiskLevel> SeverityOrder() => new[]
    {
        RiskLevel.Critical,
        RiskLevel.High,
        RiskLevel.Medium,
        RiskLevel.Low,
        RiskLevel.Informational,
    };

    private static string Escape(string value) => value.Replace("|", "\\|");

    private static void WriteToStream(StringBuilder sb, Stream output)
    {
        using var writer = new StreamWriter(output, new UTF8Encoding(false), leaveOpen: true);
        writer.Write(sb.ToString());
    }
}
