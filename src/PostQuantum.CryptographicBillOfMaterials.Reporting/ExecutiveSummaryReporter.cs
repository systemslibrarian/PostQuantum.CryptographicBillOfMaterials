using System.Text;
using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Reporting;

/// <summary>
/// Renders a short, leadership-oriented Markdown summary: solution readiness, the count of
/// urgent findings, the single biggest quantum gap, and a coverage-honesty note.
/// </summary>
public sealed class ExecutiveSummaryReporter : IReportRenderer
{
    /// <inheritdoc />
    public string FormatName => "summary";

    /// <inheritdoc />
    public string FileExtension => ".summary.md";

    /// <inheritdoc />
    public void Render(CbomDocument document, Stream output)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(output);

        var findings = document.AllFindings.ToList();
        var criticalCount = findings.Count(f => f.RiskLevel == RiskLevel.Critical);
        var highCount = findings.Count(f => f.RiskLevel == RiskLevel.High);
        var score = document.SolutionReadinessScore;
        var m = document.Metadata;
        var totalProjects = m.ProjectsAnalyzed + m.ProjectsFailed;

        var sb = new StringBuilder();
        sb.AppendLine("# Executive Summary");
        sb.AppendLine();
        sb.AppendLine($"**PQC Readiness: {score}/100** — {Interpret(score)}");
        sb.AppendLine();
        sb.AppendLine($"- **Policy profile:** `{m.PolicyProfile}`");
        sb.AppendLine($"- **Critical findings:** {criticalCount}");
        sb.AppendLine($"- **High findings:** {highCount}");

        var biggestGap = BiggestQuantumGap(findings);
        sb.AppendLine(biggestGap is null
            ? "- **Biggest quantum gap:** none detected in analyzed source"
            : $"- **Biggest quantum gap:** {biggestGap.Value.Algorithm} ({biggestGap.Value.Count} occurrence(s))");

        sb.AppendLine($"- **Coverage:** Analyzed {m.ProjectsAnalyzed} of {totalProjects} projects");
        sb.AppendLine();

        AppendTopActions(sb, document);
        AppendWhatChanged(sb, document);
        AppendWaivers(sb, document);

        sb.AppendLine(MarkdownReporter.Footer);

        using var writer = new StreamWriter(output, new UTF8Encoding(false), leaveOpen: true);
        writer.Write(sb.ToString());
    }

    private static void AppendTopActions(StringBuilder sb, CbomDocument document)
    {
        var actions = AuditInsights.TopActions(document, 3);
        if (actions.Count == 0)
            return;

        sb.AppendLine("## Top migration actions");
        sb.AppendLine();
        int n = 1;
        foreach (AuditInsights.MigrationAction a in actions)
        {
            sb.AppendLine($"{n}. **[{a.Level}] {a.Algorithm}** in `{a.Project}` ({a.Count}×, {a.RuleId}) — {a.Action}");
            n++;
        }
        sb.AppendLine();
    }

    private static void AppendWhatChanged(StringBuilder sb, CbomDocument document)
    {
        if (!AuditInsights.HasRemediationStatus(document))
            return;

        sb.AppendLine("## What changed since baseline");
        sb.AppendLine();
        foreach ((RemediationStatus status, int count) in AuditInsights.StatusBreakdown(document))
            sb.AppendLine($"- **{status}:** {count}");
        sb.AppendLine();
    }

    private static void AppendWaivers(StringBuilder sb, CbomDocument document)
    {
        var waivers = document.Metadata.AppliedConfig?.Waivers;
        if (waivers is null || waivers.Count == 0)
            return;

        sb.AppendLine("## Active waivers");
        sb.AppendLine();
        foreach (WaiverRecord w in waivers)
        {
            string expiry = w.Expired ? $"EXPIRED {w.Expiry}" : (w.Expiry ?? "no expiry");
            string state = w.Suppressed ? "suppressed" : "annotated";
            sb.AppendLine($"- **{w.RuleId}** ({w.Count}×, {state}, {expiry}) — "
                + $"{w.Justification ?? "no justification"} (approver: {w.Approver ?? "unspecified"})");
        }
        sb.AppendLine();
    }

    private static string Interpret(int score) => score switch
    {
        >= 90 => "the solution is well positioned for the post-quantum transition.",
        >= 70 => "the solution is largely on track but has gaps to close.",
        >= 40 => "significant migration work remains before quantum readiness.",
        _ => "the solution faces substantial quantum risk and needs urgent attention.",
    };

    private static (string Algorithm, int Count)? BiggestQuantumGap(IEnumerable<CryptoFinding> findings)
    {
        var top = findings
            .Where(f => f.QuantumVulnerability == QuantumVulnerability.Vulnerable)
            .GroupBy(f => f.AlgorithmName, StringComparer.Ordinal)
            .Select(g => (Algorithm: g.Key, Count: g.Count()))
            .OrderByDescending(g => g.Count)
            .ThenBy(g => g.Algorithm, StringComparer.Ordinal)
            .FirstOrDefault();

        return top.Algorithm is null ? null : top;
    }
}
