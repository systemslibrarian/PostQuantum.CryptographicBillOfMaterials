using System.Text;
using PostQuantum.CryptographicBillOfMaterials.Diff;
using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Reporting;

/// <summary>Renders a <see cref="CbomDiff"/> as a Markdown progress/regression report.</summary>
public static class DiffReporter
{
    public static void Render(CbomDiff diff, Stream output)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# CBOM diff").AppendLine();

        int qvBefore = diff.BaselineQuantumVulnerable;
        int qvAfter = diff.CurrentQuantumVulnerable;
        string qvPct = qvBefore == 0 ? "n/a" : $"{(qvAfter - qvBefore) * 100.0 / qvBefore:+0;-0;0}%";

        sb.AppendLine($"- Resolved: **{diff.ResolvedCount}**  ·  New: **{diff.NewCount}**  ·  "
            + $"Unchanged: **{diff.UnchangedCount}**  ·  Regressed: **{diff.RegressedCount}**");
        sb.AppendLine($"- Quantum-vulnerable findings: **{qvBefore} → {qvAfter}** ({qvPct})");
        sb.AppendLine($"- PQC Readiness: **{diff.BaselineReadiness} → {diff.CurrentReadiness}** "
            + $"({diff.CurrentReadiness - diff.BaselineReadiness:+0;-0;0})");
        sb.AppendLine($"- Regression check: **{(diff.NoRegressions ? "PASS" : "FAIL")}** "
            + "(no finding moved to a higher risk level)");
        sb.AppendLine();

        Section(sb, "Resolved", diff, FindingDelta.Resolved, "+");
        Section(sb, "New", diff, FindingDelta.New, "-");
        Section(sb, "Regressed (risk increased)", diff, FindingDelta.RiskIncreased, "!");

        using var writer = new StreamWriter(output, new UTF8Encoding(false), leaveOpen: true);
        writer.Write(sb.ToString());
        writer.Flush();
    }

    private static void Section(StringBuilder sb, string title, CbomDiff diff, FindingDelta delta, string marker)
    {
        var items = diff.Items.Where(i => i.Delta == delta).ToList();
        if (items.Count == 0)
            return;

        sb.AppendLine($"## {title} ({items.Count})").AppendLine();
        foreach (FindingDiff item in items.OrderByDescending(i => i.Representative.RiskLevel))
        {
            CryptoFinding f = item.Representative;
            sb.AppendLine($"- `{marker}` **{f.RiskLevel} {f.RuleId}** {f.AlgorithmName} "
                + $"— {f.Location.FilePath}:{f.Location.Line}");
        }
        sb.AppendLine();
    }
}
