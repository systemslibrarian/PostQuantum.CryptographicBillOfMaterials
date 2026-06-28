using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Reporting;

/// <summary>
/// Derives the "audit packet" views shared by the executive summary, Markdown, and HTML reports: the top
/// migration actions (what to fix first, grouped by project), the remediation-status breakdown (what
/// changed since the baseline), and the active waivers. Pure functions over a <see cref="CbomDocument"/>.
/// </summary>
public static class AuditInsights
{
    /// <summary>One prioritized remediation action: the worst occurrence of an algorithm in a project.</summary>
    public sealed record MigrationAction(
        string Project, string Algorithm, string RuleId, RiskLevel Level, int Count, string Action);

    /// <summary>The highest-priority remediation actions, grouped by project+algorithm and ordered by risk.</summary>
    public static IReadOnlyList<MigrationAction> TopActions(CbomDocument document, int max)
    {
        return document.Projects
            .SelectMany(p => p.Findings.Select(f => (Project: p.Name, Finding: f)))
            .Where(x => x.Finding.RiskLevel >= RiskLevel.High
                || x.Finding.QuantumVulnerability == QuantumVulnerability.Vulnerable)
            .GroupBy(x => (x.Project, x.Finding.AlgorithmName, x.Finding.RuleId))
            .Select(g => new MigrationAction(
                g.Key.Project,
                g.Key.AlgorithmName,
                g.Key.RuleId,
                g.Max(x => x.Finding.RiskLevel),
                g.Count(),
                FirstAction(g.First().Finding)))
            .OrderByDescending(a => a.Level)
            .ThenByDescending(a => a.Count)
            .ThenBy(a => a.Project, StringComparer.Ordinal)
            .ThenBy(a => a.Algorithm, StringComparer.Ordinal)
            .Take(max)
            .ToList();
    }

    /// <summary>Count of findings by remediation status (only meaningful when a baseline was supplied).</summary>
    public static IReadOnlyList<(RemediationStatus Status, int Count)> StatusBreakdown(CbomDocument document) =>
        document.AllFindings
            .GroupBy(f => f.Status)
            .Where(g => g.Key != RemediationStatus.Unknown)
            .Select(g => (g.Key, g.Count()))
            .OrderBy(x => (int)x.Item1)
            .ToList();

    /// <summary>True when at least one finding carries a baseline-derived or waiver status.</summary>
    public static bool HasRemediationStatus(CbomDocument document) =>
        document.AllFindings.Any(f => f.Status != RemediationStatus.Unknown);

    private static string FirstAction(CryptoFinding finding) =>
        finding.Recommendation.Options.Count > 0
            ? finding.Recommendation.Options[0].Description
            : finding.Recommendation.Summary;
}
