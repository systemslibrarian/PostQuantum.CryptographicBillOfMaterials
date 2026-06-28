using System.Net;
using System.Text;
using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Reporting;

/// <summary>Renders a self-contained, dependency-free HTML report (inline CSS).</summary>
public sealed class HtmlReporter : IReportRenderer
{
    public string FormatName => "html";
    public string FileExtension => ".html";

    public void Render(CbomDocument document, Stream output)
    {
        var findings = document.AllFindings
            .OrderByDescending(f => f.RiskLevel)
            .ThenByDescending(f => f.RiskScore)
            .ToList();

        ScanMetadata m = document.Metadata;
        int totalProjects = m.ProjectsAnalyzed + m.ProjectsFailed;

        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
        sb.AppendLine($"<title>CBOM — {E(m.SolutionName ?? "scan")}</title>");
        sb.AppendLine("<style>" + Css() + "</style></head><body>");

        sb.AppendLine($"<h1>Cryptographic Bill of Materials</h1>");
        sb.AppendLine("<p class=\"meta\">"
            + $"{E(m.SolutionName ?? "scan")} · {E(m.ToolName)} {E(m.ToolVersion)} · "
            + $"CycloneDX {E(m.CycloneDxSpecVersion)} · profile {E(m.ProfileVersion)} · "
            + $"{E(m.Timestamp.ToString("u"))}</p>");

        string coverage = $"Analyzed {m.ProjectsAnalyzed} of {totalProjects} projects";
        if (m.ProjectsFailed > 0)
            coverage += $" — {m.ProjectsFailed} failed to load (reported as NOT analyzed)";
        sb.AppendLine($"<p class=\"coverage\">{E(coverage)}</p>");

        // Readiness
        sb.AppendLine("<div class=\"cards\">");
        sb.AppendLine($"<div class=\"card\"><div class=\"score\">{document.SolutionReadinessScore}</div>"
            + "<div class=\"label\">PQC Readiness (solution)</div></div>");
        foreach (RiskLevel level in new[] { RiskLevel.Critical, RiskLevel.High, RiskLevel.Medium })
        {
            int n = findings.Count(f => f.RiskLevel == level);
            sb.AppendLine($"<div class=\"card\"><div class=\"score sev-{level}\">{n}</div>"
                + $"<div class=\"label\">{level}</div></div>");
        }
        sb.AppendLine("</div>");

        // Per-project readiness
        sb.AppendLine("<h2>Projects</h2><table><thead><tr><th>Project</th><th>Analyzed</th>"
            + "<th>Readiness</th><th>Findings</th></tr></thead><tbody>");
        foreach (ProjectInventory p in document.Projects)
        {
            string readiness = p.Analyzed
                ? p.ReadinessScore + (p.ReadinessTrivial ? " (no quantum-relevant crypto)" : string.Empty)
                : "—";
            sb.AppendLine($"<tr><td>{E(p.Name)}</td><td>{(p.Analyzed ? "yes" : "<b>NO</b>")}</td>"
                + $"<td>{E(readiness)}</td><td>{p.Findings.Count}</td></tr>");
        }
        sb.AppendLine("</tbody></table>");

        // Findings
        sb.AppendLine($"<h2>Findings ({findings.Count})</h2>");
        sb.AppendLine("<table><thead><tr><th>Severity</th><th>Rule</th><th>Algorithm</th>"
            + "<th>Location</th><th>Quantum</th><th>Recommendation</th></tr></thead><tbody>");
        foreach (CryptoFinding f in findings)
        {
            sb.AppendLine("<tr>"
                + $"<td><span class=\"pill sev-{f.RiskLevel}\">{f.RiskLevel}</span></td>"
                + $"<td>{E(f.RuleId)}</td>"
                + $"<td><b>{E(f.AlgorithmName)}</b></td>"
                + $"<td><code>{E(f.Location.FilePath)}:{f.Location.Line}</code></td>"
                + $"<td>{E(QuantumLabel(f))}</td>"
                + $"<td>{E(f.Recommendation.Summary)}</td>"
                + "</tr>");
        }
        sb.AppendLine("</tbody></table>");

        sb.AppendLine("<p class=\"footer\">A clean scan means &ldquo;no detectable issues in analyzed "
            + "source,&rdquo; not &ldquo;the system is quantum-safe.&rdquo;</p>");
        sb.AppendLine("</body></html>");

        using var writer = new StreamWriter(output, new UTF8Encoding(false), leaveOpen: true);
        writer.Write(sb.ToString());
        writer.Flush();
    }

    private static string QuantumLabel(CryptoFinding f) => f.QuantumVulnerability switch
    {
        QuantumVulnerability.Vulnerable => $"Vulnerable ({f.QuantumThreat})",
        QuantumVulnerability.ReducedMargin => "Reduced margin (Grover)",
        QuantumVulnerability.PostQuantum => "Post-quantum ✓",
        _ => "Not quantum-vulnerable",
    };

    private static string E(string? s) => WebUtility.HtmlEncode(s ?? string.Empty);

    private static string Css() =>
        "body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:2rem;color:#1b1b1f;line-height:1.45}"
        + "h1{margin-bottom:.2rem}.meta,.coverage{color:#555;margin:.2rem 0}"
        + ".cards{display:flex;gap:1rem;flex-wrap:wrap;margin:1.2rem 0}"
        + ".card{border:1px solid #ddd;border-radius:10px;padding:1rem 1.4rem;min-width:120px;text-align:center}"
        + ".score{font-size:2rem;font-weight:700}.label{color:#666;font-size:.85rem}"
        + "table{border-collapse:collapse;width:100%;margin:.6rem 0 1.6rem}"
        + "th,td{border-bottom:1px solid #eee;padding:.5rem .6rem;text-align:left;vertical-align:top}"
        + "th{background:#fafafa;font-size:.85rem;text-transform:uppercase;letter-spacing:.03em;color:#555}"
        + "code{background:#f4f4f6;padding:.1rem .3rem;border-radius:4px;font-size:.85rem}"
        + ".pill{padding:.1rem .55rem;border-radius:999px;color:#fff;font-size:.8rem;font-weight:600}"
        + ".sev-Critical{color:#b00020}.pill.sev-Critical{background:#b00020}"
        + ".sev-High{color:#c84400}.pill.sev-High{background:#c84400}"
        + ".sev-Medium{color:#9a7400}.pill.sev-Medium{background:#9a7400}"
        + ".pill.sev-Low{background:#5a7d9a}.pill.sev-Informational{background:#6b6b6b}"
        + ".footer{color:#777;border-top:1px solid #eee;padding-top:1rem;margin-top:1.5rem;font-style:italic}";
}
