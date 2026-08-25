using System.Net;
using System.Text;
using PostQuantum.CryptographicBillOfMaterials.Knowledge;
using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Reporting;

/// <summary>Renders a self-contained, dependency-free HTML report (inline CSS).</summary>
public sealed class HtmlReporter : IReportRenderer
{
    // Embedded, deterministic migration-playbook knowledge; keeps rendering a pure function of the inputs.
    private static readonly KnowledgeBase Knowledge = KnowledgeBase.LoadDefault();

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
            + $"policy <b>{E(m.PolicyProfile)}</b> · {E(m.Timestamp.ToString("u"))}</p>");

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

        // Top migration actions
        var actions = AuditInsights.TopActions(document, 10);
        if (actions.Count > 0)
        {
            sb.AppendLine("<h2>Top migration actions</h2>");
            sb.AppendLine("<table><thead><tr><th>#</th><th>Severity</th><th>Project</th><th>Algorithm</th>"
                + "<th>Rule</th><th>Count</th><th>Action</th></tr></thead><tbody>");
            int rank = 1;
            foreach (AuditInsights.MigrationAction a in actions)
            {
                sb.AppendLine("<tr>"
                    + $"<td>{rank}</td>"
                    + $"<td><span class=\"pill sev-{a.Level}\">{a.Level}</span></td>"
                    + $"<td>{E(a.Project)}</td><td><b>{E(a.Algorithm)}</b></td>"
                    + $"<td>{E(a.RuleId)}</td><td>{a.Count}</td><td>{E(a.Action)}</td></tr>");
                rank++;
            }
            sb.AppendLine("</tbody></table>");
        }

        // What changed since baseline
        if (AuditInsights.HasRemediationStatus(document))
        {
            sb.AppendLine("<h2>What changed since baseline</h2><table><thead><tr><th>Status</th>"
                + "<th>Count</th></tr></thead><tbody>");
            foreach ((RemediationStatus status, int count) in AuditInsights.StatusBreakdown(document))
                sb.AppendLine($"<tr><td>{E(status.ToString())}</td><td>{count}</td></tr>");
            sb.AppendLine("</tbody></table>");
        }

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
        bool showStatus = AuditInsights.HasRemediationStatus(document);
        sb.AppendLine($"<h2>Findings ({findings.Count})</h2>");
        sb.AppendLine("<table><thead><tr><th>Severity</th><th>Rule</th><th>Algorithm</th>"
            + "<th>Location</th><th>Quantum</th>" + (showStatus ? "<th>Status</th>" : string.Empty)
            + "<th>Recommendation</th></tr></thead><tbody>");
        foreach (CryptoFinding f in findings)
        {
            sb.AppendLine("<tr>"
                + $"<td><span class=\"pill sev-{f.RiskLevel}\">{f.RiskLevel}</span></td>"
                + $"<td>{E(f.RuleId)}</td>"
                + $"<td><b>{E(f.AlgorithmName)}</b></td>"
                + $"<td><code>{E(f.Location.FilePath)}:{f.Location.Line}</code></td>"
                + $"<td>{E(QuantumLabel(f))}</td>"
                + (showStatus ? $"<td>{E(f.Status.ToString())}</td>" : string.Empty)
                + $"<td>{E(f.Recommendation.Summary)}</td>"
                + "</tr>");
        }
        sb.AppendLine("</tbody></table>");

        AppendMigrationPlaybooks(sb, document);

        // Waivers
        var waivers = document.Metadata.AppliedConfig?.Waivers;
        if (waivers is { Count: > 0 })
        {
            sb.AppendLine("<h2>Waivers</h2><table><thead><tr><th>Rule</th><th>Count</th><th>State</th>"
                + "<th>Expiry</th><th>Justification</th><th>Approver</th></tr></thead><tbody>");
            foreach (WaiverRecord w in waivers)
            {
                string state = w.Expired ? "expired" : (w.Suppressed ? "suppressed" : "annotated");
                sb.AppendLine($"<tr><td>{E(w.RuleId)}</td><td>{w.Count}</td><td>{E(state)}</td>"
                    + $"<td>{E(w.Expiry ?? "—")}</td><td>{E(w.Justification ?? "—")}</td>"
                    + $"<td>{E(w.Approver ?? "—")}</td></tr>");
            }
            sb.AppendLine("</tbody></table>");
        }

        sb.AppendLine("<p class=\"footer\">A clean scan means &ldquo;no detectable issues in analyzed "
            + "source,&rdquo; not &ldquo;the system is quantum-safe.&rdquo;</p>");
        sb.AppendLine("</body></html>");

        using var writer = new StreamWriter(output, new UTF8Encoding(false), leaveOpen: true);
        writer.Write(sb.ToString());
        writer.Flush();
    }

    /// <summary>
    /// Renders concrete .NET PQC migration playbooks for the quantum-vulnerable algorithms found, driven by
    /// the playbook IDs baked into each finding. Gives a non-cryptographer actionable options and worked code.
    /// </summary>
    private static void AppendMigrationPlaybooks(StringBuilder sb, CbomDocument document)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var playbooks = new List<MigrationPlaybook>();
        foreach (CryptoFinding f in document.AllFindings)
            foreach (string id in f.MigrationPlaybookIds)
                if (seen.Add(id) && Knowledge.Playbook(id) is { } pb)
                    playbooks.Add(pb);

        if (playbooks.Count == 0)
            return;

        sb.AppendLine("<h2>PQC migration playbooks</h2>");
        sb.AppendLine("<p>Concrete, standards-based migration guidance for the quantum-vulnerable algorithms "
            + "above: .NET implementation options, worked code, caveats, and ordered steps.</p>");

        foreach (MigrationPlaybook pb in playbooks)
        {
            sb.AppendLine($"<details class=\"playbook\" open><summary><b>{E(pb.Title)}</b></summary>");
            sb.AppendLine($"<p><b>Applies to:</b> {E(pb.AppliesTo)}</p>");
            sb.AppendLine($"<p><b>Target state:</b> {E(pb.Target)}</p>");

            foreach (MigrationApproach a in pb.Approaches)
            {
                sb.AppendLine($"<h4>{E(a.Name)}</h4>");
                sb.AppendLine($"<p><b>Availability:</b> {E(a.Status)}<br><b>Best for:</b> {E(a.RecommendedFor)}"
                    + (string.IsNullOrWhiteSpace(a.Caveats) ? string.Empty : $"<br><b>Caveats:</b> {E(a.Caveats)}")
                    + "</p>");
                if (!string.IsNullOrWhiteSpace(a.Code))
                    sb.AppendLine($"<pre><code>{E(a.Code)}</code></pre>");
            }

            if (pb.Steps.Count > 0)
            {
                sb.AppendLine("<p><b>Migration steps</b></p><ol>");
                foreach (string step in pb.Steps)
                    sb.AppendLine($"<li>{E(step)}</li>");
                sb.AppendLine("</ol>");
            }

            if (pb.References.Count > 0)
            {
                sb.AppendLine("<p><b>References:</b> "
                    + string.Join(" · ", pb.References.Select(r => $"<a href=\"{E(r.Url)}\">{E(r.Title)}</a>"))
                    + "</p>");
            }
            sb.AppendLine("</details>");
        }
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
        + ".playbook{border:1px solid #e3e3e8;border-radius:10px;padding:.6rem 1rem;margin:.8rem 0;background:#fcfcfd}"
        + ".playbook summary{cursor:pointer;font-size:1.05rem}.playbook h4{margin:.9rem 0 .3rem}"
        + "pre{background:#0f1117;color:#e6e6e6;padding:1rem;border-radius:8px;overflow:auto;font-size:.82rem;line-height:1.4}"
        + "pre code{background:none;color:inherit;padding:0}"
        + ".footer{color:#777;border-top:1px solid #eee;padding-top:1rem;margin-top:1.5rem;font-style:italic}";
}
