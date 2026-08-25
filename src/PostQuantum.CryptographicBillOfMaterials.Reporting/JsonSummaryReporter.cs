using PostQuantum.CryptographicBillOfMaterials.Knowledge;
using System.Text.Encodings.Web;
using System.Text.Json;
using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Reporting;

/// <summary>
/// Renders a small, stable JSON summary intended as a machine contract for tooling (the VS Code extension,
/// dashboards, CI gates) — NOT a full CBOM. Consumers should read this instead of scraping Markdown/HTML.
/// The shape is versioned via <c>schemaVersion</c>; fields are only ever added, never repurposed.
/// </summary>
public sealed class JsonSummaryReporter : IReportRenderer
{
    /// <summary>Resolves playbook ids to content; same load path the Markdown and HTML reporters use.</summary>
    private static readonly KnowledgeBase Knowledge = KnowledgeBase.LoadDefault();

    /// <summary>Bump only on a breaking change to the contract; additive fields keep the same version.</summary>
    public const int SchemaVersion = 1;

    /// <inheritdoc />
    public string FormatName => "json-summary";

    /// <inheritdoc />
    public string FileExtension => ".summary.json";

    /// <inheritdoc />
    public void Render(CbomDocument document, Stream output)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(output);

        // Active findings exclude those baseline-diff marked as Fixed: they no longer exist in source, so a
        // readiness dashboard should not count them. Waived findings remain counted but are also reported
        // separately, so the UI can show "addressed via waiver" without hiding the underlying risk.
        var all = document.AllFindings.ToList();
        var active = all.Where(f => f.Status != RemediationStatus.Fixed).ToList();
        ScanMetadata m = document.Metadata;
        bool hasBaseline = AuditInsights.HasRemediationStatus(document);

        // Relaxed encoding keeps characters like '+' (e.g. "ML-KEM-768") and accented citations literal in the
        // file. Output is a standalone JSON document, never embedded in HTML, so this is safe.
        var options = new JsonWriterOptions { Indented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
        using var writer = new Utf8JsonWriter(output, options);

        writer.WriteStartObject();
        writer.WriteNumber("schemaVersion", SchemaVersion);
        writer.WriteString("tool", m.ToolName);
        writer.WriteString("toolVersion", m.ToolVersion);
        writer.WriteString("knowledgeBaseVersion", m.KnowledgeBaseVersion);
        writer.WriteString("generatedAt", m.Timestamp.ToString("o"));
        writer.WriteString("policyProfile", m.PolicyProfile);
        writer.WriteNumber("readinessScore", document.SolutionReadinessScore);

        writer.WriteStartObject("findings");
        writer.WriteNumber("total", active.Count);
        writer.WriteNumber("critical", active.Count(f => f.RiskLevel == RiskLevel.Critical));
        writer.WriteNumber("high", active.Count(f => f.RiskLevel == RiskLevel.High));
        writer.WriteNumber("medium", active.Count(f => f.RiskLevel == RiskLevel.Medium));
        writer.WriteNumber("low", active.Count(f => f.RiskLevel == RiskLevel.Low));
        writer.WriteNumber("informational", active.Count(f => f.RiskLevel == RiskLevel.Informational));
        writer.WriteEndObject();

        writer.WriteNumber("quantumVulnerable", active.Count(f => f.QuantumVulnerability == QuantumVulnerability.Vulnerable));
        writer.WriteNumber("classicalWeaknesses", active.Count(f => f.ClassicalWeakness != ClassicalWeakness.None));
        writer.WriteNumber("waived", all.Count(f => f.Status == RemediationStatus.Waived));

        // Baseline delta is null (not zeroed) when no baseline was supplied, so consumers can distinguish
        // "no comparison" from "compared, nothing changed".
        if (hasBaseline)
        {
            writer.WriteStartObject("baselineDelta");
            writer.WriteNumber("new", all.Count(f => f.Status == RemediationStatus.New));
            writer.WriteNumber("fixed", all.Count(f => f.Status == RemediationStatus.Fixed));
            writer.WriteNumber("regressed", all.Count(f => f.Status == RemediationStatus.Regressed));
            writer.WriteEndObject();
        }
        else
        {
            writer.WriteNull("baselineDelta");
        }

        writer.WriteStartObject("coverage");
        writer.WriteNumber("projectsAnalyzed", m.ProjectsAnalyzed);
        writer.WriteNumber("projectsFailed", m.ProjectsFailed);
        writer.WriteEndObject();

        // A few highest-value migration actions so the extension can show "do these next" without re-deriving.
        IReadOnlyList<AuditInsights.MigrationAction> actions = AuditInsights.TopActions(document, 5);
        writer.WriteStartArray("topActions");
        foreach (AuditInsights.MigrationAction action in actions)
        {
            writer.WriteStartObject();
            writer.WriteString("project", action.Project);
            writer.WriteString("algorithm", action.Algorithm);
            writer.WriteString("ruleId", action.RuleId);
            writer.WriteString("level", action.Level.ToString());
            writer.WriteNumber("occurrences", action.Count);
            writer.WriteString("action", action.Action);
            writer.WriteStartArray("playbookIds");
            foreach (string id in action.PlaybookIds)
                writer.WriteStringValue(id);
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        writer.WriteEndArray();

        // The playbooks those actions point at, resolved once and de-duplicated. Carrying the content here
        // rather than only the ids is what lets an editor extension show the migration guidance itself: it
        // has no knowledge base of its own, and an id alone would only tell it that guidance exists.
        // Approaches and references are deliberately omitted — this is the "what do I do next" surface, and
        // the full worked code belongs in the Markdown or HTML report.
        writer.WriteStartArray("playbooks");
        var emitted = new HashSet<string>(StringComparer.Ordinal);
        foreach (string id in actions.SelectMany(a => a.PlaybookIds))
        {
            if (!emitted.Add(id) || Knowledge.Playbook(id) is not { } pb)
                continue;

            writer.WriteStartObject();
            writer.WriteString("id", pb.Id);
            writer.WriteString("title", pb.Title);
            writer.WriteString("appliesTo", pb.AppliesTo);
            writer.WriteString("target", pb.Target);
            writer.WriteStartArray("steps");
            foreach (string step in pb.Steps)
                writer.WriteStringValue(step);
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        writer.WriteEndArray();

        writer.WriteEndObject();
        writer.Flush();
    }
}
