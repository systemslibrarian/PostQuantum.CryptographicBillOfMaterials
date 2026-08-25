using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using PostQuantum.CryptographicBillOfMaterials.Model;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Reporting.Tests;

/// <summary>
/// Locks the <c>json-summary</c> machine contract consumed by the VS Code extension / dashboards / CI.
/// These assertions are intentionally strict: the shape must not drift without a deliberate schema bump.
/// </summary>
public class JsonSummaryReporterTests
{
    private static JsonElement Render(CbomDocument document)
    {
        using var stream = new MemoryStream();
        new JsonSummaryReporter().Render(document, stream);
        stream.Position = 0;
        return JsonDocument.Parse(stream).RootElement.Clone();
    }

    [Fact]
    public void Emits_StableContract_WithExpectedCountsAndScore()
    {
        JsonElement root = Render(SampleDocuments.Create());

        Assert.Equal(JsonSummaryReporter.SchemaVersion, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("dotnet-cbom", root.GetProperty("tool").GetString());
        Assert.Equal(35, root.GetProperty("readinessScore").GetInt32());

        JsonElement findings = root.GetProperty("findings");
        Assert.Equal(4, findings.GetProperty("total").GetInt32());
        Assert.Equal(1, findings.GetProperty("critical").GetInt32());      // hardcoded key
        Assert.Equal(2, findings.GetProperty("high").GetInt32());          // RSA + MD5
        Assert.Equal(1, findings.GetProperty("informational").GetInt32()); // AES-256-GCM

        Assert.Equal(1, root.GetProperty("quantumVulnerable").GetInt32());    // RSA only
        Assert.Equal(2, root.GetProperty("classicalWeaknesses").GetInt32());  // MD5 + hardcoded key (Broken)
        Assert.Equal(0, root.GetProperty("waived").GetInt32());

        JsonElement coverage = root.GetProperty("coverage");
        Assert.Equal(1, coverage.GetProperty("projectsAnalyzed").GetInt32());
        Assert.Equal(1, coverage.GetProperty("projectsFailed").GetInt32());
    }

    [Fact]
    public void BaselineDelta_IsNull_WhenNoBaselineSupplied()
    {
        // SampleDocuments has no remediation status, so the delta must be null (not zeroed) — letting
        // consumers distinguish "no comparison" from "compared, nothing changed".
        JsonElement root = Render(SampleDocuments.Create());
        Assert.Equal(JsonValueKind.Null, root.GetProperty("baselineDelta").ValueKind);
    }

    [Fact]
    public void TopActions_LeadWithHighestRisk()
    {
        JsonElement root = Render(SampleDocuments.Create());
        JsonElement actions = root.GetProperty("topActions");

        Assert.True(actions.GetArrayLength() > 0);
        Assert.Equal("Critical", actions[0].GetProperty("level").GetString());
    }

    /// <summary>
    /// Every playbook id referenced by an action must also be present in the top-level <c>playbooks</c>
    /// array. The extension renders the guidance from that array alone -- it has no knowledge base -- so a
    /// dangling id would surface as a link to a section that was never written.
    /// </summary>
    [Fact]
    public void TopActions_PlaybookIds_AllResolveToAnEmittedPlaybook()
    {
        JsonElement root = Render(SampleDocuments.Create());

        var referenced = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonElement action in root.GetProperty("topActions").EnumerateArray())
        {
            Assert.True(action.TryGetProperty("playbookIds", out JsonElement ids),
                "every action must carry a playbookIds array, even when empty");
            foreach (JsonElement id in ids.EnumerateArray())
                referenced.Add(id.GetString()!);
        }

        var emitted = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonElement pb in root.GetProperty("playbooks").EnumerateArray())
        {
            string id = pb.GetProperty("id").GetString()!;
            Assert.True(emitted.Add(id), $"playbook '{id}' was emitted more than once");

            // Headline fields only; the worked code stays in the Markdown/HTML reports.
            Assert.False(string.IsNullOrWhiteSpace(pb.GetProperty("title").GetString()));
            Assert.False(string.IsNullOrWhiteSpace(pb.GetProperty("target").GetString()));
            Assert.True(pb.TryGetProperty("appliesTo", out _));
            Assert.True(pb.TryGetProperty("steps", out _));
        }

        Assert.True(referenced.IsSubsetOf(emitted),
            "referenced playbook ids with no emitted playbook: " + string.Join(", ", referenced.Except(emitted)));
    }
}
