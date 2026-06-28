using PostQuantum.CryptographicBillOfMaterials.Analysis.Engine;
using PostQuantum.CryptographicBillOfMaterials.Knowledge;
using PostQuantum.CryptographicBillOfMaterials.Risk;
using PostQuantum.CryptographicBillOfMaterials.Scoring;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Tests;

/// <summary>
/// Guards against accidental drift in the rule set, mandatory bases, and scoring formula versions.
/// Adding/removing a rule or bumping a formula must be a deliberate change that updates these snapshots.
/// </summary>
public class DriftGuardTests
{
    private static readonly DetectorRegistry Registry =
        DetectorRegistry.CreateDefault(KnowledgeBase.LoadDefault());

    [Fact]
    public void RuleIdSet_IsStable()
    {
        string[] ids = Registry.Detectors.Select(d => d.Metadata.RuleId).OrderBy(x => x).ToArray();
        string[] expected =
        {
            "CBOM0001", "CBOM0002", "CBOM0003", "CBOM0007", "CBOM0010", "CBOM0021",
            "CBOM0030", "CBOM0040", "CBOM0041", "CBOM0050", "CBOM0060", "CBOM0070", "CBOM0090",
        };
        Assert.Equal(expected, ids);
    }

    [Fact]
    public void EveryRule_HasUniqueId_AndNonEmptyBasis()
    {
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var d in Registry.Detectors)
        {
            Assert.True(ids.Add(d.Metadata.RuleId), $"Duplicate rule id {d.Metadata.RuleId}");
            Assert.False(string.IsNullOrWhiteSpace(d.Metadata.Basis), $"{d.Metadata.RuleId} has no basis");
        }
    }

    [Fact]
    public void FormulaVersions_AreStable()
    {
        Assert.Equal("1.0", RiskEngine.FormulaVersion);
        Assert.Equal("1.0", ReadinessCalculator.FormulaVersion);
    }
}
