using PostQuantum.CryptographicBillOfMaterials.Diff;
using PostQuantum.CryptographicBillOfMaterials.Model;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Tests;

public class DiffEngineTests
{
    private static CryptoFinding F(string bomRef, RiskLevel level,
        QuantumVulnerability qv = QuantumVulnerability.NotVulnerable) => new()
        {
            RuleId = "R",
            Title = "t",
            Category = RuleCategory.AsymmetricEncryption,
            AlgorithmName = "X",
            RiskBasis = "b",
            Location = new SourceLocation("f.cs", 1),
            RiskLevel = level,
            QuantumVulnerability = qv,
            BomRef = bomRef,
        };

    private static CbomDocument Doc(int readiness, params CryptoFinding[] findings) => new()
    {
        Metadata = new ScanMetadata
        {
            ToolName = "t",
            ToolVersion = "1",
            ProfileVersion = "1",
            CycloneDxSpecVersion = "1.6",
        },
        Projects = new[] { new ProjectInventory { Name = "p", Findings = findings } },
        SolutionReadinessScore = readiness,
    };

    [Fact]
    public void Classifies_New_Resolved_Unchanged()
    {
        CbomDocument baseline = Doc(40,
            F("a", RiskLevel.High, QuantumVulnerability.Vulnerable),
            F("b", RiskLevel.High, QuantumVulnerability.Vulnerable));
        CbomDocument current = Doc(60,
            F("a", RiskLevel.High, QuantumVulnerability.Vulnerable),   // unchanged
            F("c", RiskLevel.High));                                   // new; "b" resolved

        CbomDiff diff = DiffEngine.Compare(baseline, current);

        Assert.Equal(1, diff.NewCount);
        Assert.Equal(1, diff.ResolvedCount);
        Assert.Equal(1, diff.UnchangedCount);
        Assert.Equal(2, diff.BaselineQuantumVulnerable);
        Assert.Equal(1, diff.CurrentQuantumVulnerable);
        Assert.True(diff.NoRegressions);
    }

    [Fact]
    public void Detects_RiskRegression()
    {
        CbomDocument baseline = Doc(80, F("a", RiskLevel.Low));
        CbomDocument current = Doc(70, F("a", RiskLevel.Critical));

        CbomDiff diff = DiffEngine.Compare(baseline, current);

        Assert.Equal(1, diff.RegressedCount);
        Assert.False(diff.NoRegressions);
    }
}
