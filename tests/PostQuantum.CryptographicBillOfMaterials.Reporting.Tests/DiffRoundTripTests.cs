using PostQuantum.CryptographicBillOfMaterials.Diff;
using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Reporting;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Reporting.Tests;

public class DiffRoundTripTests
{
    private static CryptoFinding F(string bomRef, string name, RiskLevel level, QuantumVulnerability qv) => new()
    {
        RuleId = "CBOM0002",
        Title = name,
        Category = RuleCategory.AsymmetricEncryption,
        AlgorithmName = name,
        RiskBasis = "basis",
        Location = new SourceLocation("src/A.cs", 10),
        RiskLevel = level,
        QuantumVulnerability = qv,
        BomRef = bomRef,
    };

    private static CbomDocument SampleDoc() => new()
    {
        Metadata = new ScanMetadata
        {
            ToolName = "dotnet-cbom",
            ToolVersion = "0.1.0",
            ProfileVersion = "1.0",
            CycloneDxSpecVersion = "1.6",
        },
        Projects = new[]
        {
            new ProjectInventory
            {
                Name = "Demo",
                Findings = new[]
                {
                    F("crypto/rsa/aaa111", "RSA", RiskLevel.High, QuantumVulnerability.Vulnerable),
                    F("crypto/md5/bbb222", "MD5", RiskLevel.High, QuantumVulnerability.NotVulnerable),
                },
            },
        },
        SolutionReadinessScore = 50,
    };

    [Fact]
    public void CycloneDx_RoundTrips_ForBaselineDiff()
    {
        CbomDocument original = SampleDoc();

        using var stream = new MemoryStream();
        new CycloneDxReporter().Render(original, stream);
        stream.Position = 0;

        CbomDocument restored = CbomReader.Read(stream);

        Assert.Equal(original.AllFindings.Count(), restored.AllFindings.Count());
        Assert.Equal(50, restored.SolutionReadinessScore);
        Assert.Contains(restored.AllFindings, f => f.BomRef == "crypto/rsa/aaa111"
            && f.QuantumVulnerability == QuantumVulnerability.Vulnerable
            && f.RiskLevel == RiskLevel.High);

        // Comparing a CBOM to itself yields no changes.
        CbomDiff diff = DiffEngine.Compare(restored, original);
        Assert.Equal(0, diff.NewCount);
        Assert.Equal(0, diff.ResolvedCount);
        Assert.True(diff.NoRegressions);
    }
}
