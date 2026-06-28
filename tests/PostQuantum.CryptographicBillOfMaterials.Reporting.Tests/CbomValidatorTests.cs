using System.Text;
using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Reporting;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Reporting.Tests;

public class CbomValidatorTests
{
    private static CbomDocument Doc() => new()
    {
        Metadata = new ScanMetadata
        {
            ToolName = "dotnet-cbom",
            ToolVersion = "0.1.0",
            ProfileVersion = "1.0",
            CycloneDxSpecVersion = "1.6",
            SolutionName = "Demo",
            ProjectsAnalyzed = 1,
        },
        Projects = new[]
        {
            new ProjectInventory
            {
                Name = "Demo",
                Findings = new[]
                {
                    new CryptoFinding
                    {
                        RuleId = "CBOM0002",
                        Title = "RSA",
                        Category = RuleCategory.AsymmetricEncryption,
                        AlgorithmName = "RSA-2048",
                        RiskBasis = "Shor",
                        Location = new SourceLocation("src/A.cs", 10),
                        RiskLevel = RiskLevel.High,
                        QuantumVulnerability = QuantumVulnerability.Vulnerable,
                        Confidence = DetectionConfidence.Confirmed,
                        BomRef = "crypto/rsa/abc123",
                    },
                },
            },
        },
        SolutionReadinessScore = 50,
    };

    [Fact]
    public void OwnOutput_IsValid()
    {
        using var stream = new MemoryStream();
        new CycloneDxReporter().Render(Doc(), stream);
        stream.Position = 0;

        ValidationResult result = CbomValidator.Validate(stream);

        Assert.True(result.IsValid, string.Join("; ", result.Issues.Select(i => $"{i.Location}:{i.Message}")));
    }

    [Fact]
    public void WrongSpecVersion_IsError()
    {
        const string json = """
            { "bomFormat": "CycloneDX", "specVersion": "1.4", "metadata": {}, "components": [] }
            """;
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(json));
        ValidationResult result = CbomValidator.Validate(stream);

        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, i => i.Location == "$.specVersion");
    }

    [Fact]
    public void CryptoAssetMissingProfileFields_IsError()
    {
        const string json = """
            {
              "bomFormat": "CycloneDX", "specVersion": "1.6",
              "metadata": { "properties": [ { "name": "cbom:profile:version", "value": "1.0" } ] },
              "components": [ { "type": "cryptographic-asset", "name": "X" } ]
            }
            """;
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(json));
        ValidationResult result = CbomValidator.Validate(stream);

        Assert.False(result.IsValid); // missing bom-ref, cryptoProperties.assetType, cbom:risk:level, cbom:rule:id
    }
}
