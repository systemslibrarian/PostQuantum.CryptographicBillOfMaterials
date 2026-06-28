using System.Text;
using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Reporting;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Reporting.Tests;

public class HtmlReporterTests
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
                        QuantumThreat = QuantumThreat.HarvestNowDecryptLater,
                    },
                },
            },
        },
        SolutionReadinessScore = 50,
    };

    [Fact]
    public void RendersSelfContainedHtml()
    {
        using var stream = new MemoryStream();
        new HtmlReporter().Render(Doc(), stream);
        string html = Encoding.UTF8.GetString(stream.ToArray());

        Assert.Contains("<!DOCTYPE html>", html);
        Assert.Contains("PQC Readiness", html);
        Assert.Contains("RSA-2048", html);
        Assert.Contains("sev-High", html);
        Assert.Contains("quantum-safe", html); // the honesty footer
    }
}
