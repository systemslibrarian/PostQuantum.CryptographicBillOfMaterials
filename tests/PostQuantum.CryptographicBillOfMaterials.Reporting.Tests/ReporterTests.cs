using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using PostQuantum.CryptographicBillOfMaterials.Model;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Reporting.Tests;

public sealed class ReporterTests
{
    private static string Render(IReportRenderer renderer)
    {
        var document = SampleDocuments.Create();
        using var stream = new MemoryStream();
        renderer.Render(document, stream);
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    [Fact]
    public void CycloneDx_EmitsValidProfiledBom()
    {
        var json = Render(new CycloneDxReporter());
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("CycloneDX", root.GetProperty("bomFormat").GetString());
        Assert.Equal("1.6", root.GetProperty("specVersion").GetString());
        Assert.Equal(1, root.GetProperty("version").GetInt32());
        Assert.StartsWith("urn:uuid:", root.GetProperty("serialNumber").GetString());

        var components = root.GetProperty("components").EnumerateArray().ToList();
        Assert.All(components, c => Assert.Equal("cryptographic-asset", c.GetProperty("type").GetString()));

        // At least one algorithm asset.
        Assert.Contains(components, c =>
            c.GetProperty("cryptoProperties").GetProperty("assetType").GetString() == "algorithm");

        // The related-crypto-material finding maps correctly.
        Assert.Contains(components, c =>
            c.GetProperty("cryptoProperties").GetProperty("assetType").GetString() == "related-crypto-material");

        // Every component has a cbom:risk:level property.
        Assert.All(components, c =>
            Assert.Contains(
                c.GetProperty("properties").EnumerateArray(),
                p => p.GetProperty("name").GetString() == "cbom:risk:level"));

        // metadata.properties contains readiness score.
        var metaProps = root.GetProperty("metadata").GetProperty("properties").EnumerateArray();
        Assert.Contains(metaProps, p => p.GetProperty("name").GetString() == "cbom:readiness:score");
    }

    [Fact]
    public void CycloneDx_OmitsNullAlgorithmFields()
    {
        var json = Render(new CycloneDxReporter());
        using var doc = JsonDocument.Parse(json);
        var rsa = doc.RootElement.GetProperty("components").EnumerateArray()
            .First(c => c.GetProperty("name").GetString() == "RSA");

        var algo = rsa.GetProperty("cryptoProperties").GetProperty("algorithmProperties");
        Assert.False(algo.TryGetProperty("curve", out _));
        Assert.Equal("2048", algo.GetProperty("parameterSetIdentifier").GetString());
    }

    [Fact]
    public void CycloneDx_IsDeterministic()
    {
        var first = Render(new CycloneDxReporter());
        var second = Render(new CycloneDxReporter());
        Assert.Equal(first, second);
    }

    [Fact]
    public void Sarif_EmitsValidLog()
    {
        var json = Render(new SarifReporter());
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("2.1.0", root.GetProperty("version").GetString());

        var run = root.GetProperty("runs").EnumerateArray().First();
        Assert.Equal("dotnet-cbom", run.GetProperty("tool").GetProperty("driver").GetProperty("name").GetString());

        var results = run.GetProperty("results").EnumerateArray().ToList();
        Assert.Contains(results, r => r.GetProperty("level").GetString() == "error");
    }

    [Fact]
    public void Markdown_ContainsReadinessFooterAndLocation()
    {
        var md = Render(new MarkdownReporter());
        Assert.Contains("Readiness", md);
        Assert.Contains(MarkdownReporter.Footer, md);
        Assert.Contains("src/Auth/KeyExchange.cs:42", md);
    }

    [Fact]
    public void Markdown_RendersMigrationPlaybooksWithWorkedCode()
    {
        var md = Render(new MarkdownReporter());
        // The RSA finding must surface both playbooks with concrete, verified .NET 10 API guidance.
        Assert.Contains("## PQC Migration Playbooks", md);
        Assert.Contains("Migrate key establishment to ML-KEM", md);
        Assert.Contains("Migrate digital signatures to ML-DSA", md);
        Assert.Contains("MLKem.GenerateKey", md);
        Assert.Contains("MLDsa.GenerateKey", md);
        Assert.Contains("MLKem.IsSupported", md);
    }

    [Fact]
    public void Html_RendersMigrationPlaybooks()
    {
        var html = Render(new HtmlReporter());
        Assert.Contains("PQC migration playbooks", html);
        Assert.Contains("MLKem.GenerateKey", html);
    }

    [Fact]
    public void CycloneDx_EmitsMachineReadablePlaybookPointer()
    {
        var json = Render(new CycloneDxReporter());
        using var doc = JsonDocument.Parse(json);
        var rsa = doc.RootElement.GetProperty("components").EnumerateArray()
            .First(c => c.GetProperty("name").GetString() == "RSA");
        var prop = rsa.GetProperty("properties").EnumerateArray()
            .First(p => p.GetProperty("name").GetString() == "cbom:migration:playbooks");
        Assert.Contains("pqc-key-establishment", prop.GetProperty("value").GetString());
    }

    [Fact]
    public void CycloneDx_PostQuantumAndStatus_RoundTrip()
    {
        // Regression: PostQuantum collapsed to NotVulnerable, and remediation status was never read back.
        var finding = new CryptoFinding
        {
            RuleId = "CBOM0090",
            Title = "ML-KEM",
            Category = RuleCategory.PostQuantum,
            AlgorithmName = "ML-KEM",
            RiskBasis = "FIPS 203.",
            QuantumVulnerability = QuantumVulnerability.PostQuantum,
            Status = RemediationStatus.Waived,
            Location = new SourceLocation("src/Pqc.cs", 5),
            BomRef = "crypto/ml-kem/abc123",
        };
        var doc = new CbomDocument
        {
            Metadata = new ScanMetadata
            {
                ToolName = "dotnet-cbom", ToolVersion = "1.0.0", ProfileVersion = "1.0",
                CycloneDxSpecVersion = "1.6", Timestamp = new DateTimeOffset(2026, 6, 29, 0, 0, 0, TimeSpan.Zero),
                SolutionName = "S",
            },
            Projects = new[] { new ProjectInventory { Name = "P", Findings = new[] { finding } } },
        };

        using var stream = new MemoryStream();
        new CycloneDxReporter().Render(doc, stream);
        stream.Position = 0;
        CbomDocument readBack = CbomReader.Read(stream);

        CryptoFinding rt = Assert.Single(readBack.AllFindings);
        Assert.Equal(QuantumVulnerability.PostQuantum, rt.QuantumVulnerability);
        Assert.Equal(RemediationStatus.Waived, rt.Status);
    }

    [Fact]
    public void CbomValidator_DoesNotThrow_OnWrongTypedValues()
    {
        // A validator must report malformed input, not crash. specVersion as a number previously threw.
        const string json = """
            { "bomFormat": "CycloneDX", "specVersion": 1.6, "metadata": {}, "components": [] }
            """;
        var bytes = Encoding.UTF8.GetBytes(json);

        ValidationResult result = CbomValidator.Validate(new MemoryStream(bytes));

        Assert.False(result.IsValid); // specVersion is not the string "1.6"
    }

    [Fact]
    public void ExecutiveSummary_ContainsScoreAndCounts()
    {
        var md = Render(new ExecutiveSummaryReporter());
        Assert.Contains("35/100", md);
        Assert.Contains("Critical findings:", md);
        Assert.Contains("High findings:", md);
        Assert.Contains(MarkdownReporter.Footer, md);
    }
}
