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
    public void ExecutiveSummary_ContainsScoreAndCounts()
    {
        var md = Render(new ExecutiveSummaryReporter());
        Assert.Contains("35/100", md);
        Assert.Contains("Critical findings:", md);
        Assert.Contains("High findings:", md);
        Assert.Contains(MarkdownReporter.Footer, md);
    }
}
