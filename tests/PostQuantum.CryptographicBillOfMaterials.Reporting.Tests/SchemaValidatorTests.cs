using System.Text;
using PostQuantum.CryptographicBillOfMaterials.Reporting;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Reporting.Tests;

/// <summary>
/// Proves generated CBOMs conform to the OFFICIAL CycloneDX 1.6 JSON Schema (not just our profile),
/// closing the headline trust gap. Uses the representative sample plus a real scan-shaped document.
/// </summary>
public class SchemaValidatorTests
{
    [Fact]
    public void SampleOutput_ConformsToOfficialCycloneDx16Schema()
    {
        using var stream = new MemoryStream();
        new CycloneDxReporter().Render(SampleDocuments.Create(), stream);
        stream.Position = 0;

        ValidationResult result = CycloneDxSchemaValidator.Validate(stream);

        Assert.True(result.IsValid,
            "Generated CBOM failed official CycloneDX 1.6 schema:\n"
            + string.Join("\n", result.Issues.Select(i => $"  {i.Location}: {i.Message}")));
    }

    [Fact]
    public void RejectsDocumentThatViolatesSchema()
    {
        // specVersion 1.6 but bomFormat is wrong and a required field type is violated.
        const string json = """
            { "bomFormat": "NotCycloneDX", "specVersion": "1.6", "version": "one" }
            """;
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(json));

        ValidationResult result = CycloneDxSchemaValidator.Validate(stream);

        Assert.False(result.IsValid);
    }

    [Fact]
    public void InvalidJson_IsReportedAsError()
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes("{ not json"));
        ValidationResult result = CycloneDxSchemaValidator.Validate(stream);
        Assert.False(result.IsValid);
    }
}
