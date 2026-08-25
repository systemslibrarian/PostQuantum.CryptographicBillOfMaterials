using PostQuantum.CryptographicBillOfMaterials.Analysis.Engine;
using PostQuantum.CryptographicBillOfMaterials.Model;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Tests;

/// <summary>
/// bom-refs must identify a finding stably across scans for baseline diffing: independent of the source line
/// (which shifts on unrelated edits) but unique per finding. Regression for the line-in-the-identity bug.
/// </summary>
public class BomRefStabilityTests
{
    private static CryptoFinding Aes(int line) => new()
    {
        RuleId = "CBOM0001",
        Title = "AES",
        Category = RuleCategory.SymmetricEncryption,
        AlgorithmName = "AES",
        RiskBasis = "FIPS 197.",
        Location = new SourceLocation("src/A.cs", line),
    };

    [Fact]
    public void BomRef_IsLineIndependent()
    {
        // The same finding at a different line (e.g. after adding a using/comment above it) keeps its ref.
        string at10 = FindingPostProcessor.Relativize(new[] { Aes(10) }, "")[0].BomRef!;
        string at25 = FindingPostProcessor.Relativize(new[] { Aes(25) }, "")[0].BomRef!;
        Assert.Equal(at10, at25);
    }

    [Fact]
    public void BomRef_DisambiguatesMultipleOccurrences()
    {
        // Two findings of the same rule+algorithm in the same file must still get distinct, unique refs.
        var refs = FindingPostProcessor.Relativize(new[] { Aes(10), Aes(20) }, "");
        Assert.NotEqual(refs[0].BomRef, refs[1].BomRef);
    }
}
