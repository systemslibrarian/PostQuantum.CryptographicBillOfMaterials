using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Scoring;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Tests;

public class ReadinessCalculatorTests
{
    private static CryptoFinding Finding(
        QuantumVulnerability qv,
        UsageContext usage,
        CryptoAssetType assetType = CryptoAssetType.Algorithm,
        bool hybrid = false,
        string? primitive = null) => new()
        {
            RuleId = "T",
            Title = "t",
            Category = RuleCategory.AsymmetricEncryption,
            AlgorithmName = "X",
            RiskBasis = "basis",
            Location = new SourceLocation("f.cs", 1),
            QuantumVulnerability = qv,
            UsageContext = usage,
            AssetType = assetType,
            IsHybrid = hybrid,
            Primitive = primitive,
        };

    [Fact]
    public void EmptySet_IsTrivial100()
    {
        ReadinessResult result = ReadinessCalculator.Calculate(Array.Empty<CryptoFinding>());
        Assert.True(result.Trivial);
        Assert.Equal(100, result.Score);
    }

    [Fact]
    public void OneVulnerableOneSafe_EqualWeight_Is50()
    {
        var findings = new[]
        {
            Finding(QuantumVulnerability.Vulnerable, UsageContext.KeyExchange),
            Finding(QuantumVulnerability.NotVulnerable, UsageContext.AtRest),
        };

        ReadinessResult result = ReadinessCalculator.Calculate(findings);
        Assert.False(result.Trivial);
        Assert.Equal(50, result.Score);
    }

    [Fact]
    public void ClassicalOnlyFindings_AreExcludedFromReadiness()
    {
        var findings = new[]
        {
            Finding(QuantumVulnerability.PostQuantum, UsageContext.KeyExchange),
            // Hardcoded key: related-crypto-material, must not affect readiness.
            Finding(QuantumVulnerability.NotVulnerable, UsageContext.AtRest, CryptoAssetType.RelatedCryptoMaterial),
            // ECB: a block-cipher-mode finding, also excluded.
            Finding(QuantumVulnerability.NotVulnerable, UsageContext.AtRest, primitive: "block-cipher-mode"),
        };

        ReadinessResult result = ReadinessCalculator.Calculate(findings);
        Assert.Equal(100, result.Score); // only the PQC algorithm counts, and it is safe
        Assert.False(result.Trivial);
    }
}
