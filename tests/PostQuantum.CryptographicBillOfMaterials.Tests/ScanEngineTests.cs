using Microsoft.CodeAnalysis;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Engine;
using PostQuantum.CryptographicBillOfMaterials.Knowledge;
using PostQuantum.CryptographicBillOfMaterials.Model;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Tests;

public class ScanEngineTests
{
    private static IReadOnlyList<CryptoFinding> Scan(string source)
    {
        Compilation compilation = TestCompilation.Create(source);
        var engine = new ScanEngine(DetectorRegistry.CreateDefault(KnowledgeBase.LoadDefault()));
        return engine.AnalyzeCompilation(compilation);
    }

    private const string Sample = """
        using System.Security.Cryptography;

        public class C
        {
            public void M()
            {
                var aes = Aes.Create();
                aes.Mode = CipherMode.ECB;
                aes.Key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
                var rsa = RSA.Create(2048);
                using var md5 = MD5.Create();
            }
        }
        """;

    [Fact]
    public void DetectsRsa_AsQuantumVulnerable_HarvestNowDecryptLater()
    {
        CryptoFinding rsa = Assert.Single(Scan(Sample), f => f.RuleId == "CBOM0002");
        Assert.Equal(QuantumVulnerability.Vulnerable, rsa.QuantumVulnerability);
        Assert.Equal(QuantumThreat.HarvestNowDecryptLater, rsa.QuantumThreat);
        Assert.Equal(RiskLevel.High, rsa.RiskLevel);
        Assert.Equal("RSA-2048", rsa.AlgorithmName);
        Assert.NotEmpty(rsa.Recommendation.Options);
    }

    [Fact]
    public void DetectsEcb_AsHigh()
    {
        CryptoFinding ecb = Assert.Single(Scan(Sample), f => f.RuleId == "CBOM0007");
        Assert.Equal(RiskLevel.High, ecb.RiskLevel);
        Assert.Equal(ClassicalWeakness.Broken, ecb.ClassicalWeakness);
    }

    [Fact]
    public void DetectsMd5_AsBroken_ButNotQuantumVulnerable()
    {
        CryptoFinding md5 = Assert.Single(Scan(Sample), f => f.RuleId == "CBOM0010");
        Assert.Equal(ClassicalWeakness.Broken, md5.ClassicalWeakness);
        Assert.Equal(QuantumVulnerability.NotVulnerable, md5.QuantumVulnerability);
        Assert.Equal(RiskLevel.High, md5.RiskLevel); // floored up from the formula
    }

    [Fact]
    public void DetectsHardcodedKey_AsCritical_RelatedMaterial()
    {
        CryptoFinding key = Assert.Single(Scan(Sample), f => f.RuleId == "CBOM0030");
        Assert.Equal(RiskLevel.Critical, key.RiskLevel);
        Assert.Equal(CryptoAssetType.RelatedCryptoMaterial, key.AssetType);
        Assert.Equal(DetectionMethod.Constant, key.DetectionMethod);
    }

    [Fact]
    public void DetectsAes_AsPositiveSignal_Informational()
    {
        CryptoFinding aes = Assert.Single(Scan(Sample), f => f.RuleId == "CBOM0001");
        Assert.Equal(QuantumVulnerability.NotVulnerable, aes.QuantumVulnerability);
        Assert.Equal(RiskLevel.Informational, aes.RiskLevel);
    }

    [Fact]
    public void CleanCryptoCode_ProducesNoHighRiskFindings()
    {
        const string clean = """
            using System.Security.Cryptography;
            public class Safe
            {
                public byte[] Hash(byte[] data) => SHA384.HashData(data);
            }
            """;

        Assert.DoesNotContain(Scan(clean), f => f.RiskLevel >= RiskLevel.High);
    }
}
