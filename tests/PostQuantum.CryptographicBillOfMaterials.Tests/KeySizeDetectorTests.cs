using PostQuantum.CryptographicBillOfMaterials.Analysis.Engine;
using PostQuantum.CryptographicBillOfMaterials.Knowledge;
using PostQuantum.CryptographicBillOfMaterials.Model;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Tests;

public class KeySizeDetectorTests
{
    private static IReadOnlyList<CryptoFinding> Scan(string source)
    {
        var engine = new ScanEngine(DetectorRegistry.CreateDefault(KnowledgeBase.LoadDefault()));
        return engine.AnalyzeCompilation(TestCompilation.Create(source));
    }

    [Fact]
    public void DetectsAes128_SetViaKeySizeProperty()
    {
        const string src = """
            using System.Security.Cryptography;
            public class C
            {
                public void M()
                {
                    var aes = Aes.Create();
                    aes.KeySize = 128;
                }
            }
            """;

        CryptoFinding f = Assert.Single(Scan(src), x => x.RuleId == "CBOM0003");
        Assert.Equal(QuantumVulnerability.ReducedMargin, f.QuantumVulnerability);
        Assert.Equal(QuantumThreat.Grover, f.QuantumThreat);
        Assert.Equal("AES-128", f.AlgorithmName);
    }

    [Fact]
    public void Aes256KeySize_IsNotFlagged()
    {
        const string src = """
            using System.Security.Cryptography;
            public class C
            {
                public void M()
                {
                    var aes = Aes.Create();
                    aes.KeySize = 256;
                }
            }
            """;

        Assert.DoesNotContain(Scan(src), x => x.RuleId == "CBOM0003");
    }
}
