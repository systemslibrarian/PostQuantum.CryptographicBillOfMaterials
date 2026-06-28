using PostQuantum.CryptographicBillOfMaterials.Analysis.Engine;
using PostQuantum.CryptographicBillOfMaterials.Knowledge;
using PostQuantum.CryptographicBillOfMaterials.Model;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Tests;

/// <summary>
/// Property-style invariants checked across a corpus of crypto snippets: whatever a detector emits, certain
/// guarantees must always hold (documented basis, fail-closed floors, misuse-resistant recommendations,
/// stable bom-refs). These catch regressions that single-case tests miss.
/// </summary>
public class InvariantPropertyTests
{
    private static readonly string[] Corpus =
    {
        "using System.Security.Cryptography; class C { void M(){ var a = Aes.Create(); a.KeySize = 128; } }",
        "using System.Security.Cryptography; class C { void M(){ var r = RSA.Create(512); } }",
        "using System.Security.Cryptography; class C { void M(){ var r = RSA.Create(2048); } }",
        "using System.Security.Cryptography; class C { void M(){ var d = DES.Create(); } }",
        "using System.Security.Cryptography; class C { void M(){ var m = MD5.Create(); } }",
        "using System.Security.Cryptography; class C { void M(){ var s = SHA256.Create(); } }",
        "using System.Security.Cryptography; class C { byte[] GenerateKey(){ var k=new byte[16]; new System.Random().NextBytes(k); return k; } }",
        "using System.Security.Cryptography; class C { void M(){ var e = ECDsa.Create(); } }",
        "using System.Security.Cryptography.X509Certificates; class C { void M(){ var c = new X509Certificate2(\"x.pfx\"); } }",
        "class C { int Roll() => new System.Random().Next(); }",
    };

    private static IEnumerable<CryptoFinding> AllFindings()
    {
        var engine = new ScanEngine(DetectorRegistry.CreateDefault(KnowledgeBase.LoadDefault()));
        foreach (string src in Corpus)
            foreach (CryptoFinding f in engine.AnalyzeCompilation(TestCompilation.Create(src)))
                yield return f;
    }

    private static int Safety(QuantumVulnerability v) => v switch
    {
        QuantumVulnerability.PostQuantum => 0,
        QuantumVulnerability.NotVulnerable => 1,
        QuantumVulnerability.ReducedMargin => 2,
        _ => 3,
    };

    [Fact]
    public void EveryFinding_HasDocumentedBasis_AndBomRef()
    {
        foreach (CryptoFinding f in AllFindings())
        {
            Assert.False(string.IsNullOrWhiteSpace(f.RiskBasis), $"{f.RuleId}/{f.AlgorithmName} has no basis");
            Assert.False(string.IsNullOrWhiteSpace(f.BomRef), $"{f.RuleId}/{f.AlgorithmName} has no bom-ref");
        }
    }

    [Fact]
    public void BrokenPrimitives_AreNeverBelowHigh()
    {
        foreach (CryptoFinding f in AllFindings())
            if (f.ClassicalWeakness == ClassicalWeakness.Broken)
                Assert.True(f.RiskLevel >= RiskLevel.High, $"{f.RuleId}/{f.AlgorithmName} is broken but {f.RiskLevel}");
    }

    [Fact]
    public void Recommendations_NeverIncreaseVulnerability()
    {
        foreach (CryptoFinding f in AllFindings())
        {
            int source = Safety(f.QuantumVulnerability);
            foreach (RecommendationOption o in f.Recommendation.Options)
                if (o.ResultingVulnerability is { } resulting)
                    Assert.True(Safety(resulting) <= source,
                        $"{f.RuleId}/{f.AlgorithmName}: recommendation would reduce safety");
        }
    }

    [Fact]
    public void RiskScore_IsAlwaysInRange()
    {
        foreach (CryptoFinding f in AllFindings())
            Assert.InRange(f.RiskScore, 0, 100);
    }

    [Fact]
    public void Scan_IsDeterministic_AcrossRuns()
    {
        var engine = new ScanEngine(DetectorRegistry.CreateDefault(KnowledgeBase.LoadDefault()));
        string src = Corpus[0] + "\n" + Corpus[1] + "\n" + Corpus[4];
        string[] First() => engine.AnalyzeCompilation(TestCompilation.Create(src))
            .Select(f => f.BomRef!).ToArray();

        Assert.Equal(First(), First());
    }
}
