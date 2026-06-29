using PostQuantum.CryptographicBillOfMaterials.Knowledge;
using PostQuantum.CryptographicBillOfMaterials.Model;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Tests;

public class KnowledgeBaseTests
{
    private static readonly KnowledgeBase Kb = KnowledgeBase.LoadDefault();

    [Fact]
    public void LoadsEmbeddedKnowledgeBase()
    {
        Assert.NotEmpty(Kb.Algorithms);
        Assert.Equal("1.0", Kb.Version);
    }

    [Theory]
    [InlineData("RSA", QuantumVulnerability.Vulnerable)]
    [InlineData("ECDH", QuantumVulnerability.Vulnerable)]
    [InlineData("AES", QuantumVulnerability.NotVulnerable)]
    [InlineData("ML-KEM", QuantumVulnerability.PostQuantum)]
    [InlineData("ML-DSA", QuantumVulnerability.PostQuantum)]
    public void KnownAlgorithms_HaveExpectedQuantumVerdict(string name, QuantumVulnerability expected)
    {
        AlgorithmInfo? info = Kb.Lookup(name);
        Assert.NotNull(info);
        Assert.Equal(expected, info!.QuantumVulnerability);
    }

    [Fact]
    public void EveryAlgorithm_HasADocumentedBasis()
    {
        // Accuracy-over-confidence: no verdict ships without a citation.
        Assert.All(Kb.Algorithms, a => Assert.False(string.IsNullOrWhiteSpace(a.Basis)));
    }

    [Fact]
    public void PortableLoader_ProducesIdenticalData_ToSystemTextJsonLoader()
    {
        // The analyzer loads the knowledge base via the dependency-free MiniJson path (LoadPortable) to
        // keep System.Text.Json out of the analyzer's load context. This guards that the two paths never
        // drift: every field of every algorithm (and its recommendation) must match the STJ result.
        KnowledgeBase portable = KnowledgeBase.LoadPortable();

        Assert.Equal(Kb.Version, portable.Version);

        var expected = Kb.Algorithms.OrderBy(a => a.Name, StringComparer.Ordinal).ToList();
        var actual = portable.Algorithms.OrderBy(a => a.Name, StringComparer.Ordinal).ToList();
        Assert.Equal(expected.Count, actual.Count);

        foreach (var (e, a) in expected.Zip(actual))
        {
            Assert.Equal(e.Name, a.Name);
            Assert.Equal(e.Primitive, a.Primitive);
            Assert.Equal(e.DefaultKeyBits, a.DefaultKeyBits);
            Assert.Equal(e.ClassicalSecurityLevel, a.ClassicalSecurityLevel);
            Assert.Equal(e.NistQuantumSecurityLevel, a.NistQuantumSecurityLevel);
            Assert.Equal(e.Oid, a.Oid);
            Assert.Equal(e.QuantumVulnerability, a.QuantumVulnerability);
            Assert.Equal(e.QuantumThreat, a.QuantumThreat);
            Assert.Equal(e.ClassicalWeakness, a.ClassicalWeakness);
            Assert.Equal(e.Basis, a.Basis);

            Assert.Equal(e.Recommendation is null, a.Recommendation is null);
            if (e.Recommendation is null)
                continue;

            Assert.Equal(e.Recommendation.Summary, a.Recommendation!.Summary);
            Assert.Equal(e.Recommendation.Options.Count, a.Recommendation.Options.Count);
            foreach (var (eo, ao) in e.Recommendation.Options.Zip(a.Recommendation.Options))
            {
                Assert.Equal(eo.Description, ao.Description);
                Assert.Equal(eo.Basis, ao.Basis);
                Assert.Equal(eo.Tradeoffs, ao.Tradeoffs);
                Assert.Equal(eo.ResultingVulnerability, ao.ResultingVulnerability);
            }
        }
    }
}
