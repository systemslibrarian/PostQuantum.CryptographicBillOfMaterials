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
}
