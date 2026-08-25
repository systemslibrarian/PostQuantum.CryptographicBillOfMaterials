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
    public void LoadsMigrationPlaybooks()
    {
        Assert.NotEmpty(Kb.Playbooks);
        Assert.Equal("1.0", Kb.PlaybooksVersion);
    }

    [Fact]
    public void EveryReferencedPlaybookId_Resolves()
    {
        // Referential integrity: an algorithm must never point at a playbook that does not exist, or the
        // report would silently drop migration guidance for a quantum-vulnerable finding.
        foreach (AlgorithmInfo a in Kb.Algorithms)
            foreach (string id in a.MigrationPlaybookIds)
                Assert.True(Kb.Playbook(id) is not null, $"{a.Name} references missing playbook '{id}'");
    }

    [Fact]
    public void EveryShorVulnerableAlgorithm_HasAMigrationPlaybook()
    {
        // The mission: every quantum-broken (Shor) public-key algorithm must carry actionable PQC guidance.
        var missing = Kb.Algorithms
            .Where(a => a.QuantumVulnerability == QuantumVulnerability.Vulnerable)
            .Where(a => Kb.PlaybooksForAlgorithm(a.Name).Count == 0)
            .Select(a => a.Name)
            .ToArray();
        Assert.True(missing.Length == 0, "Vulnerable algorithms without a playbook: " + string.Join(", ", missing));
    }

    [Fact]
    public void EveryPlaybook_IsWellFormed()
    {
        // A shipped playbook must be actionable: title, applicability, target, at least one approach with a
        // worked example, ordered steps, and at least one authoritative reference with a real URL.
        foreach (MigrationPlaybook pb in Kb.Playbooks)
        {
            Assert.False(string.IsNullOrWhiteSpace(pb.Id));
            Assert.False(string.IsNullOrWhiteSpace(pb.Title), $"{pb.Id}: title");
            Assert.False(string.IsNullOrWhiteSpace(pb.AppliesTo), $"{pb.Id}: appliesTo");
            Assert.False(string.IsNullOrWhiteSpace(pb.Target), $"{pb.Id}: target");
            Assert.NotEmpty(pb.Approaches);
            Assert.All(pb.Approaches, a =>
            {
                Assert.False(string.IsNullOrWhiteSpace(a.Name), $"{pb.Id}: approach name");
                Assert.False(string.IsNullOrWhiteSpace(a.Code), $"{pb.Id}/{a.Name}: code");
            });
            Assert.NotEmpty(pb.Steps);
            Assert.NotEmpty(pb.References);
            Assert.All(pb.References, r => Assert.StartsWith("https://", r.Url));
        }
    }

    [Fact]
    public void PlaybookIdSet_IsStable()
    {
        // Drift guard: changing the shipped playbook IDs must be deliberate (they are cited in CBOM output).
        string[] ids = Kb.Playbooks.Select(p => p.Id).OrderBy(x => x, System.StringComparer.Ordinal).ToArray();
        Assert.Equal(new[] { "pqc-key-establishment", "pqc-signatures" }, ids);
    }

    [Fact]
    public void Rsa_MapsToBothKeyEstablishmentAndSignaturePlaybooks()
    {
        // RSA is used for both encryption/key transport and signing, so it must surface both playbooks.
        var ids = Kb.PlaybooksForAlgorithm("RSA").Select(p => p.Id).ToArray();
        Assert.Contains("pqc-key-establishment", ids);
        Assert.Contains("pqc-signatures", ids);
    }
}
