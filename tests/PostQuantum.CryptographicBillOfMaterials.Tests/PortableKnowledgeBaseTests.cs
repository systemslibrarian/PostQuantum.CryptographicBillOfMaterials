using PostQuantum.CryptographicBillOfMaterials.Knowledge;
using PostQuantum.CryptographicBillOfMaterials.Model;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Tests;

/// <summary>
/// The analyzer loads the knowledge base through LoadPortable (MiniJson) because its dependency closure has
/// to stay limited to the compiler libraries, while the CLI uses LoadDefault (System.Text.Json). Nothing
/// tested that the two agree, so their algorithm data matching was luck rather than a guarded invariant —
/// and any drift shows up as the editor and the CBOM disagreeing about the same code.
/// </summary>
public class PortableKnowledgeBaseTests
{
    private static readonly KnowledgeBase Stj = KnowledgeBase.LoadDefault();
    private static readonly KnowledgeBase Mini = KnowledgeBase.LoadPortable();

    [Fact]
    public void AlgorithmData_IsIdenticalToTheSystemTextJsonPath()
    {
        Assert.Equal(Stj.Version, Mini.Version);
        Assert.Equal(Stj.PlaybooksVersion, Mini.PlaybooksVersion);
        Assert.Equal(Stj.Algorithms.Count, Mini.Algorithms.Count);
        Assert.NotEmpty(Stj.Algorithms);

        foreach (AlgorithmInfo expected in Stj.Algorithms)
        {
            AlgorithmInfo actual = Assert.Single(Mini.Algorithms, a => a.Name == expected.Name);
            Assert.Equal(expected.Primitive, actual.Primitive);
            Assert.Equal(expected.QuantumVulnerability, actual.QuantumVulnerability);
            Assert.Equal(expected.QuantumThreat, actual.QuantumThreat);
            Assert.Equal(expected.ClassicalWeakness, actual.ClassicalWeakness);
            Assert.Equal(expected.Basis, actual.Basis);
            Assert.Equal(expected.MigrationPlaybookIds, actual.MigrationPlaybookIds);

            // Recommendation is optional (algorithms that need no migration carry none), so absence must
            // agree too — a reader that silently dropped the whole node would otherwise pass.
            Assert.Equal(expected.Recommendation is null, actual.Recommendation is null);
            if (expected.Recommendation is null)
                continue;

            Assert.Equal(expected.Recommendation.Summary, actual.Recommendation!.Summary);
            Assert.Equal(
                expected.Recommendation.Options.Select(o => (o.Description, o.Basis, o.Tradeoffs, o.ResultingVulnerability)),
                actual.Recommendation.Options.Select(o => (o.Description, o.Basis, o.Tradeoffs, o.ResultingVulnerability)));
        }
    }

    [Fact]
    public void Playbooks_AreShallow_ExactlyAsDocumented()
    {
        // The shallow load is deliberate (MiniJson exists to bound the analyzer's dependency closure, not to
        // grow a second full deserializer). This pins the documented contract so the doc cannot drift back
        // into claiming parity it does not deliver.
        Assert.Equal(Stj.Playbooks.Count, Mini.Playbooks.Count);
        Assert.NotEmpty(Stj.Playbooks);

        foreach (MigrationPlaybook expected in Stj.Playbooks)
        {
            MigrationPlaybook actual = Assert.Single(Mini.Playbooks, p => p.Id == expected.Id);
            Assert.Equal(expected.Title, actual.Title);
            Assert.Equal(expected.AppliesTo, actual.AppliesTo);
            Assert.Equal(expected.Target, actual.Target);
            Assert.Equal(expected.Steps, actual.Steps);

            Assert.NotEmpty(expected.Approaches);
            Assert.NotEmpty(expected.References);
            Assert.Empty(actual.Approaches);
            Assert.Empty(actual.References);
        }
    }
}
