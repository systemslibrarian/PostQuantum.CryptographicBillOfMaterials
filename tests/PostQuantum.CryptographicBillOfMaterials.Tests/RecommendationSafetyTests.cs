using PostQuantum.CryptographicBillOfMaterials.Knowledge;
using PostQuantum.CryptographicBillOfMaterials.Model;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Tests;

/// <summary>
/// Enforces the misuse-resistance invariant (TDD §4 principle 4, §5.4): a recommendation must never
/// steer a user toward a configuration weaker than the one detected.
/// </summary>
public class RecommendationSafetyTests
{
    private static readonly KnowledgeBase Kb = KnowledgeBase.LoadDefault();

    // Lower number = safer.
    private static int Severity(QuantumVulnerability v) => v switch
    {
        QuantumVulnerability.PostQuantum => 0,
        QuantumVulnerability.NotVulnerable => 1,
        QuantumVulnerability.ReducedMargin => 2,
        QuantumVulnerability.Vulnerable => 3,
        _ => 3,
    };

    [Fact]
    public void NoRecommendationOption_IsLessSafeThanTheSource()
    {
        foreach (AlgorithmInfo algo in Kb.Algorithms)
        {
            if (algo.Recommendation is null)
                continue;

            int sourceSeverity = Severity(algo.QuantumVulnerability);
            foreach (RecommendationOptionData option in algo.Recommendation.Options)
            {
                if (option.ResultingVulnerability is { } resulting)
                {
                    Assert.True(
                        Severity(resulting) <= sourceSeverity,
                        $"{algo.Name}: option '{option.Description}' would downgrade safety.");
                }
            }
        }
    }

    [Fact]
    public void EveryQuantumVulnerableAlgorithm_OffersAtLeastOnePqcPath()
    {
        foreach (AlgorithmInfo algo in Kb.Algorithms)
        {
            if (algo.QuantumVulnerability != QuantumVulnerability.Vulnerable)
                continue;

            Assert.NotNull(algo.Recommendation);
            Assert.Contains(
                algo.Recommendation!.Options,
                o => o.ResultingVulnerability is QuantumVulnerability.PostQuantum
                       or QuantumVulnerability.NotVulnerable);
        }
    }
}
