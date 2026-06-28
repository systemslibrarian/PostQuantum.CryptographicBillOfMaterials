namespace PostQuantum.CryptographicBillOfMaterials.Model;

/// <summary>
/// A single standards-based remediation option. <see cref="ResultingVulnerability"/> records the
/// quantum posture the user would end up in, which the misuse-resistance invariant checks so that
/// no recommendation ever yields a less-safe configuration than the detected state.
/// </summary>
public sealed record RecommendationOption(
    string Description,
    string Basis,
    string? Tradeoffs = null,
    QuantumVulnerability? ResultingVulnerability = null);

/// <summary>An ordered set of remediation options. The first option is the preferred path.</summary>
public sealed record Recommendation(string Summary, IReadOnlyList<RecommendationOption> Options)
{
    /// <summary>A no-op recommendation used for positive / informational findings.</summary>
    public static Recommendation None { get; } =
        new("No action required.", Array.Empty<RecommendationOption>());
}
