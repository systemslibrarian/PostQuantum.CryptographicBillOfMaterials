using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Knowledge;

/// <summary>
/// A data-driven fact record about one algorithm. Lives in <c>algorithms.json</c> (data, not code) so that
/// security judgments can be reviewed and cited independently of detector logic (TDD §7.2).
/// </summary>
public sealed class AlgorithmInfo
{
    public string Name { get; init; } = "";
    public string? Primitive { get; init; }
    public int? DefaultKeyBits { get; init; }
    public int? ClassicalSecurityLevel { get; init; }
    public int? NistQuantumSecurityLevel { get; init; }
    public string? Oid { get; init; }
    public QuantumVulnerability QuantumVulnerability { get; init; }
    public QuantumThreat QuantumThreat { get; init; }
    public ClassicalWeakness ClassicalWeakness { get; init; }

    /// <summary>The documented basis (citation string) for this algorithm's verdict. Required for every entry.</summary>
    public string Basis { get; init; } = "";

    public RecommendationData? Recommendation { get; init; }

    /// <summary>
    /// IDs of the migration playbooks (in <c>playbooks.json</c>) that apply to this algorithm. Empty for
    /// algorithms that need no migration. RSA appears in both the key-establishment and signature playbooks
    /// because it is used for both. Referential integrity is enforced by a knowledge-base test.
    /// </summary>
    public List<string> MigrationPlaybookIds { get; init; } = new();
}

/// <summary>Serializable recommendation payload.</summary>
public sealed class RecommendationData
{
    public string Summary { get; init; } = "";
    public List<RecommendationOptionData> Options { get; init; } = new();
}

/// <summary>Serializable recommendation option.</summary>
public sealed class RecommendationOptionData
{
    public string Description { get; init; } = "";
    public string Basis { get; init; } = "";
    public string? Tradeoffs { get; init; }
    public QuantumVulnerability? ResultingVulnerability { get; init; }
}
