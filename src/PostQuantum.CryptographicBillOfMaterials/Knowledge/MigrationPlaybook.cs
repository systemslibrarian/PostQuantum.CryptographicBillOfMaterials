namespace PostQuantum.CryptographicBillOfMaterials.Knowledge;

/// <summary>
/// A concrete, .NET-specific guide for migrating one class of quantum-vulnerable cryptography to a
/// post-quantum scheme. Lives in <c>playbooks.json</c> (data, not code) so the migration guidance can be
/// reviewed, cited, and versioned independently of detector logic — the same discipline as the algorithm
/// knowledge base. A playbook turns a finding's one-line recommendation into actionable steps, library
/// options, and worked code so a team without a cryptographer can execute the transition.
/// </summary>
public sealed class MigrationPlaybook
{
    /// <summary>Stable identifier referenced from <see cref="AlgorithmInfo.MigrationPlaybookIds"/>.</summary>
    public string Id { get; init; } = "";

    /// <summary>Short human title, e.g. "Migrate key establishment to ML-KEM (hybrid first)".</summary>
    public string Title { get; init; } = "";

    /// <summary>Which crypto this applies to and why it matters (e.g. harvest-now-decrypt-later urgency).</summary>
    public string AppliesTo { get; init; } = "";

    /// <summary>The recommended post-quantum end state in one sentence.</summary>
    public string Target { get; init; } = "";

    /// <summary>Ordered implementation options, preferred first.</summary>
    public List<MigrationApproach> Approaches { get; init; } = new();

    /// <summary>Ordered migration steps a team can follow.</summary>
    public List<string> Steps { get; init; } = new();

    /// <summary>Authoritative references (standards and .NET docs) backing the guidance.</summary>
    public List<PlaybookReference> References { get; init; } = new();
}

/// <summary>One concrete way to implement the migration (in-box .NET, BouncyCastle, transport, hybrid).</summary>
public sealed class MigrationApproach
{
    public string Name { get; init; } = "";

    /// <summary>Availability/maturity and platform requirements for this approach.</summary>
    public string Status { get; init; } = "";

    /// <summary>The situation this approach is the right fit for.</summary>
    public string RecommendedFor { get; init; } = "";

    /// <summary>Language of <see cref="Code"/> for fenced rendering (e.g. "csharp", "text").</summary>
    public string Language { get; init; } = "text";

    /// <summary>A worked, copy-pasteable example or concrete step list.</summary>
    public string Code { get; init; } = "";

    /// <summary>Gotchas, interop caveats, and size/performance warnings.</summary>
    public string? Caveats { get; init; }
}

/// <summary>A titled link to a standard or documentation source.</summary>
public sealed class PlaybookReference
{
    public string Title { get; init; } = "";
    public string Url { get; init; } = "";
}
