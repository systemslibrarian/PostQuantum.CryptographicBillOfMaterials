using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Configuration;

/// <summary>
/// A named risk posture. Different audiences (commercial, federal/NSS, audit) need different answers, but a
/// profile may only ever <em>raise</em> severity or <em>require more evidence</em> — it can never silently
/// make a risky finding disappear or score lower (the misuse-resistance invariant, TDD §0). A profile is
/// recorded in the CBOM so every report states which posture produced it.
/// </summary>
public sealed class PolicyProfile
{
    public required string Name { get; init; }
    public required string Description { get; init; }

    /// <summary>Raise every Shor-vulnerable (quantum-vulnerable) finding to at least this level, if set.</summary>
    public RiskLevel? QuantumVulnerableFloor { get; init; }

    /// <summary>Raise every Grover reduced-margin finding (e.g., AES-128) to at least this level, if set.</summary>
    public RiskLevel? ReducedMarginFloor { get; init; }

    /// <summary>
    /// When false (the <c>audit</c> posture), a disabled-rule waiver does not drop the finding from the
    /// inventory: it is kept and marked <see cref="RemediationStatus.Waived"/> so an auditor still sees it.
    /// When true, a waiver suppresses the finding from output (still counted in the recorded waiver tally).
    /// </summary>
    public bool WaiversSuppress { get; init; } = true;

    /// <summary>Whether date-sensitive recommendations should be presented with maximum standards detail.</summary>
    public bool VerboseBasis { get; init; }

    /// <summary>The conservative commercial default applied when no profile is selected.</summary>
    public static PolicyProfile Default => Get("general");

    private static readonly Dictionary<string, PolicyProfile> BuiltIn =
        new[]
        {
            new PolicyProfile
            {
                Name = "general",
                Description = "Conservative commercial default. Draft guidance is labelled as draft.",
            },
            new PolicyProfile
            {
                Name = "federal",
                Description = "NIST-centered U.S. federal posture. Shor-vulnerable public-key crypto is at least High.",
                QuantumVulnerableFloor = RiskLevel.High,
            },
            new PolicyProfile
            {
                Name = "cnsa2",
                Description = "CNSA 2.0 / national-security-systems posture. AES-128 is insufficient (AES-256 required); "
                    + "Shor-vulnerable crypto is at least High.",
                QuantumVulnerableFloor = RiskLevel.High,
                ReducedMarginFloor = RiskLevel.High,
                VerboseBasis = true,
            },
            new PolicyProfile
            {
                Name = "audit",
                Description = "Maximum-evidence audit posture. Waivers annotate rather than suppress; full basis is shown.",
                WaiversSuppress = false,
                VerboseBasis = true,
            },
            new PolicyProfile
            {
                Name = "developer",
                Description = "Lower-noise local posture focused on actionable fixes. Risk classification is unchanged "
                    + "(never lowered); presentation favors High+ findings.",
            },
        }.ToDictionary(p => p.Name, StringComparer.OrdinalIgnoreCase);

    /// <summary>All built-in profile names, for help text and validation.</summary>
    public static IReadOnlyCollection<string> Names => BuiltIn.Keys;

    /// <summary>True if <paramref name="name"/> is a known built-in profile.</summary>
    public static bool IsKnown(string name) => BuiltIn.ContainsKey(name);

    /// <summary>Resolve a profile by name (case-insensitive); falls back to the default for unknown names.</summary>
    public static PolicyProfile Get(string? name) =>
        name is not null && BuiltIn.TryGetValue(name, out PolicyProfile? p) ? p : BuiltIn["general"];
}
