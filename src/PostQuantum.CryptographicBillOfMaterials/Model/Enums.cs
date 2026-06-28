namespace PostQuantum.CryptographicBillOfMaterials.Model;

/// <summary>Overall, quantum-weighted severity of a finding. Higher ordinal = more severe.</summary>
public enum RiskLevel
{
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// <summary>
/// The quantum-resistance verdict for an algorithm, independent of any classical weakness.
/// </summary>
public enum QuantumVulnerability
{
    /// <summary>Believed safe against known quantum attacks (e.g., AES-256, SHA-384).</summary>
    NotVulnerable,

    /// <summary>Security margin reduced by Grover but not broken (e.g., AES-128).</summary>
    ReducedMargin,

    /// <summary>Broken by a cryptographically relevant quantum computer via Shor (RSA, ECC, DH).</summary>
    Vulnerable,

    /// <summary>A NIST-standardized post-quantum algorithm (ML-KEM, ML-DSA, SLH-DSA). Positive signal.</summary>
    PostQuantum,
}

/// <summary>The quantum mechanism by which an algorithm is threatened.</summary>
public enum QuantumThreat
{
    None,
    Grover,
    Shor,
    HarvestNowDecryptLater,
}

/// <summary>Classical (non-quantum) weakness of an algorithm or usage.</summary>
public enum ClassicalWeakness
{
    None,
    Suboptimal,
    Deprecated,
    Broken,
}

/// <summary>How confident the detector is that this finding is real. Never used to suppress high-risk findings.</summary>
public enum DetectionConfidence
{
    Low,
    Medium,
    High,
    Confirmed,
}

/// <summary>How the finding was identified.</summary>
public enum DetectionMethod
{
    Symbol,
    Constant,
    Heuristic,
    Config,
}

/// <summary>The usage context of a cryptographic asset; drives exposure weighting.</summary>
public enum UsageContext
{
    Unknown,
    Hashing,
    Signing,
    Auth,
    AtRest,
    InTransit,
    KeyExchange,
}

/// <summary>CycloneDX cryptographic-asset assetType.</summary>
public enum CryptoAssetType
{
    Algorithm,
    Certificate,
    Protocol,
    RelatedCryptoMaterial,
}

/// <summary>
/// The remediation lifecycle state of a finding, for audit-packet reporting. <see cref="New"/>,
/// <see cref="Unchanged"/>, <see cref="Fixed"/>, and <see cref="Regressed"/> are derived from a baseline
/// diff; <see cref="Waived"/> comes from an explicit, justified config waiver.
/// </summary>
public enum RemediationStatus
{
    /// <summary>No baseline was supplied, so lifecycle state is unknown.</summary>
    Unknown = 0,
    New,
    Unchanged,
    Fixed,
    Regressed,
    Waived,
}

/// <summary>Detection rule category.</summary>
public enum RuleCategory
{
    SymmetricEncryption,
    AsymmetricEncryption,
    KeyExchange,
    Hashing,
    Mac,
    KeyDerivation,
    DigitalSignature,
    Jwt,
    Tls,
    CloudKms,
    Randomness,
    HardcodedSecret,
    PostQuantum,
}
