namespace PostQuantum.CryptographicBillOfMaterials.Model;

/// <summary>
/// A single cryptographic finding. Maps to one CycloneDX <c>cryptographic-asset</c> component.
/// Immutable; produced by detectors and scored by the risk engine.
/// </summary>
public sealed record CryptoFinding
{
    /// <summary>Rule identifier, e.g. <c>CBOM0007</c>.</summary>
    public required string RuleId { get; init; }

    /// <summary>Short human-readable title.</summary>
    public required string Title { get; init; }

    /// <summary>Detection category.</summary>
    public required RuleCategory Category { get; init; }

    /// <summary>CycloneDX assetType.</summary>
    public CryptoAssetType AssetType { get; init; } = CryptoAssetType.Algorithm;

    /// <summary>Display name of the algorithm/material, e.g. <c>AES-128-ECB</c> or <c>RSA</c>.</summary>
    public required string AlgorithmName { get; init; }

    public string? Primitive { get; init; }
    public int? KeySizeBits { get; init; }
    public string? Curve { get; init; }
    public string? Mode { get; init; }
    public string? Padding { get; init; }
    public int? ClassicalSecurityLevel { get; init; }
    public int? NistQuantumSecurityLevel { get; init; }
    public string? Oid { get; init; }

    /// <summary>True for hybrid classical+PQC constructions (strongest positive signal).</summary>
    public bool IsHybrid { get; init; }

    public QuantumVulnerability QuantumVulnerability { get; init; }
    public QuantumThreat QuantumThreat { get; init; }
    public ClassicalWeakness ClassicalWeakness { get; init; }
    public UsageContext UsageContext { get; init; } = UsageContext.Unknown;

    public DetectionConfidence Confidence { get; init; } = DetectionConfidence.High;
    public DetectionMethod DetectionMethod { get; init; } = DetectionMethod.Symbol;

    /// <summary>Final risk level (after formula + floors).</summary>
    public RiskLevel RiskLevel { get; init; }

    /// <summary>Transparent 0–100 risk score.</summary>
    public int RiskScore { get; init; }

    /// <summary>The documented basis for the risk classification (citation string). Required by design.</summary>
    public required string RiskBasis { get; init; }

    public Recommendation Recommendation { get; init; } = Recommendation.None;

    public required SourceLocation Location { get; init; }

    /// <summary>Stable CycloneDX bom-ref (normalized location + symbol hash).</summary>
    public string? BomRef { get; init; }

    /// <summary>Remediation lifecycle state (set by baseline diff and config waivers); drives audit reporting.</summary>
    public RemediationStatus Status { get; init; } = RemediationStatus.Unknown;

    /// <summary>Justification recorded when this finding is waived via config. Required for an audit-friendly waiver.</summary>
    public string? WaiverJustification { get; init; }

    /// <summary>Who approved the waiver (name/role), recorded from config.</summary>
    public string? WaiverApprover { get; init; }

    /// <summary>ISO date (yyyy-MM-dd) when the waiver expires, after which the finding re-activates.</summary>
    public string? WaiverExpiry { get; init; }

    /// <summary>The policy profile in force when this finding was scored (e.g., <c>cnsa2</c>).</summary>
    public string? PolicyProfile { get; init; }
}
