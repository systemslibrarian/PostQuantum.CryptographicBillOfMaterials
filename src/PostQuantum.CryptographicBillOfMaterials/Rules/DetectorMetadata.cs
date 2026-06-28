using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Rules;

/// <summary>
/// Static metadata for a detection rule. A "basis" citation is mandatory by construction so that no
/// rule can register a weak/quantum verdict without a documented justification (TDD §0, §4).
/// </summary>
public sealed record DetectorMetadata(
    string RuleId,
    string Title,
    RuleCategory Category,
    RiskLevel DefaultSeverity,
    string Basis,
    string? DocumentationUrl = null);
