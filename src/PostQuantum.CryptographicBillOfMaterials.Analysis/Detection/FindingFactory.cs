using Microsoft.CodeAnalysis;
using PostQuantum.CryptographicBillOfMaterials.Knowledge;
using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Risk;
using PostQuantum.CryptographicBillOfMaterials.Rules;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;

/// <summary>
/// Builds a fully-scored <see cref="CryptoFinding"/> from an algorithm fact plus per-site overrides.
/// Centralizes risk evaluation, fail-closed floors, harvest-now-decrypt-later threat tagging, and bom-ref
/// generation so detectors stay small and consistent.
/// </summary>
internal static class FindingFactory
{
    public static CryptoFinding FromAlgorithm(
        DetectorMetadata meta,
        AlgorithmInfo info,
        DetectionContext ctx,
        SyntaxNode locationNode,
        KnowledgeBase knowledgeBase,
        UsageContext usage,
        DetectionConfidence confidence,
        int? keySize = null,
        ClassicalWeakness? classicalOverride = null,
        QuantumVulnerability? quantumOverride = null,
        string? mode = null,
        RiskLevel? floor = null,
        Recommendation? recommendationOverride = null,
        string? titleOverride = null,
        string? displayName = null,
        CryptoAssetType assetType = CryptoAssetType.Algorithm,
        DetectionMethod method = DetectionMethod.Symbol)
    {
        QuantumVulnerability qv = quantumOverride ?? info.QuantumVulnerability;
        ClassicalWeakness cw = classicalOverride ?? info.ClassicalWeakness;

        // Fail-closed floors (TDD §5.1): a broken primitive in use is at least High; a Shor-vulnerable
        // algorithm protecting long-lived confidentiality is at least High. Explicit floors win.
        RiskLevel? effectiveFloor = floor;
        if (effectiveFloor is null && cw == ClassicalWeakness.Broken)
            effectiveFloor = RiskLevel.High;
        if (effectiveFloor is null && IsLongLivedConfidentiality(qv, usage))
            effectiveFloor = RiskLevel.High;

        RiskResult risk = RiskEngine.Evaluate(new RiskInput(qv, cw, usage, confidence, effectiveFloor));

        QuantumThreat threat = qv switch
        {
            QuantumVulnerability.Vulnerable => QuantumThreat.Shor,
            QuantumVulnerability.ReducedMargin => QuantumThreat.Grover,
            _ => info.QuantumThreat,
        };
        if (IsLongLivedConfidentiality(qv, usage))
            threat = QuantumThreat.HarvestNowDecryptLater;

        Recommendation recommendation =
            recommendationOverride ?? knowledgeBase.BuildRecommendation(info.Name) ?? Recommendation.None;
        SourceLocation location = ctx.LocationOf(locationNode);
        string display = displayName ?? info.Name;

        return new CryptoFinding
        {
            RuleId = meta.RuleId,
            Title = titleOverride ?? meta.Title,
            Category = meta.Category,
            AssetType = assetType,
            AlgorithmName = display,
            Primitive = info.Primitive,
            KeySizeBits = keySize ?? info.DefaultKeyBits,
            Mode = mode,
            ClassicalSecurityLevel = info.ClassicalSecurityLevel,
            NistQuantumSecurityLevel = info.NistQuantumSecurityLevel,
            Oid = info.Oid,
            QuantumVulnerability = qv,
            QuantumThreat = threat,
            ClassicalWeakness = cw,
            UsageContext = usage,
            Confidence = confidence,
            DetectionMethod = method,
            RiskLevel = risk.Level,
            RiskScore = risk.Score,
            RiskBasis = info.Basis,
            Recommendation = recommendation,
            Location = location,
            BomRef = BomRef.Create(display, location, meta.RuleId),
        };
    }

    /// <summary>
    /// Build a finding for a configuration/usage issue that is not backed by a knowledge-base algorithm
    /// entry (e.g., JWT signature validation disabled, deprecated TLS, disabled cert validation).
    /// </summary>
    public static CryptoFinding Create(
        DetectorMetadata meta,
        DetectionContext ctx,
        SyntaxNode locationNode,
        string displayName,
        QuantumVulnerability quantumVulnerability,
        ClassicalWeakness classicalWeakness,
        UsageContext usage,
        DetectionConfidence confidence,
        string basis,
        Recommendation recommendation,
        RiskLevel? floor = null,
        CryptoAssetType assetType = CryptoAssetType.Algorithm,
        DetectionMethod method = DetectionMethod.Symbol,
        string? primitive = null)
    {
        RiskLevel? effectiveFloor = floor;
        if (effectiveFloor is null && classicalWeakness == ClassicalWeakness.Broken)
            effectiveFloor = RiskLevel.High;
        if (effectiveFloor is null && IsLongLivedConfidentiality(quantumVulnerability, usage))
            effectiveFloor = RiskLevel.High;

        RiskResult risk = RiskEngine.Evaluate(
            new RiskInput(quantumVulnerability, classicalWeakness, usage, confidence, effectiveFloor));

        QuantumThreat threat = quantumVulnerability switch
        {
            QuantumVulnerability.Vulnerable => QuantumThreat.Shor,
            QuantumVulnerability.ReducedMargin => QuantumThreat.Grover,
            _ => QuantumThreat.None,
        };
        if (IsLongLivedConfidentiality(quantumVulnerability, usage))
            threat = QuantumThreat.HarvestNowDecryptLater;

        SourceLocation location = ctx.LocationOf(locationNode);

        return new CryptoFinding
        {
            RuleId = meta.RuleId,
            Title = meta.Title,
            Category = meta.Category,
            AssetType = assetType,
            AlgorithmName = displayName,
            Primitive = primitive,
            QuantumVulnerability = quantumVulnerability,
            QuantumThreat = threat,
            ClassicalWeakness = classicalWeakness,
            UsageContext = usage,
            Confidence = confidence,
            DetectionMethod = method,
            RiskLevel = risk.Level,
            RiskScore = risk.Score,
            RiskBasis = basis,
            Recommendation = recommendation,
            Location = location,
            BomRef = BomRef.Create(displayName, location, meta.RuleId),
        };
    }

    private static bool IsLongLivedConfidentiality(QuantumVulnerability qv, UsageContext usage) =>
        qv == QuantumVulnerability.Vulnerable
        && usage is UsageContext.AtRest or UsageContext.InTransit or UsageContext.KeyExchange;
}
