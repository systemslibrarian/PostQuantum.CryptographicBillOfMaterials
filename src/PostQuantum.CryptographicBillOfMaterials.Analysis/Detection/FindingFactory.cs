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

    private static bool IsLongLivedConfidentiality(QuantumVulnerability qv, UsageContext usage) =>
        qv == QuantumVulnerability.Vulnerable
        && usage is UsageContext.AtRest or UsageContext.InTransit or UsageContext.KeyExchange;
}
