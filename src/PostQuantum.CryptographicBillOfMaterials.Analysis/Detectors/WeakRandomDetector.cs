using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Rules;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detectors;

/// <summary>
/// Detects construction of <c>System.Random</c>, a non-cryptographic RNG. Flagged low-confidence/low-noise
/// since it is only a weakness when used to generate keys, tokens, salts, or IVs.
/// </summary>
internal sealed class WeakRandomDetector : DetectorBase
{
    private const string SystemRandomType = "System.Random";

    public override DetectorMetadata Metadata { get; } = new(
        "CBOM0050", "Non-cryptographic random number generator", RuleCategory.Randomness, RiskLevel.Low,
        "System.Random is not cryptographically secure; use RandomNumberGenerator for security-sensitive values (CWE-338).");

    public override IReadOnlyCollection<SyntaxKind> SyntaxKinds { get; } =
        new[] { SyntaxKind.ObjectCreationExpression };

    public override void Inspect(DetectionContext ctx)
    {
        ITypeSymbol? type = ResolveInstantiatedType(ctx);
        if (type is null || FullName(type) != SystemRandomType)
            return;

        const string basis =
            "System.Random is not cryptographically secure; if used for keys/tokens/IVs use RandomNumberGenerator (CWE-338).";

        var recommendation = new Recommendation(
            "For security-sensitive values, use a cryptographically secure RNG.",
            new[]
            {
                new RecommendationOption(
                    "Use System.Security.Cryptography.RandomNumberGenerator (e.g., GetBytes/GetInt32) for keys, tokens, salts, and IVs.",
                    basis, null, QuantumVulnerability.NotVulnerable),
            });

        ctx.Report(FindingFactory.Create(
            Metadata, ctx, ctx.Node,
            displayName: "System.Random (non-cryptographic RNG)",
            quantumVulnerability: QuantumVulnerability.NotVulnerable,
            classicalWeakness: ClassicalWeakness.Suboptimal,
            usage: UsageContext.Unknown,
            confidence: DetectionConfidence.Medium,
            basis: basis,
            recommendation: recommendation,
            assetType: CryptoAssetType.RelatedCryptoMaterial,
            method: DetectionMethod.Heuristic,
            primitive: "rng"));
    }
}
