using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Rules;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detectors;

/// <summary>
/// Detects use of <c>System.Random</c> / <c>Random.Shared</c>, a non-cryptographic RNG. Base case is
/// low-noise (a weak RNG for gameplay is not a vulnerability), but <see cref="CryptoTaintAnalysis"/> elevates
/// the finding to Broken/High when intra-method dataflow shows the random output reaching a key/IV/nonce
/// sink — the precise distinction the roadmap calls for, without the false positives of name-matching (CWE-338).
/// </summary>
internal sealed class WeakRandomDetector : DetectorBase
{
    private const string SystemRandomType = "System.Random";

    public override DetectorMetadata Metadata { get; } = new(
        "CBOM0050", "Non-cryptographic random number generator", RuleCategory.Randomness, RiskLevel.Low,
        "System.Random is not cryptographically secure; use RandomNumberGenerator for security-sensitive values (CWE-338).");

    public override IReadOnlyCollection<SyntaxKind> SyntaxKinds { get; } =
        new[] { SyntaxKind.ObjectCreationExpression, SyntaxKind.SimpleMemberAccessExpression };

    public override void Inspect(DetectionContext ctx)
    {
        SyntaxNode? source = MatchRandomSource(ctx);
        if (source is null)
            return;

        bool sensitive = CryptoTaintAnalysis.WeakRandomReachesKeyMaterial(ctx.SemanticModel, source);

        const string baseBasis =
            "System.Random is not cryptographically secure; if used for keys/tokens/IVs use RandomNumberGenerator (CWE-338).";
        const string sensitiveBasis =
            "Weak randomness from System.Random flows into key/IV/nonce material (intra-method dataflow). Its "
            + "predictable, seedable state makes the produced secret recoverable (CWE-338, CWE-330).";

        string basis = sensitive ? sensitiveBasis : baseBasis;

        var recommendation = new Recommendation(
            sensitive
                ? "Replace System.Random with a cryptographically secure RNG for this secret material."
                : "For any security-sensitive values, use a cryptographically secure RNG.",
            new[]
            {
                new RecommendationOption(
                    "Use System.Security.Cryptography.RandomNumberGenerator (e.g., GetBytes/GetInt32) for keys, tokens, salts, IVs, and nonces.",
                    basis, null, QuantumVulnerability.NotVulnerable),
            });

        ctx.Report(FindingFactory.Create(
            Metadata, ctx, source,
            displayName: sensitive
                ? "System.Random reaching key material"
                : "System.Random (non-cryptographic RNG)",
            quantumVulnerability: QuantumVulnerability.NotVulnerable,
            classicalWeakness: sensitive ? ClassicalWeakness.Broken : ClassicalWeakness.Suboptimal,
            usage: sensitive ? UsageContext.Auth : UsageContext.Unknown,
            confidence: sensitive ? DetectionConfidence.High : DetectionConfidence.Medium,
            basis: basis,
            recommendation: recommendation,
            floor: sensitive ? RiskLevel.High : null,
            assetType: CryptoAssetType.RelatedCryptoMaterial,
            method: DetectionMethod.Heuristic,
            primitive: "rng"));
    }

    /// <summary>Match a weak-random source: <c>new Random()</c> or the <c>Random.Shared</c> singleton.</summary>
    private static SyntaxNode? MatchRandomSource(DetectionContext ctx)
    {
        switch (ctx.Node)
        {
            case ObjectCreationExpressionSyntax:
                ITypeSymbol? type = ResolveInstantiatedType(ctx);
                return type is not null && FullName(type) == SystemRandomType ? ctx.Node : null;

            case MemberAccessExpressionSyntax ma when ma.Name.Identifier.ValueText == "Shared":
                // Report at the Random.Shared site only; skip the outer member access of e.g. .NextBytes.
                ITypeSymbol? t = ctx.SemanticModel.GetTypeInfo(ma).Type;
                return t is not null && FullName(t) == SystemRandomType ? ma : null;

            default:
                return null;
        }
    }
}
