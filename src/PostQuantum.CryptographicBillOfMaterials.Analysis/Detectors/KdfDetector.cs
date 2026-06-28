using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Rules;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detectors;

/// <summary>
/// Detects weak password-based key derivation: the obsolete <c>PasswordDeriveBytes</c> (PBKDF1) and
/// <c>Rfc2898DeriveBytes</c> (PBKDF2) configured with an iteration count below current OWASP guidance.
/// </summary>
internal sealed class KdfDetector : DetectorBase
{
    private const int MinPbkdf2Iterations = 100_000;
    private const string PasswordDeriveBytesType = "System.Security.Cryptography.PasswordDeriveBytes";
    private const string Rfc2898Type = "System.Security.Cryptography.Rfc2898DeriveBytes";

    public override DetectorMetadata Metadata { get; } = new(
        "CBOM0060", "Weak key derivation function", RuleCategory.KeyDerivation, RiskLevel.High,
        "Password-based key derivation must use PBKDF2/Argon2 with adequate iterations (OWASP Password Storage Cheat Sheet).");

    public override IReadOnlyCollection<SyntaxKind> SyntaxKinds { get; } =
        new[] { SyntaxKind.ObjectCreationExpression, SyntaxKind.InvocationExpression };

    public override void Inspect(DetectionContext ctx)
    {
        ITypeSymbol? type = ResolveInstantiatedType(ctx);
        if (type is null)
            return;

        string fullName = FullName(type);

        if (fullName == PasswordDeriveBytesType)
        {
            ReportPasswordDeriveBytes(ctx);
            return;
        }

        if (fullName == Rfc2898Type)
            ReportWeakPbkdf2(ctx);
    }

    private void ReportPasswordDeriveBytes(DetectionContext ctx)
    {
        const string basis =
            "PasswordDeriveBytes implements the obsolete PBKDF1; use Rfc2898DeriveBytes (PBKDF2) or Argon2.";

        var recommendation = new Recommendation(
            "Replace PBKDF1 with PBKDF2 (Rfc2898DeriveBytes) or Argon2id.",
            new[]
            {
                new RecommendationOption(
                    "Use Rfc2898DeriveBytes (PBKDF2-HMAC-SHA256) with >= 100,000 iterations, or Argon2id.",
                    basis, null, QuantumVulnerability.NotVulnerable),
            });

        ctx.Report(FindingFactory.Create(
            Metadata, ctx, ctx.Node,
            displayName: "PasswordDeriveBytes (PBKDF1)",
            quantumVulnerability: QuantumVulnerability.NotVulnerable,
            classicalWeakness: ClassicalWeakness.Deprecated,
            usage: UsageContext.AtRest,
            confidence: DetectionConfidence.Confirmed,
            basis: basis,
            recommendation: recommendation,
            floor: RiskLevel.High,
            assetType: CryptoAssetType.RelatedCryptoMaterial,
            primitive: "kdf"));
    }

    private void ReportWeakPbkdf2(DetectionContext ctx)
    {
        int? iterations = FirstIntArgument(ctx);
        if (iterations is not { } iters || iters >= MinPbkdf2Iterations)
            return; // No constant iteration count, or count meets guidance: stay low-noise.

        const string basis =
            "PBKDF2 iteration count below current OWASP guidance (>= 100,000 for PBKDF2-HMAC-SHA256).";

        var recommendation = new Recommendation(
            "Raise the PBKDF2 iteration count or migrate to Argon2id.",
            new[]
            {
                new RecommendationOption(
                    "Use >= 100,000 iterations for PBKDF2-HMAC-SHA256 (more for stronger HMACs), or switch to Argon2id.",
                    basis, null, QuantumVulnerability.NotVulnerable),
            });

        ctx.Report(FindingFactory.Create(
            Metadata, ctx, ctx.Node,
            displayName: $"PBKDF2 ({iters} iterations)",
            quantumVulnerability: QuantumVulnerability.NotVulnerable,
            classicalWeakness: ClassicalWeakness.Suboptimal,
            usage: UsageContext.AtRest,
            confidence: DetectionConfidence.High,
            basis: basis,
            recommendation: recommendation,
            assetType: CryptoAssetType.RelatedCryptoMaterial,
            method: DetectionMethod.Constant,
            primitive: "kdf"));
    }
}
