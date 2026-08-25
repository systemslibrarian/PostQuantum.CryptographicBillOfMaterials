using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
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
    private const int MinPbkdf2Iterations = 600_000;
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
                    "Use Rfc2898DeriveBytes (PBKDF2-HMAC-SHA256) with >= 600,000 iterations, or Argon2id.",
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
        int? iterations = Pbkdf2Iterations(ctx);
        if (iterations is not { } iters || iters >= MinPbkdf2Iterations)
            return; // Couldn't determine the count, or it meets guidance: stay low-noise.

        const string basis =
            "PBKDF2 iteration count below current OWASP guidance (>= 600,000 for PBKDF2-HMAC-SHA256).";

        var recommendation = new Recommendation(
            "Raise the PBKDF2 iteration count or migrate to Argon2id.",
            new[]
            {
                new RecommendationOption(
                    "Use >= 600,000 iterations for PBKDF2-HMAC-SHA256 (more for stronger HMACs), or switch to Argon2id.",
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

    /// <summary>
    /// The PBKDF2 iteration count for this <c>Rfc2898DeriveBytes</c> construction: the constant value of the
    /// parameter literally named <c>iterations</c> (positional or named), or <b>1000</b> — the framework
    /// default — for an overload that has no <c>iterations</c> parameter. Returns null when the constructor
    /// can't be resolved or the count isn't a compile-time constant. This must NOT use "first int argument":
    /// the <c>Rfc2898DeriveBytes(string, int saltSize, int iterations)</c> overload puts saltSize first.
    /// </summary>
    private static int? Pbkdf2Iterations(DetectionContext ctx)
    {
        if (ctx.Node is not ObjectCreationExpressionSyntax oce)
            return null;
        if (ctx.SemanticModel.GetSymbolInfo(oce).Symbol is not IMethodSymbol ctor)
            return null;

        int idx = -1;
        for (int i = 0; i < ctor.Parameters.Length; i++)
        {
            if (ctor.Parameters[i].Name == "iterations") { idx = i; break; }
        }
        if (idx < 0)
            return 1000; // overloads without an explicit iterations parameter default to 1000

        SeparatedSyntaxList<ArgumentSyntax>? args = oce.ArgumentList?.Arguments;
        if (args is null)
            return 1000;

        foreach (ArgumentSyntax a in args)
        {
            if (a.NameColon?.Name.Identifier.ValueText == "iterations")
                return ConstInt(ctx, a.Expression);
        }
        return idx < args.Value.Count && args.Value[idx].NameColon is null
            ? ConstInt(ctx, args.Value[idx].Expression)
            : 1000;
    }

    private static int? ConstInt(DetectionContext ctx, ExpressionSyntax expr)
    {
        Optional<object?> cv = ctx.SemanticModel.GetConstantValue(expr);
        return cv.HasValue && cv.Value is int i ? i : null;
    }
}
