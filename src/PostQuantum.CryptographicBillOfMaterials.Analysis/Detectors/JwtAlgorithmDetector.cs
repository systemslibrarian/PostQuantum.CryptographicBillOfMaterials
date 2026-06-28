using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Rules;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detectors;

/// <summary>
/// Detects JWT algorithm weaknesses that the validation-bypass rule (CBOM0021) does not cover:
/// the unsigned <c>alg=none</c> algorithm (raw literal or <c>SecurityAlgorithms.None</c>), and HMAC
/// signing keys that are hardcoded or shorter than the 256-bit minimum for HS256 (RFC 8725 §3.5).
/// </summary>
internal sealed class JwtAlgorithmDetector : DetectorBase
{
    /// <summary>HS256 requires a key at least as long as its 256-bit output (RFC 8725 §3.5; RFC 7518 §3.2).</summary>
    private const int MinHmacKeyBytes = 32;

    public override DetectorMetadata Metadata { get; } = new(
        "CBOM0022", "Unsigned or weak-keyed JWT algorithm", RuleCategory.Jwt, RiskLevel.High,
        "alg=none accepts unsigned tokens; HMAC keys shorter than the hash output are brute-forceable (RFC 8725; RFC 7518).");

    public override IReadOnlyCollection<SyntaxKind> SyntaxKinds { get; } = new[]
    {
        SyntaxKind.ObjectCreationExpression,
        SyntaxKind.SimpleMemberAccessExpression,
        SyntaxKind.StringLiteralExpression,
    };

    public override void Inspect(DetectionContext ctx)
    {
        switch (ctx.Node)
        {
            case ObjectCreationExpressionSyntax oce:
                InspectSigningKey(ctx, oce);
                break;
            case MemberAccessExpressionSyntax ma:
                InspectAlgNoneConstant(ctx, ma);
                break;
            case LiteralExpressionSyntax lit:
                InspectAlgNoneLiteral(ctx, lit);
                break;
        }
    }

    /// <summary><c>new SymmetricSecurityKey(...)</c> with hardcoded or sub-256-bit key material.</summary>
    private void InspectSigningKey(DetectionContext ctx, ObjectCreationExpressionSyntax oce)
    {
        if (SimpleTypeName(oce.Type) != "SymmetricSecurityKey")
            return;
        if (oce.ArgumentList is not { Arguments.Count: > 0 } args)
            return;

        ExpressionSyntax keyArg = args.Arguments[0].Expression;
        (bool weak, bool hardcoded, int? bytes) = ClassifyKeyMaterial(keyArg);
        if (!weak && !hardcoded)
            return;

        string why = hardcoded
            ? "JWT HMAC signing key is hardcoded in source (CWE-321/CWE-798); anyone with the binary can forge tokens."
            : $"JWT HMAC signing key is {bytes.GetValueOrDefault() * 8}-bit, below the 256-bit HS256 minimum (RFC 8725 §3.5; RFC 7518 §3.2).";

        var recommendation = new Recommendation(
            "Use a random signing key of at least 256 bits, loaded from a secret manager — never a hardcoded or short string.",
            new[]
            {
                new RecommendationOption(
                    "Generate a >=256-bit key with RandomNumberGenerator and load it from a KMS / secret store; rotate on schedule.",
                    "RFC 8725 (JWT BCP) §2.1, §3.5; OWASP JWT Cheat Sheet.", null,
                    QuantumVulnerability.NotVulnerable),
            });

        ctx.Report(FindingFactory.Create(
            Metadata, ctx, oce,
            displayName: hardcoded ? "JWT HMAC key (hardcoded)" : $"JWT HMAC key ({bytes.GetValueOrDefault() * 8}-bit)",
            quantumVulnerability: QuantumVulnerability.NotVulnerable,
            classicalWeakness: ClassicalWeakness.Broken,
            usage: UsageContext.Auth,
            confidence: DetectionConfidence.High,
            basis: why,
            recommendation: recommendation,
            floor: hardcoded ? RiskLevel.Critical : RiskLevel.High,
            assetType: CryptoAssetType.RelatedCryptoMaterial,
            method: DetectionMethod.Constant,
            primitive: "hmac"));
    }

    /// <summary><c>SecurityAlgorithms.None</c> — the IdentityModel constant for an unsigned token.</summary>
    private void InspectAlgNoneConstant(DetectionContext ctx, MemberAccessExpressionSyntax ma)
    {
        if (ma.Name.Identifier.ValueText != "None")
            return;
        if (SimpleTypeName(ma.Expression) != "SecurityAlgorithms")
            return;
        ReportAlgNone(ctx, ma);
    }

    /// <summary>A raw <c>"none"</c> JOSE alg literal in a JWT header/descriptor argument.</summary>
    private void InspectAlgNoneLiteral(DetectionContext ctx, LiteralExpressionSyntax lit)
    {
        if (!string.Equals(lit.Token.ValueText, "none", StringComparison.OrdinalIgnoreCase))
            return;

        // Low-FP gate: only when the literal is an argument to a JWT-shaped call/initializer member named
        // like alg/algorithm, so we don't flag unrelated "none" strings.
        if (!IsJwtAlgorithmContext(lit))
            return;
        ReportAlgNone(ctx, lit);
    }

    private void ReportAlgNone(DetectionContext ctx, SyntaxNode node)
    {
        var recommendation = new Recommendation(
            "Never accept alg=none. Require an asymmetric or HMAC signature and validate it.",
            new[]
            {
                new RecommendationOption(
                    "Use a fixed, validated algorithm (e.g., RS256/ES256/HS256) and reject tokens whose header alg differs.",
                    "RFC 8725 (JWT BCP) §2.1, §3.1; OWASP JWT Cheat Sheet.", null,
                    QuantumVulnerability.NotVulnerable),
            });

        ctx.Report(FindingFactory.Create(
            Metadata, ctx, node,
            displayName: "JWT alg=none (unsigned token)",
            quantumVulnerability: QuantumVulnerability.NotVulnerable,
            classicalWeakness: ClassicalWeakness.Broken,
            usage: UsageContext.Auth,
            confidence: DetectionConfidence.High,
            basis: "alg=none disables signature verification entirely, allowing trivial token forgery (RFC 8725 §3.1).",
            recommendation: recommendation,
            floor: RiskLevel.Critical,
            assetType: CryptoAssetType.Protocol,
            primitive: "jwt"));
    }

    /// <summary>
    /// Classify a <c>SymmetricSecurityKey</c> argument. Returns whether the key is weak (sub-256-bit) and/or
    /// hardcoded, plus the inferred byte length when known.
    /// </summary>
    private static (bool Weak, bool Hardcoded, int? Bytes) ClassifyKeyMaterial(ExpressionSyntax keyArg)
    {
        // new byte[] { ... } literal
        if (TryConstantByteArrayLength(keyArg) is int arrayLen)
            return (arrayLen < MinHmacKeyBytes, Hardcoded: true, arrayLen);

        // Encoding.*.GetBytes("literal") — hardcoded; length = UTF8 byte count of the literal
        if (keyArg is InvocationExpressionSyntax inv
            && inv.Expression is MemberAccessExpressionSyntax m
            && m.Name.Identifier.ValueText == "GetBytes"
            && inv.ArgumentList.Arguments.Count > 0
            && inv.ArgumentList.Arguments[0].Expression is LiteralExpressionSyntax s
            && s.IsKind(SyntaxKind.StringLiteralExpression))
        {
            int byteLen = System.Text.Encoding.UTF8.GetByteCount(s.Token.ValueText);
            return (byteLen < MinHmacKeyBytes, Hardcoded: true, byteLen);
        }

        // Convert.FromBase64String("literal") / FromHexString("literal") — hardcoded, length unknown-but-fixed
        if (keyArg is InvocationExpressionSyntax conv
            && conv.Expression is MemberAccessExpressionSyntax cm
            && cm.Name.Identifier.ValueText is "FromBase64String" or "FromHexString"
            && conv.ArgumentList.Arguments.Count > 0
            && conv.ArgumentList.Arguments[0].Expression is LiteralExpressionSyntax)
        {
            return (false, Hardcoded: true, null);
        }

        return (false, false, null);
    }

    private static int? TryConstantByteArrayLength(ExpressionSyntax expression)
    {
        InitializerExpressionSyntax? initializer = expression switch
        {
            ArrayCreationExpressionSyntax a => a.Initializer,
            ImplicitArrayCreationExpressionSyntax ia => ia.Initializer,
            _ => null,
        };
        if (initializer is null || initializer.Expressions.Count == 0)
            return null;
        return initializer.Expressions.All(e => e is LiteralExpressionSyntax)
            ? initializer.Expressions.Count
            : null;
    }

    /// <summary>True when the literal sits in an arg/initializer whose name suggests a JOSE algorithm field.</summary>
    private static bool IsJwtAlgorithmContext(LiteralExpressionSyntax lit)
    {
        for (SyntaxNode? n = lit.Parent; n is not null; n = n.Parent)
        {
            switch (n)
            {
                case AssignmentExpressionSyntax asg when asg.Left is IdentifierNameSyntax or MemberAccessExpressionSyntax:
                    string name = asg.Left is MemberAccessExpressionSyntax ma
                        ? ma.Name.Identifier.ValueText
                        : ((IdentifierNameSyntax)asg.Left).Identifier.ValueText;
                    return LooksLikeAlg(name);
                case ArgumentSyntax { NameColon.Name.Identifier.ValueText: { } argName }:
                    return LooksLikeAlg(argName);
                case StatementSyntax:
                case MemberDeclarationSyntax:
                    return false;
            }
        }
        return false;
    }

    private static bool LooksLikeAlg(string name) =>
        name.Contains("alg", StringComparison.OrdinalIgnoreCase);

    private static string? SimpleTypeName(SyntaxNode? typeOrExpr) => typeOrExpr switch
    {
        IdentifierNameSyntax id => id.Identifier.ValueText,
        QualifiedNameSyntax q => q.Right.Identifier.ValueText,
        MemberAccessExpressionSyntax m => m.Name.Identifier.ValueText,
        GenericNameSyntax g => g.Identifier.ValueText,
        _ => null,
    };
}
