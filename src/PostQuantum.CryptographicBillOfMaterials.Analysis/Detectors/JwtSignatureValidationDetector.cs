using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Rules;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detectors;

/// <summary>
/// Detects JWT validation being weakened to accept unsigned/unverified tokens
/// (<c>TokenValidationParameters.RequireSignedTokens = false</c> or <c>ValidateIssuerSigningKey = false</c>),
/// the practical equivalent of accepting <c>alg=none</c>.
/// </summary>
internal sealed class JwtSignatureValidationDetector : DetectorBase
{
    public override DetectorMetadata Metadata { get; } = new(
        "CBOM0021", "JWT signature validation disabled", RuleCategory.Jwt, RiskLevel.Critical,
        "Accepting unsigned or unverified JWTs enables token forgery (RFC 8725 JWT BCP; OWASP).");

    public override IReadOnlyCollection<SyntaxKind> SyntaxKinds { get; } =
        new[] { SyntaxKind.SimpleAssignmentExpression };

    public override void Inspect(DetectionContext ctx)
    {
        var assignment = (AssignmentExpressionSyntax)ctx.Node;
        if (AssignmentTarget(assignment) is not { } target)
            return;

        string member = target.MemberName;
        if (member is not ("RequireSignedTokens" or "ValidateIssuerSigningKey"))
            return;

        Optional<object?> rhs = ctx.SemanticModel.GetConstantValue(assignment.Right);
        if (!rhs.HasValue || rhs.Value is not false)
            return;

        if (ctx.SemanticModel.GetSymbolInfo(target.LeftNode).Symbol is not IPropertySymbol prop)
            return;
        if (prop.ContainingType?.Name != "TokenValidationParameters")
            return;

        var recommendation = new Recommendation(
            "Require signed tokens and validate the issuer signing key.",
            new[]
            {
                new RecommendationOption(
                    "Set RequireSignedTokens = true and ValidateIssuerSigningKey = true; pin issuer keys or use OIDC metadata.",
                    "RFC 8725 (JWT Best Current Practices); OWASP JWT Cheat Sheet.", null,
                    QuantumVulnerability.NotVulnerable),
            });

        ctx.Report(FindingFactory.Create(
            Metadata, ctx, ctx.Node,
            displayName: $"JWT validation: {member}=false",
            quantumVulnerability: QuantumVulnerability.NotVulnerable,
            classicalWeakness: ClassicalWeakness.Broken,
            usage: UsageContext.Auth,
            confidence: DetectionConfidence.High,
            basis: Metadata.Basis,
            recommendation: recommendation,
            floor: RiskLevel.Critical,
            assetType: CryptoAssetType.Protocol,
            primitive: "jwt"));
    }
}
