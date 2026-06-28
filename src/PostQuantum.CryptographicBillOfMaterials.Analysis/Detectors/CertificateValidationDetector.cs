using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Rules;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detectors;

/// <summary>
/// Detects disabled TLS certificate validation: a server/remote certificate callback that
/// unconditionally returns <c>true</c>, or use of <c>DangerousAcceptAnyServerCertificateValidator</c>.
/// </summary>
internal sealed class CertificateValidationDetector : DetectorBase
{
    private static readonly HashSet<string> CallbackMembers = new(StringComparer.Ordinal)
    {
        "ServerCertificateCustomValidationCallback",
        "ServerCertificateValidationCallback",
        "RemoteCertificateValidationCallback",
    };

    public override DetectorMetadata Metadata { get; } = new(
        "CBOM0041", "TLS certificate validation disabled", RuleCategory.Tls, RiskLevel.Critical,
        "Accepting any certificate defeats TLS authentication and enables man-in-the-middle (CWE-295).");

    public override IReadOnlyCollection<SyntaxKind> SyntaxKinds { get; } =
        new[] { SyntaxKind.SimpleAssignmentExpression };

    public override void Inspect(DetectionContext ctx)
    {
        var assignment = (AssignmentExpressionSyntax)ctx.Node;
        if (AssignmentTarget(assignment) is not { } target)
            return;
        if (!CallbackMembers.Contains(target.MemberName))
            return;
        if (!AcceptsAnyCertificate(assignment.Right))
            return;

        var recommendation = new Recommendation(
            "Remove the accept-all callback and let the platform validate certificates.",
            new[]
            {
                new RecommendationOption(
                    "Delete the custom validation callback (default chain validation), or implement real chain/hostname checks and certificate pinning.",
                    "CWE-295; OWASP TLS Cheat Sheet.", null, QuantumVulnerability.NotVulnerable),
            });

        ctx.Report(FindingFactory.Create(
            Metadata, ctx, ctx.Node,
            displayName: "TLS certificate validation disabled",
            quantumVulnerability: QuantumVulnerability.NotVulnerable,
            classicalWeakness: ClassicalWeakness.Broken,
            usage: UsageContext.InTransit,
            confidence: DetectionConfidence.High,
            basis: Metadata.Basis,
            recommendation: recommendation,
            floor: RiskLevel.Critical,
            assetType: CryptoAssetType.Protocol,
            primitive: "tls"));
    }

    private static bool AcceptsAnyCertificate(ExpressionSyntax right)
    {
        switch (right)
        {
            case ParenthesizedLambdaExpressionSyntax pl:
                return LambdaBodyReturnsTrue(pl.Body);
            case SimpleLambdaExpressionSyntax sl:
                return LambdaBodyReturnsTrue(sl.Body);
            case MemberAccessExpressionSyntax m
                when m.Name.Identifier.ValueText == "DangerousAcceptAnyServerCertificateValidator":
                return true;
            default:
                return false;
        }
    }

    private static bool LambdaBodyReturnsTrue(CSharpSyntaxNode body)
    {
        if (body is LiteralExpressionSyntax literal)
            return literal.IsKind(SyntaxKind.TrueLiteralExpression);

        if (body is BlockSyntax block
            && block.Statements.Count == 1
            && block.Statements[0] is ReturnStatementSyntax ret
            && ret.Expression is LiteralExpressionSyntax retLiteral)
        {
            return retLiteral.IsKind(SyntaxKind.TrueLiteralExpression);
        }

        return false;
    }
}
