using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Knowledge;
using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Rules;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detectors;

/// <summary>Detects use of ECB cipher mode (no semantic security).</summary>
internal sealed class EcbModeDetector : DetectorBase
{
    private readonly KnowledgeBase _kb;

    public EcbModeDetector(KnowledgeBase kb) => _kb = kb;

    public override DetectorMetadata Metadata { get; } = new(
        "CBOM0007", "ECB mode used", RuleCategory.SymmetricEncryption, RiskLevel.High,
        "ECB reveals plaintext patterns and is not semantically secure (NIST SP 800-38A).");

    public override IReadOnlyCollection<SyntaxKind> SyntaxKinds { get; } =
        new[] { SyntaxKind.SimpleMemberAccessExpression };

    private static readonly AlgorithmInfo EcbInfo = new()
    {
        Name = "ECB",
        Primitive = "block-cipher-mode",
        QuantumVulnerability = QuantumVulnerability.NotVulnerable,
        QuantumThreat = QuantumThreat.None,
        ClassicalWeakness = ClassicalWeakness.Broken,
        Basis = "ECB reveals plaintext patterns and is not semantically secure (NIST SP 800-38A).",
    };

    public override void Inspect(DetectionContext ctx)
    {
        var member = (MemberAccessExpressionSyntax)ctx.Node;
        if (member.Name.Identifier.ValueText != "ECB")
            return;

        if (ctx.SemanticModel.GetSymbolInfo(member).Symbol is not IFieldSymbol field)
            return;
        if (field.ContainingType?.Name != "CipherMode")
            return;

        var recommendation = new Recommendation(
            "Use an authenticated mode such as AES-GCM instead of ECB.",
            new[]
            {
                new RecommendationOption(
                    "AES-256-GCM (authenticated encryption).", "NIST SP 800-38D.", null,
                    QuantumVulnerability.NotVulnerable),
            });

        ctx.Report(FindingFactory.FromAlgorithm(
            Metadata, EcbInfo, ctx, ctx.Node, _kb,
            usage: UsageContext.AtRest,
            confidence: DetectionConfidence.Confirmed,
            floor: RiskLevel.High,
            recommendationOverride: recommendation,
            displayName: "ECB mode"));
    }
}
