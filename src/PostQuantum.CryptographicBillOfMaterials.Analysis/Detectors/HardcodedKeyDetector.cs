using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Knowledge;
using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Rules;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detectors;

/// <summary>Detects hardcoded symmetric keys / IVs assigned from inline byte-array literals.</summary>
internal sealed class HardcodedKeyDetector : DetectorBase
{
    private readonly KnowledgeBase _kb;

    public HardcodedKeyDetector(KnowledgeBase kb) => _kb = kb;

    public override DetectorMetadata Metadata { get; } = new(
        "CBOM0030", "Hardcoded cryptographic key or IV", RuleCategory.HardcodedSecret, RiskLevel.Critical,
        "Hardcoded keys/IVs are recoverable from source or compiled binaries (CWE-321, CWE-798).");

    public override IReadOnlyCollection<SyntaxKind> SyntaxKinds { get; } =
        new[] { SyntaxKind.SimpleAssignmentExpression };

    public override void Inspect(DetectionContext ctx)
    {
        var assignment = (AssignmentExpressionSyntax)ctx.Node;
        if (AssignmentTarget(assignment) is not { } target)
            return;

        string member = target.MemberName;
        bool isKey = member == "Key";
        bool isIv = member == "IV";
        if (!isKey && !isIv)
            return;

        // Confirm the target is a byte[] crypto property (e.g., SymmetricAlgorithm.Key / .IV).
        if (ctx.SemanticModel.GetSymbolInfo(target.LeftNode).Symbol is not IPropertySymbol prop)
            return;
        if (prop.Type is not IArrayTypeSymbol array || array.ElementType.SpecialType != SpecialType.System_Byte)
            return;

        if (!IsConstantByteArray(assignment.Right))
            return;

        var info = new AlgorithmInfo
        {
            Name = isKey ? "Hardcoded key" : "Hardcoded IV",
            Primitive = "key-material",
            QuantumVulnerability = QuantumVulnerability.NotVulnerable,
            QuantumThreat = QuantumThreat.None,
            ClassicalWeakness = ClassicalWeakness.Broken,
            Basis = "Hardcoded keys/IVs are recoverable from source or compiled binaries (CWE-321, CWE-798).",
        };

        var recommendation = new Recommendation(
            "Never hardcode keys. Derive from a KDF or load from a secret manager / KMS.",
            new[]
            {
                new RecommendationOption(
                    "Load keys from a KMS (Azure Key Vault, AWS KMS) or derive via PBKDF2/Argon2 from a managed secret.",
                    "CWE-798; OWASP Cryptographic Storage Cheat Sheet.", null,
                    QuantumVulnerability.NotVulnerable),
            });

        ctx.Report(FindingFactory.FromAlgorithm(
            Metadata, info, ctx, ctx.Node, _kb,
            usage: UsageContext.AtRest,
            confidence: DetectionConfidence.Confirmed,
            floor: RiskLevel.Critical,
            assetType: CryptoAssetType.RelatedCryptoMaterial,
            method: DetectionMethod.Constant,
            recommendationOverride: recommendation,
            displayName: info.Name));
    }

    private static bool IsConstantByteArray(ExpressionSyntax expression)
    {
        InitializerExpressionSyntax? initializer = expression switch
        {
            ArrayCreationExpressionSyntax a => a.Initializer,
            ImplicitArrayCreationExpressionSyntax ia => ia.Initializer,
            InitializerExpressionSyntax ie => ie,
            _ => null,
        };

        if (initializer is null || initializer.Expressions.Count == 0)
            return false;

        return initializer.Expressions.All(e => e is LiteralExpressionSyntax);
    }
}
