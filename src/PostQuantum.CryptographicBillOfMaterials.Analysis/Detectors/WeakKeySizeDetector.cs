using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Rules;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detectors;

/// <summary>
/// Flags a symmetric key size set via the <c>KeySize</c> property to a value with reduced post-quantum
/// margin (e.g., <c>aes.KeySize = 128</c>), which the construction-site detector cannot see because
/// .NET's <c>Aes.Create()</c> defaults to 256-bit. Handles the <c>obj.KeySize = n</c> form.
/// </summary>
internal sealed class WeakKeySizeDetector : DetectorBase
{
    private static readonly HashSet<string> SymmetricFamilies =
        new(StringComparer.Ordinal) { "AES", "3DES", "DES", "RC2" };

    public override DetectorMetadata Metadata { get; } = new(
        "CBOM0003", "Reduced-margin symmetric key size", RuleCategory.SymmetricEncryption, RiskLevel.Medium,
        "Symmetric keys <= 128 bits have reduced post-quantum margin under Grover; CNSA 2.0 selects AES-256.");

    public override IReadOnlyCollection<SyntaxKind> SyntaxKinds { get; } =
        new[] { SyntaxKind.SimpleAssignmentExpression };

    public override void Inspect(DetectionContext ctx)
    {
        var assignment = (AssignmentExpressionSyntax)ctx.Node;
        if (AssignmentTarget(assignment) is not { MemberName: "KeySize" } target)
            return;

        // Only the receiver form (obj.KeySize = n) lets us recover the concrete algorithm type.
        if (target.LeftNode is not MemberAccessExpressionSyntax member)
            return;

        Optional<object?> value = ctx.SemanticModel.GetConstantValue(assignment.Right);
        if (!value.HasValue || value.Value is not int bits || bits > 128)
            return;

        ITypeSymbol? receiverType = ctx.SemanticModel.GetTypeInfo(member.Expression).Type;
        if (receiverType is null)
            return;

        string? family = AlgorithmMap.FromTypeName(FullName(receiverType));
        if (family is null || !SymmetricFamilies.Contains(family))
            return;

        var recommendation = new Recommendation(
            "Use a 256-bit key to retain full margin against Grover.",
            new[]
            {
                new RecommendationOption(
                    $"Set {family} KeySize = 256 (AES-256-GCM).", "FIPS 197; CNSA 2.0 selects AES-256.", null,
                    QuantumVulnerability.NotVulnerable),
            });

        ctx.Report(FindingFactory.Create(
            Metadata, ctx, ctx.Node,
            displayName: $"{family}-{bits}",
            quantumVulnerability: QuantumVulnerability.ReducedMargin,
            classicalWeakness: ClassicalWeakness.None,
            usage: UsageContext.AtRest,
            confidence: DetectionConfidence.Confirmed,
            basis: Metadata.Basis,
            recommendation: recommendation,
            method: DetectionMethod.Constant,
            primitive: "block-cipher"));
    }
}
