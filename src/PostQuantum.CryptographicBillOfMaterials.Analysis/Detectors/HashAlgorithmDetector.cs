using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Knowledge;
using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Rules;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detectors;

/// <summary>Detects hash-algorithm usage; flags MD5/SHA-1 as collision-broken, inventories SHA-2.</summary>
internal sealed class HashAlgorithmDetector : DetectorBase
{
    private static readonly HashSet<string> Families =
        new(StringComparer.Ordinal) { "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512" };

    private readonly KnowledgeBase _kb;

    public HashAlgorithmDetector(KnowledgeBase kb) => _kb = kb;

    public override DetectorMetadata Metadata { get; } = new(
        "CBOM0010", "Hash algorithm usage", RuleCategory.Hashing, RiskLevel.Informational,
        "Inventory of hash algorithms; MD5/SHA-1 are collision-broken (NIST SP 800-131A), SHA-2 per FIPS 180-4.");

    public override IReadOnlyCollection<SyntaxKind> SyntaxKinds { get; } =
        new[] { SyntaxKind.ObjectCreationExpression, SyntaxKind.InvocationExpression };

    public override void Inspect(DetectionContext ctx)
    {
        ITypeSymbol? type = ResolveInstantiatedType(ctx);
        if (type is null)
            return;

        string? name = AlgorithmMap.FromTypeName(FullName(type));
        if (name is null || !Families.Contains(name))
            return;

        AlgorithmInfo? info = _kb.Lookup(name);
        if (info is null)
            return;

        ctx.Report(FindingFactory.FromAlgorithm(
            Metadata, info, ctx, ctx.Node, _kb,
            usage: UsageContext.Hashing,
            confidence: DetectionConfidence.Confirmed));
    }
}
