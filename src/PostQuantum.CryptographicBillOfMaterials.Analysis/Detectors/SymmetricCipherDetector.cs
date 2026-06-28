using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Knowledge;
using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Rules;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detectors;

/// <summary>Detects symmetric cipher usage (AES, 3DES, DES, RC2) and flags deprecated/reduced-margin ciphers.</summary>
internal sealed class SymmetricCipherDetector : DetectorBase
{
    private static readonly HashSet<string> Families = new(StringComparer.Ordinal) { "AES", "3DES", "DES", "RC2" };
    private readonly KnowledgeBase _kb;

    public SymmetricCipherDetector(KnowledgeBase kb) => _kb = kb;

    public override DetectorMetadata Metadata { get; } = new(
        "CBOM0001", "Symmetric cipher usage", RuleCategory.SymmetricEncryption, RiskLevel.Informational,
        "Inventory of symmetric ciphers; weak/deprecated ciphers per NIST SP 800-131A, strong ciphers per FIPS 197.");

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

        int? keySize = FirstIntArgument(ctx);
        QuantumVulnerability? quantumOverride = null;
        Recommendation? recommendation = null;
        string display = name;

        // .NET's Aes defaults to 256-bit keys. Only flag a reduced quantum margin when AES-128 is explicit.
        if (name == "AES" && keySize is 128)
        {
            quantumOverride = QuantumVulnerability.ReducedMargin;
            display = "AES-128";
            recommendation = new Recommendation(
                "Prefer AES-256 to retain full margin against Grover.",
                new[]
                {
                    new RecommendationOption(
                        "Use AES-256-GCM.", "FIPS 197; CNSA 2.0 selects AES-256.", null,
                        QuantumVulnerability.NotVulnerable),
                });
        }

        ctx.Report(FindingFactory.FromAlgorithm(
            Metadata, info, ctx, ctx.Node, _kb,
            usage: UsageContext.AtRest,
            confidence: DetectionConfidence.Confirmed,
            keySize: keySize,
            quantumOverride: quantumOverride,
            recommendationOverride: recommendation,
            displayName: display));
    }
}
