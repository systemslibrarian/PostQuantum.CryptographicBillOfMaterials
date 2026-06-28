using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Knowledge;
using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Rules;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detectors;

/// <summary>Detects quantum-vulnerable public-key algorithms (RSA, ECDSA, ECDH, DSA) broken by Shor.</summary>
internal sealed class AsymmetricAlgorithmDetector : DetectorBase
{
    private static readonly HashSet<string> Families = new(StringComparer.Ordinal) { "RSA", "ECDSA", "ECDH", "DSA" };
    private readonly KnowledgeBase _kb;

    public AsymmetricAlgorithmDetector(KnowledgeBase kb) => _kb = kb;

    public override DetectorMetadata Metadata { get; } = new(
        "CBOM0002", "Quantum-vulnerable public-key algorithm", RuleCategory.AsymmetricEncryption, RiskLevel.High,
        "RSA/ECC/DH are broken by Shor's algorithm (NIST IR 8547 DRAFT; CNSA 2.0).");

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
        ClassicalWeakness? classicalOverride = null;
        if (name is "RSA" or "DSA" && keySize is int k)
        {
            if (k < 1024)
                classicalOverride = ClassicalWeakness.Broken;
            else if (k < 2048)
                classicalOverride = ClassicalWeakness.Deprecated;
        }

        UsageContext usage = name switch
        {
            "RSA" or "ECDH" => UsageContext.KeyExchange,
            "ECDSA" or "DSA" => UsageContext.Signing,
            _ => UsageContext.Unknown,
        };

        string display = keySize is int ks ? $"{name}-{ks}" : name;

        ctx.Report(FindingFactory.FromAlgorithm(
            Metadata, info, ctx, ctx.Node, _kb,
            usage: usage,
            confidence: DetectionConfidence.Confirmed,
            keySize: keySize,
            classicalOverride: classicalOverride,
            displayName: display));
    }
}
