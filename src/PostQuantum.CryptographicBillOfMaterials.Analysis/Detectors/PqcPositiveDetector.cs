using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Knowledge;
using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Rules;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detectors;

/// <summary>
/// Detects post-quantum algorithm usage (ML-KEM/ML-DSA/SLH-DSA, e.g. the .NET 10
/// <c>System.Security.Cryptography.MLKem</c> family) as a positive signal that raises readiness.
/// </summary>
internal sealed class PqcPositiveDetector : DetectorBase
{
    private readonly KnowledgeBase _kb;

    public PqcPositiveDetector(KnowledgeBase kb) => _kb = kb;

    public override DetectorMetadata Metadata { get; } = new(
        "CBOM0090", "Post-quantum algorithm in use", RuleCategory.PostQuantum, RiskLevel.Informational,
        "NIST-standardized PQC: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205).");

    public override IReadOnlyCollection<SyntaxKind> SyntaxKinds { get; } =
        new[] { SyntaxKind.ObjectCreationExpression, SyntaxKind.InvocationExpression };

    public override void Inspect(DetectionContext ctx)
    {
        ITypeSymbol? type = ResolveInstantiatedType(ctx);
        if (type is null)
            return;

        (string canonical, UsageContext usage)? match = Classify(type.Name);
        if (match is null)
            return;

        AlgorithmInfo? info = _kb.Lookup(match.Value.canonical);
        if (info is null)
            return;

        ctx.Report(FindingFactory.FromAlgorithm(
            Metadata, info, ctx, ctx.Node, _kb,
            usage: match.Value.usage,
            confidence: DetectionConfidence.Confirmed,
            titleOverride: Metadata.Title,
            displayName: match.Value.canonical));
    }

    private static (string canonical, UsageContext usage)? Classify(string typeName)
    {
        if (typeName.StartsWith("MLKem", StringComparison.Ordinal))
            return ("ML-KEM", UsageContext.KeyExchange);
        if (typeName.StartsWith("MLDsa", StringComparison.Ordinal))
            return ("ML-DSA", UsageContext.Signing);
        if (typeName.StartsWith("SlhDsa", StringComparison.Ordinal))
            return ("SLH-DSA", UsageContext.Signing);
        return null;
    }
}
