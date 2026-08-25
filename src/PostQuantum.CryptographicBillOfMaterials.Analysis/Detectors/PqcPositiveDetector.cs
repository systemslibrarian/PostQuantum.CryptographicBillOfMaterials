using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
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
        (string canonical, UsageContext usage)? match = Resolve(ctx);
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

    private static (string canonical, UsageContext usage)? Resolve(DetectionContext ctx)
    {
        // Preferred: the resolved symbol (works when the PQC types are in the reference set, e.g. a .NET 10+
        // target with the BCL crypto assembly resolved). Require the System.Security.Cryptography namespace so
        // a user-defined type whose name merely starts with MLKem/MLDsa/SlhDsa (e.g. App.MLKemWidget) is not
        // mistaken for in-box PQC. A resolved symbol in another namespace is a real user type — never PQC here.
        ITypeSymbol? type = ResolveInstantiatedType(ctx);
        if (type is not null)
            return InCryptographyNamespace(type) ? Classify(type.Name) : null;

        // Fallback: the in-box PQC types (System.Security.Cryptography.MLKem/MLDsa/SlhDsa) won't resolve when
        // scanning on an SDK older than the code's target (no MSBuild, or an older BCL reference set). Credit
        // the post-quantum usage anyway by matching the syntactic type name — adopting PQC shouldn't go
        // unrecorded just because the scan host predates the API. We can't verify the namespace here, so match
        // only the exact factory entry-point type names (the in-box PQC types have no public constructors and
        // are always used as MLKem/MLDsa/SlhDsa.GenerateKey/Import...). Positive signal only; mirrors CBOM0081.
        string? syntacticName = SyntacticTypeName(ctx.Node);
        return syntacticName is not null && IsExactPqcEntryType(syntacticName) ? Classify(syntacticName) : null;
    }

    private static bool InCryptographyNamespace(ITypeSymbol type) =>
        type.ContainingNamespace?.ToDisplayString() == "System.Security.Cryptography";

    private static bool IsExactPqcEntryType(string name) =>
        name is "MLKem" or "MLDsa" or "SlhDsa";

    /// <summary>The type name being constructed or whose static member is being invoked, taken from syntax
    /// (not symbols) so it works even when the type does not resolve.</summary>
    private static string? SyntacticTypeName(SyntaxNode node) => node switch
    {
        ObjectCreationExpressionSyntax oce => TypeName(oce.Type),
        InvocationExpressionSyntax { Expression: MemberAccessExpressionSyntax ma } => ReceiverName(ma.Expression),
        _ => null,
    };

    private static string? TypeName(TypeSyntax type) => type switch
    {
        IdentifierNameSyntax id => id.Identifier.ValueText,
        QualifiedNameSyntax q => q.Right.Identifier.ValueText,
        _ => null,
    };

    private static string? ReceiverName(ExpressionSyntax expr) => expr switch
    {
        IdentifierNameSyntax id => id.Identifier.ValueText,              // MLKem.GenerateKey(...)
        MemberAccessExpressionSyntax ma => ma.Name.Identifier.ValueText, // System.Security.Cryptography.MLKem.GenerateKey(...)
        _ => null,
    };

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
