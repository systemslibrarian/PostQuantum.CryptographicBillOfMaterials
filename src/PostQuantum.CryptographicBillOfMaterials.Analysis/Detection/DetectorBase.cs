using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using PostQuantum.CryptographicBillOfMaterials.Rules;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;

/// <summary>Base class with shared symbol-resolution helpers for detectors.</summary>
public abstract class DetectorBase : ICryptoDetector
{
    public abstract DetectorMetadata Metadata { get; }
    public abstract IReadOnlyCollection<SyntaxKind> SyntaxKinds { get; }
    public abstract void Inspect(DetectionContext context);

    /// <summary>
    /// Resolve the cryptographic type produced/used at this node. Handles <c>new T(...)</c> and static
    /// factory/helper calls (<c>T.Create(...)</c>, <c>T.HashData(...)</c>). Instance method calls return
    /// null so we don't double-count usage of an already-detected object.
    /// </summary>
    protected static ITypeSymbol? ResolveInstantiatedType(DetectionContext ctx)
    {
        switch (ctx.Node)
        {
            case ObjectCreationExpressionSyntax oce:
                if (ctx.SemanticModel.GetSymbolInfo(oce).Symbol is IMethodSymbol ctor)
                    return ctor.ContainingType;
                return ctx.SemanticModel.GetTypeInfo(oce).Type;

            case InvocationExpressionSyntax ie:
                if (ctx.SemanticModel.GetSymbolInfo(ie).Symbol is IMethodSymbol m && m.IsStatic)
                    return m.ContainingType;
                return null;

            default:
                return null;
        }
    }

    /// <summary>Fully-qualified type name without the <c>global::</c> prefix.</summary>
    protected static string FullName(ITypeSymbol type) =>
        type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat).Replace("global::", string.Empty);

    /// <summary>
    /// Resolves the target of an assignment to (the left node, member name), handling BOTH
    /// <c>obj.Member = ...</c> (member access) and <c>new T { Member = ... }</c> (object-initializer
    /// identifier) forms. Returns null for indexers and other unsupported left-hand sides.
    /// </summary>
    protected static (SyntaxNode LeftNode, string MemberName)? AssignmentTarget(AssignmentExpressionSyntax assignment) =>
        assignment.Left switch
        {
            MemberAccessExpressionSyntax m => (assignment.Left, m.Name.Identifier.ValueText),
            IdentifierNameSyntax id => (assignment.Left, id.Identifier.ValueText),
            _ => null,
        };

    /// <summary>First integer constant argument to the call/constructor at this node, if any (e.g., RSA key size).</summary>
    protected static int? FirstIntArgument(DetectionContext ctx)
    {
        ArgumentListSyntax? args = ctx.Node switch
        {
            ObjectCreationExpressionSyntax oce => oce.ArgumentList,
            InvocationExpressionSyntax ie => ie.ArgumentList,
            _ => null,
        };
        if (args is null)
            return null;

        foreach (ArgumentSyntax arg in args.Arguments)
        {
            Optional<object?> cv = ctx.SemanticModel.GetConstantValue(arg.Expression);
            if (cv.HasValue && cv.Value is int i)
                return i;
        }
        return null;
    }
}
