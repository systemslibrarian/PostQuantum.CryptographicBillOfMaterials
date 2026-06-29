using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;

/// <summary>
/// Bounded, intra-procedural forward dataflow for cryptographic key material. It answers one question
/// precisely: does weak randomness (<c>System.Random</c> / <c>Random.Shared</c>) flow — through local
/// assignments and buffer fills — into a key/IV/nonce sink within the same method?
/// </summary>
/// <remarks>
/// This replaces identifier-name guessing with real def-use tracking, so it catches
/// <c>rnd.NextBytes(buf); aes.Key = buf;</c> (no "key"-named variable) and avoids false positives like
/// <c>var keyboard = new Random();</c> (no flow to a sink). It is deliberately scoped to a single method
/// body and a linear pass — sound enough for the common case, honest about not being inter-procedural
/// (cross-method flow remains a documented gap).
/// </remarks>
public static class CryptoTaintAnalysis
{
    private static readonly HashSet<string> RandomOutputMethods = new(StringComparer.Ordinal)
    {
        "Next", "NextDouble", "NextInt64", "NextSingle", "NextBytes",
    };

    /// <summary>Member names that are unambiguously key material: a weak-random value here is Broken.</summary>
    private static readonly HashSet<string> KeyMaterialMembers = new(StringComparer.Ordinal)
    {
        "Key", "IV", "Nonce",
    };

    /// <summary>Type names whose constructor consumes a signing/encryption key as its first argument.</summary>
    private static readonly HashSet<string> KeySinkTypes = new(StringComparer.Ordinal)
    {
        "SymmetricSecurityKey", "HMACSHA256", "HMACSHA384", "HMACSHA512", "HMACSHA1", "HMACMD5",
    };

    private static readonly string[] SensitiveNames =
    {
        "key", "secret", "token", "password", "passwd", "pwd", "iv", "nonce", "salt",
        "otp", "apikey", "credential", "session", "signing", "privatekey",
    };

    /// <summary>
    /// True when weak randomness originating at <paramref name="randomSource"/> reaches key/IV/nonce material
    /// in its enclosing method. <paramref name="randomSource"/> is the <c>new Random()</c> creation or the
    /// <c>Random.Shared</c> access that a detector matched.
    /// </summary>
    public static bool WeakRandomReachesKeyMaterial(SemanticModel model, SyntaxNode randomSource)
    {
        SyntaxNode? scope = EnclosingBody(randomSource);
        if (scope is null)
            return false;

        var comparer = SymbolEqualityComparer.Default;
        var randomInstances = new HashSet<ISymbol>(comparer); // locals that hold a Random instance
        var tainted = new HashSet<ISymbol>(comparer);          // locals/buffers holding weak-random output

        // Seed: if the matched source is stored in a local, that local is a random instance.
        if (LocalAssignedFrom(model, randomSource) is { } seed)
            randomInstances.Add(seed);

        bool IsRandomReceiver(ExpressionSyntax expr)
        {
            expr = Unwrap(expr);
            if (expr == randomSource)
                return true;
            if (IsWeakRandomCreation(model, expr))
                return true;
            ISymbol? s = model.GetSymbolInfo(expr).Symbol;
            return s is not null && randomInstances.Contains(s);
        }

        // A random output call: rnd.Next*()/NextBytes(...). Returns the call + (for NextBytes) the buffer arg.
        bool IsRandomOutputCall(ExpressionSyntax expr, out ArgumentSyntax? bufferArg)
        {
            bufferArg = null;
            if (Unwrap(expr) is not InvocationExpressionSyntax inv
                || inv.Expression is not MemberAccessExpressionSyntax ma
                || !RandomOutputMethods.Contains(ma.Name.Identifier.ValueText)
                || !IsRandomReceiver(ma.Expression))
                return false;
            if (ma.Name.Identifier.ValueText == "NextBytes" && inv.ArgumentList.Arguments.Count > 0)
                bufferArg = inv.ArgumentList.Arguments[0];
            return true;
        }

        bool ExprIsTainted(ExpressionSyntax? expr)
        {
            if (expr is null)
                return false;
            if (IsRandomOutputCall(expr, out _))
                return true;
            foreach (IdentifierNameSyntax id in expr.DescendantNodesAndSelf().OfType<IdentifierNameSyntax>())
                if (model.GetSymbolInfo(id).Symbol is { } s && tainted.Contains(s))
                    return true;
            return false;
        }

        // Single forward pass in document order: propagate taint, then test sinks.
        foreach (SyntaxNode node in scope.DescendantNodes())
        {
            switch (node)
            {
                case InvocationExpressionSyntax inv
                    when IsRandomOutputCall(inv, out ArgumentSyntax? buf) && buf is not null:
                    if (SymbolOf(model, buf.Expression) is { } bufSym)
                        tainted.Add(bufSym);
                    break;

                case VariableDeclaratorSyntax v when v.Initializer is { } init:
                    PropagateAssign(model, v.Initializer.Value, model.GetDeclaredSymbol(v), randomInstances, tainted, IsRandomReceiver, ExprIsTainted);
                    break;

                case AssignmentExpressionSyntax asg when asg.IsKind(SyntaxKind.SimpleAssignmentExpression):
                    if (IsKeyMaterialSink(asg) && ExprIsTainted(asg.Right))
                        return true;
                    if (IsSensitiveFieldOrProperty(model, asg.Left) && ExprIsTainted(asg.Right))
                        return true;
                    PropagateAssign(model, asg.Right, SymbolOf(model, asg.Left), randomInstances, tainted, IsRandomReceiver, ExprIsTainted);
                    break;

                case ObjectCreationExpressionSyntax oce when IsKeySinkConstruction(oce)
                    && oce.ArgumentList is { } args && args.Arguments.Any(a => ExprIsTainted(a.Expression)):
                    return true;

                case ReturnStatementSyntax ret when ExprIsTainted(ret.Expression)
                    && EnclosingMemberNameIsSensitive(randomSource):
                    return true;

                case ArrowExpressionClauseSyntax arrow when ExprIsTainted(arrow.Expression)
                    && EnclosingMemberNameIsSensitive(randomSource):
                    return true;
            }
        }

        return false;
    }

    private static void PropagateAssign(
        SemanticModel model, ExpressionSyntax rhs, ISymbol? lhsSymbol,
        HashSet<ISymbol> randomInstances, HashSet<ISymbol> tainted,
        Func<ExpressionSyntax, bool> isRandomReceiver, Func<ExpressionSyntax?, bool> exprIsTainted)
    {
        if (lhsSymbol is null)
            return;
        ExpressionSyntax value = Unwrap(rhs);
        if (IsWeakRandomCreation(model, value) || (model.GetSymbolInfo(value).Symbol is { } s && randomInstances.Contains(s)))
            randomInstances.Add(lhsSymbol);
        else if (exprIsTainted(value))
            tainted.Add(lhsSymbol);
    }

    private static bool IsKeyMaterialSink(AssignmentExpressionSyntax asg) =>
        asg.Left is MemberAccessExpressionSyntax m && KeyMaterialMembers.Contains(m.Name.Identifier.ValueText)
        || asg.Left is IdentifierNameSyntax id && KeyMaterialMembers.Contains(id.Identifier.ValueText);

    private static bool IsSensitiveFieldOrProperty(SemanticModel model, ExpressionSyntax left)
    {
        ISymbol? symbol = model.GetSymbolInfo(left).Symbol;
        return symbol is IFieldSymbol or IPropertySymbol && NameIsSensitive(symbol.Name);
    }

    private static bool IsKeySinkConstruction(ObjectCreationExpressionSyntax oce) =>
        SimpleTypeName(oce.Type) is { } name && KeySinkTypes.Contains(name);

    private static bool IsWeakRandomCreation(SemanticModel model, ExpressionSyntax expr)
    {
        expr = Unwrap(expr);
        if (expr is ObjectCreationExpressionSyntax oce)
        {
            ITypeSymbol? t = model.GetSymbolInfo(oce).Symbol is IMethodSymbol ctor
                ? ctor.ContainingType
                : model.GetTypeInfo(oce).Type;
            return t is not null && FullName(t) == "System.Random";
        }
        // Random.Shared
        if (expr is MemberAccessExpressionSyntax ma && ma.Name.Identifier.ValueText == "Shared")
        {
            ITypeSymbol? t = model.GetTypeInfo(ma).Type;
            return t is not null && FullName(t) == "System.Random";
        }
        return false;
    }

    private static ISymbol? LocalAssignedFrom(SemanticModel model, SyntaxNode source)
    {
        SyntaxNode? parent = source is ExpressionSyntax es ? Unwrap(es).Parent : source.Parent;
        return parent switch
        {
            EqualsValueClauseSyntax { Parent: VariableDeclaratorSyntax v } => model.GetDeclaredSymbol(v),
            AssignmentExpressionSyntax { Left: { } left } => SymbolOf(model, left),
            _ => null,
        };
    }

    private static bool EnclosingMemberNameIsSensitive(SyntaxNode node) =>
        node.FirstAncestorOrSelf<MemberDeclarationSyntax>() switch
        {
            MethodDeclarationSyntax m => NameIsSensitive(m.Identifier.ValueText),
            PropertyDeclarationSyntax p => NameIsSensitive(p.Identifier.ValueText),
            _ => node.FirstAncestorOrSelf<LocalFunctionStatementSyntax>() is { } lf && NameIsSensitive(lf.Identifier.ValueText),
        };

    private static SyntaxNode? EnclosingBody(SyntaxNode node)
    {
        for (SyntaxNode? n = node; n is not null; n = n.Parent)
        {
            if (n is MethodDeclarationSyntax or ConstructorDeclarationSyntax or LocalFunctionStatementSyntax
                or AccessorDeclarationSyntax or PropertyDeclarationSyntax
                or ParenthesizedLambdaExpressionSyntax or SimpleLambdaExpressionSyntax)
                return n;
        }
        return null;
    }

    private static ISymbol? SymbolOf(SemanticModel model, ExpressionSyntax expr) =>
        model.GetSymbolInfo(expr).Symbol;

    private static ExpressionSyntax Unwrap(ExpressionSyntax expr) => expr switch
    {
        ParenthesizedExpressionSyntax p => Unwrap(p.Expression),
        CastExpressionSyntax c => Unwrap(c.Expression),
        _ => expr,
    };

    private static bool NameIsSensitive(string name)
    {
        foreach (string token in SensitiveNames)
            if (name.Contains(token, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }

    private static string FullName(ITypeSymbol type) =>
        type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat).Replace("global::", string.Empty);

    private static string? SimpleTypeName(SyntaxNode? type) => type switch
    {
        IdentifierNameSyntax id => id.Identifier.ValueText,
        QualifiedNameSyntax q => q.Right.Identifier.ValueText,
        GenericNameSyntax g => g.Identifier.ValueText,
        _ => null,
    };
}
