using Microsoft.CodeAnalysis;
using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;

/// <summary>Per-node context passed to a detector: the node, its semantic model, and a report sink.</summary>
public sealed class DetectionContext
{
    private readonly Action<CryptoFinding> _report;

    public DetectionContext(SyntaxNode node, SemanticModel semanticModel, string filePath, Action<CryptoFinding> report)
    {
        Node = node;
        SemanticModel = semanticModel;
        FilePath = filePath;
        _report = report;
    }

    public SyntaxNode Node { get; }
    public SemanticModel SemanticModel { get; }
    public string FilePath { get; }

    /// <summary>Report a finding. The engine collects and de-duplicates these.</summary>
    public void Report(CryptoFinding finding) => _report(finding);

    /// <summary>1-based source location of a node within the current file, with enclosing namespace/symbol.</summary>
    public SourceLocation LocationOf(SyntaxNode node)
    {
        FileLinePositionSpan span = node.GetLocation().GetLineSpan();
        (string? ns, string? symbol) = EnclosingContext(node);
        return new SourceLocation(
            string.IsNullOrEmpty(FilePath) ? span.Path : FilePath,
            span.StartLinePosition.Line + 1,
            span.StartLinePosition.Character + 1,
            ns,
            symbol);
    }

    private (string? Namespace, string? Symbol) EnclosingContext(SyntaxNode node)
    {
        try
        {
            ISymbol? symbol = SemanticModel.GetEnclosingSymbol(node.SpanStart);
            if (symbol is null)
                return (null, null);

            string? ns = symbol.ContainingNamespace is { IsGlobalNamespace: false } n
                ? n.ToDisplayString()
                : null;

            // Walk to the enclosing named type for a stable, readable symbol path.
            ISymbol cursor = symbol;
            while (cursor is not null and not INamedTypeSymbol && cursor.ContainingSymbol is not null and not INamespaceSymbol)
                cursor = cursor.ContainingSymbol;

            string? symbolPath = symbol.Kind is SymbolKind.Method or SymbolKind.Property or SymbolKind.Field or SymbolKind.NamedType
                ? symbol.ToDisplayString(SymbolDisplayFormat.CSharpErrorMessageFormat)
                : (cursor as INamedTypeSymbol)?.ToDisplayString();

            return (ns, symbolPath);
        }
        catch
        {
            return (null, null);
        }
    }
}
