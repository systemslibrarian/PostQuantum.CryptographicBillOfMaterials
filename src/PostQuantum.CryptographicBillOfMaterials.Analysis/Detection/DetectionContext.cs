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

    /// <summary>1-based source location of a node within the current file.</summary>
    public SourceLocation LocationOf(SyntaxNode node)
    {
        FileLinePositionSpan span = node.GetLocation().GetLineSpan();
        return new SourceLocation(
            string.IsNullOrEmpty(FilePath) ? span.Path : FilePath,
            span.StartLinePosition.Line + 1,
            span.StartLinePosition.Character + 1);
    }
}
