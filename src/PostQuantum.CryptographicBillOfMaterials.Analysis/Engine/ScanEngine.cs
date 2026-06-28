using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Engine;

/// <summary>A non-fatal problem encountered during a scan (e.g., a detector threw on one node).</summary>
public sealed record ScanDiagnostic(string Source, string Message);

/// <summary>Findings plus any non-fatal diagnostics produced while scanning a compilation.</summary>
public sealed record CompilationScanResult(
    IReadOnlyList<CryptoFinding> Findings,
    IReadOnlyList<ScanDiagnostic> Diagnostics);

/// <summary>
/// Runs detectors over a Roslyn <see cref="Compilation"/>. Detectors are indexed by syntax kind so each
/// node is dispatched only to interested detectors. A detector that throws is isolated and recorded as a
/// diagnostic, never aborting the scan (fail-closed: one broken rule must not silence the rest).
/// </summary>
public sealed class ScanEngine
{
    private readonly DetectorRegistry _registry;

    public ScanEngine(DetectorRegistry registry) => _registry = registry;

    /// <summary>Analyze a compilation, returning de-duplicated findings and diagnostics.</summary>
    public CompilationScanResult Analyze(Compilation compilation)
    {
        var findings = new List<CryptoFinding>();
        var diagnostics = new List<ScanDiagnostic>();

        var byKind = new Dictionary<SyntaxKind, List<ICryptoDetector>>();
        foreach (ICryptoDetector detector in _registry.Detectors)
        {
            foreach (SyntaxKind kind in detector.SyntaxKinds)
            {
                if (!byKind.TryGetValue(kind, out List<ICryptoDetector>? list))
                    byKind[kind] = list = new List<ICryptoDetector>();
                list.Add(detector);
            }
        }

        // Trees are independent (stateless detectors, per-tree semantic models), so analyze them in
        // parallel for throughput on large solutions, then merge results IN TREE ORDER so output stays
        // deterministic regardless of scheduling. Degrades gracefully to sequential for a single tree.
        SyntaxTree[] trees = compilation.SyntaxTrees.ToArray();
        var perTree = new (List<CryptoFinding> Findings, List<ScanDiagnostic> Diagnostics)[trees.Length];

        if (trees.Length <= 1)
        {
            for (int i = 0; i < trees.Length; i++)
                perTree[i] = AnalyzeTree(compilation, trees[i], byKind);
        }
        else
        {
            Parallel.For(0, trees.Length, i => perTree[i] = AnalyzeTree(compilation, trees[i], byKind));
        }

        foreach (var (treeFindings, treeDiagnostics) in perTree)
        {
            findings.AddRange(treeFindings);
            diagnostics.AddRange(treeDiagnostics);
        }

        return new CompilationScanResult(Deduplicate(findings), diagnostics);
    }

    private static (List<CryptoFinding>, List<ScanDiagnostic>) AnalyzeTree(
        Compilation compilation, SyntaxTree tree, Dictionary<SyntaxKind, List<ICryptoDetector>> byKind)
    {
        var findings = new List<CryptoFinding>();
        var diagnostics = new List<ScanDiagnostic>();
        SemanticModel model = compilation.GetSemanticModel(tree);
        string filePath = tree.FilePath;
        SyntaxNode root = tree.GetRoot();

        foreach (SyntaxNode node in root.DescendantNodesAndSelf())
        {
            if (!byKind.TryGetValue(node.Kind(), out List<ICryptoDetector>? detectors))
                continue;

            foreach (ICryptoDetector detector in detectors)
            {
                var ctx = new DetectionContext(node, model, filePath, findings.Add);
                try
                {
                    detector.Inspect(ctx);
                }
                catch (Exception ex)
                {
                    // Isolate a misbehaving detector; record rather than crash the scan.
                    diagnostics.Add(new ScanDiagnostic(detector.Metadata.RuleId, ex.Message));
                }
            }
        }

        return (findings, diagnostics);
    }

    /// <summary>Convenience overload returning only findings (used by tests and simple callers).</summary>
    public IReadOnlyList<CryptoFinding> AnalyzeCompilation(Compilation compilation) =>
        Analyze(compilation).Findings;

    private static IReadOnlyList<CryptoFinding> Deduplicate(List<CryptoFinding> findings)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var result = new List<CryptoFinding>(findings.Count);
        foreach (CryptoFinding finding in findings)
        {
            string key = finding.BomRef
                ?? $"{finding.RuleId}:{finding.Location.FilePath}:{finding.Location.Line}:{finding.AlgorithmName}";
            if (seen.Add(key))
                result.Add(finding);
        }
        return result;
    }
}
