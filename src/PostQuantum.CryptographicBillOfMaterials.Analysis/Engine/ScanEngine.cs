using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Engine;

/// <summary>
/// Runs detectors over a Roslyn <see cref="Compilation"/>. Detectors are indexed by syntax kind so each
/// node is dispatched only to interested detectors. A detector that throws is isolated and does not abort
/// the scan (fail-closed: one broken rule never silences the rest).
/// </summary>
public sealed class ScanEngine
{
    private readonly DetectorRegistry _registry;

    public ScanEngine(DetectorRegistry registry) => _registry = registry;

    /// <summary>Analyze a single compilation and return de-duplicated findings.</summary>
    public IReadOnlyList<CryptoFinding> AnalyzeCompilation(Compilation compilation)
    {
        var findings = new List<CryptoFinding>();

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

        foreach (SyntaxTree tree in compilation.SyntaxTrees)
        {
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
                    detector.Inspect(ctx);
                }
            }
        }

        return Deduplicate(findings);
    }

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
