using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Engine;

/// <summary>Post-processing applied to findings after a scan (path normalization, etc.).</summary>
public static class FindingPostProcessor
{
    /// <summary>
    /// Rewrite finding locations to forward-slash paths relative to <paramref name="baseDirectory"/> and
    /// recompute the bom-ref from the relative path, so bom-refs are stable across machines and check-outs
    /// (essential for baseline diffing). Paths outside the base directory keep their absolute form.
    /// </summary>
    public static IReadOnlyList<CryptoFinding> Relativize(
        IReadOnlyList<CryptoFinding> findings, string baseDirectory)
    {
        var result = new List<CryptoFinding>(findings.Count);
        foreach (CryptoFinding f in findings)
        {
            string relative = ToRelative(f.Location.FilePath, baseDirectory);
            SourceLocation location = f.Location with { FilePath = relative };
            result.Add(f with
            {
                Location = location,
                BomRef = BomRef.Create(f.AlgorithmName, location, f.RuleId),
            });
        }
        return result;
    }

    private static string ToRelative(string path, string baseDirectory)
    {
        if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(baseDirectory))
            return path;
        try
        {
            string relative = Path.GetRelativePath(baseDirectory, path);
            return relative.Replace('\\', '/');
        }
        catch
        {
            return path;
        }
    }
}
