using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Engine;

/// <summary>Post-processing applied to findings after a scan (path normalization, etc.).</summary>
public static class FindingPostProcessor
{
    /// <summary>
    /// Rewrite finding locations to forward-slash paths relative to <paramref name="baseDirectory"/> and
    /// assign stable bom-refs. Bom-refs are keyed on (rule, algorithm, relative file, occurrence) — NOT the
    /// source line — so they survive unrelated edits that shift line numbers, which is essential for baseline
    /// diffing. The occurrence ordinal (assigned here in document order) disambiguates multiple findings of
    /// the same rule+algorithm in one file and guarantees uniqueness. Paths outside the base directory keep
    /// their absolute form.
    /// </summary>
    public static IReadOnlyList<CryptoFinding> Relativize(
        IReadOnlyList<CryptoFinding> findings, string baseDirectory)
    {
        var result = new List<CryptoFinding>(findings.Count);
        var occurrences = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (CryptoFinding f in findings)
        {
            string relative = ToRelative(f.Location.FilePath, baseDirectory);
            SourceLocation location = f.Location with { FilePath = relative };

            string key = $"{f.RuleId}|{f.AlgorithmName}|{relative}";
            int occurrence = occurrences.TryGetValue(key, out int n) ? n : 0;
            occurrences[key] = occurrence + 1;

            result.Add(f with
            {
                Location = location,
                BomRef = BomRef.Create(f.AlgorithmName, relative, f.RuleId, occurrence),
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
