using System.Text;
using System.Text.RegularExpressions;
using PostQuantum.CryptographicBillOfMaterials.Configuration;
using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Cli;

/// <summary>Parsing of risk-level strings used by --fail-on and config severity floors.</summary>
internal static class Levels
{
    public static RiskLevel? ParseFailOn(string value) => value.ToLowerInvariant() switch
    {
        "critical" => RiskLevel.Critical,
        "high" => RiskLevel.High,
        "medium" => RiskLevel.Medium,
        "low" => RiskLevel.Low,
        "none" => null,
        _ => RiskLevel.High,
    };

    public static RiskLevel? ParseLevel(string value) => value.ToLowerInvariant() switch
    {
        "critical" => RiskLevel.Critical,
        "high" => RiskLevel.High,
        "medium" => RiskLevel.Medium,
        "low" => RiskLevel.Low,
        "info" or "informational" => RiskLevel.Informational,
        _ => null,
    };
}

/// <summary>Minimal glob matcher supporting <c>*</c>, <c>**</c>, and <c>?</c> over forward-slash paths.</summary>
internal static class GlobMatcher
{
    public static bool IsMatch(string path, string pattern)
    {
        string p = path.Replace('\\', '/');
        string rx = "^" + Translate(pattern.Replace('\\', '/')) + "$";
        return Regex.IsMatch(p, rx, RegexOptions.IgnoreCase);
    }

    private static string Translate(string pattern)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < pattern.Length; i++)
        {
            char c = pattern[i];
            if (c == '*')
            {
                if (i + 1 < pattern.Length && pattern[i + 1] == '*')
                {
                    sb.Append(".*");
                    i++;
                    if (i + 1 < pattern.Length && pattern[i + 1] == '/')
                        i++;
                }
                else
                {
                    sb.Append("[^/]*");
                }
            }
            else if (c == '?')
            {
                sb.Append('.');
            }
            else
            {
                sb.Append(Regex.Escape(c.ToString()));
            }
        }
        return sb.ToString();
    }
}

/// <summary>Discovers and loads an optional <c>cbom.config.json</c>.</summary>
internal static class ConfigLoader
{
    public static CbomConfig? Load(string? explicitPath, string target, IList<string> diagnostics)
    {
        string? path = explicitPath;
        if (path is null)
        {
            string dir = File.Exists(target) ? Path.GetDirectoryName(target) ?? "." : target;
            string candidate = Path.Combine(dir, CbomConfig.FileName);
            if (File.Exists(candidate))
                path = candidate;
        }

        if (path is null)
            return null;

        try
        {
            CbomConfig config = CbomConfig.Load(path);
            diagnostics.Add($"Using config: {path}");
            return config;
        }
        catch (Exception ex)
        {
            diagnostics.Add($"Failed to load config '{path}': {ex.Message}");
            return null;
        }
    }
}

/// <summary>Applies config-driven rule toggles, severity floors, and path filters to findings.</summary>
internal static class ConfigApplication
{
    public static IReadOnlyList<CryptoFinding> Apply(
        IReadOnlyList<CryptoFinding> findings, CbomConfig? config, IList<string> diagnostics)
    {
        if (config is null)
            return findings;

        var kept = new List<CryptoFinding>(findings.Count);
        int disabledSuppressed = 0;
        int pathSuppressed = 0;

        foreach (CryptoFinding f in findings)
        {
            RuleConfig? rule = null;
            config.Rules?.TryGetValue(f.RuleId, out rule);

            if (rule?.Enabled == false)
            {
                disabledSuppressed++;
                continue;
            }

            if (config.Exclude is { Length: > 0 }
                && config.Exclude.Any(g => GlobMatcher.IsMatch(f.Location.FilePath, g)))
            {
                pathSuppressed++;
                continue;
            }

            if (config.Include is { Length: > 0 }
                && !config.Include.Any(g => GlobMatcher.IsMatch(f.Location.FilePath, g)))
            {
                pathSuppressed++;
                continue;
            }

            CryptoFinding outFinding = f;
            if (rule?.SeverityFloor is { } floorText
                && Levels.ParseLevel(floorText) is { } floor
                && floor > f.RiskLevel)
            {
                outFinding = f with { RiskLevel = floor };
            }

            kept.Add(outFinding);
        }

        if (disabledSuppressed > 0)
            diagnostics.Add($"config: {disabledSuppressed} finding(s) suppressed by disabled rules (recorded waiver).");
        if (pathSuppressed > 0)
            diagnostics.Add($"config: {pathSuppressed} finding(s) suppressed by include/exclude filters.");

        return kept;
    }
}
