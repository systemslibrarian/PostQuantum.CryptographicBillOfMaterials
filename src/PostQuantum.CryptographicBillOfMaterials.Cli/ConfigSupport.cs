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
                    i++; // consume the second '*'
                    if (i + 1 < pattern.Length && pattern[i + 1] == '/')
                    {
                        // '**/' = zero or more WHOLE path segments. Must be boundary-anchored so that
                        // '**/Crypto.cs' matches 'src/Crypto.cs' and 'Crypto.cs' but NOT 'src/NotCrypto.cs'.
                        sb.Append("(?:.*/)?");
                        i++; // consume the '/'
                    }
                    else
                    {
                        // Trailing or un-anchored '**' (e.g. 'src/**') crosses segments freely.
                        sb.Append(".*");
                    }
                }
                else
                {
                    sb.Append("[^/]*"); // single '*' stays within one segment
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

/// <summary>
/// A config that exists but cannot be parsed/validated. This is fatal by design: silently reverting to
/// defaults could drop a severity floor or waiver an auditor relied on (fail-closed, TDD §0 misuse-resistance).
/// </summary>
internal sealed class ConfigException : Exception
{
    public ConfigException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>Discovers and loads an optional <c>cbom.config.json</c>.</summary>
internal static class ConfigLoader
{
    public static CbomConfig? Load(string? explicitPath, string target, IList<string> diagnostics)
    {
        string? path = explicitPath;
        bool wasExplicit = explicitPath is not null;
        if (path is null)
        {
            string dir = File.Exists(target) ? Path.GetDirectoryName(target) ?? "." : target;
            string candidate = Path.Combine(dir, CbomConfig.FileName);
            if (File.Exists(candidate))
                path = candidate;
        }

        if (path is null)
            return null;

        // An explicitly requested config that does not exist is a usage error, not "no config."
        if (wasExplicit && !File.Exists(path))
            throw new ConfigException($"config not found: {path}");

        try
        {
            CbomConfig config = CbomConfig.Load(path);
            diagnostics.Add($"Using config: {path}");
            return config;
        }
        catch (ConfigException)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Fail-closed: a present-but-broken config aborts the scan rather than scanning on defaults.
            throw new ConfigException($"failed to load config '{path}': {ex.Message}", ex);
        }
    }
}

/// <summary>Findings after config/policy is applied, plus a transparent record of what was applied.</summary>
internal sealed record ConfigApplicationResult(
    IReadOnlyList<CryptoFinding> Findings, AppliedConfigSummary Summary);

/// <summary>
/// Applies, in a fixed and auditable order: rule/algorithm toggles and waivers, include/exclude filters,
/// raise-only severity floors, policy-profile floors, and data-sensitivity (HNDL) elevation. Every action
/// is counted into an <see cref="AppliedConfigSummary"/> recorded in the CBOM — nothing is dropped silently.
/// </summary>
internal static class ConfigApplication
{
    public static ConfigApplicationResult Apply(
        IReadOnlyList<CryptoFinding> findings, CbomConfig? config, PolicyProfile profile, IList<string> diagnostics)
    {
        var kept = new List<CryptoFinding>(findings.Count);
        int disabledSuppressed = 0, pathSuppressed = 0, elevatedByData = 0, elevatedByPolicy = 0;
        var waivers = new Dictionary<string, WaiverRecord>(StringComparer.Ordinal);
        DateOnly today = DateOnly.FromDateTime(DateTime.UtcNow);

        foreach (CryptoFinding raw in findings)
        {
            CryptoFinding f = raw with { PolicyProfile = profile.Name };

            RuleConfig? rule = null;
            config?.Rules?.TryGetValue(f.RuleId, out rule);
            RuleConfig? algRule = ResolveAlgorithmRule(rule, f.AlgorithmName);
            RuleConfig? effective = algRule ?? rule;

            // --- Waivers / disable ---
            bool disabled = (algRule?.Enabled ?? rule?.Enabled) == false;
            if (disabled)
            {
                bool justified = !string.IsNullOrWhiteSpace(effective?.WaiverJustification);
                bool expired = TryParseDate(effective?.WaiverExpiry, out DateOnly exp) && exp < today;

                // Misuse-resistance (TDD §0): a waiver may only suppress a finding when it is JUSTIFIED and
                // not expired. An unjustified disable cannot quietly remove findings — it is retained and
                // flagged, so a typo'd or rubber-stamped config can never produce a misleading "clean" BOM.
                bool suppress = profile.WaiversSuppress && !expired && justified;
                RecordWaiver(waivers, f.RuleId, effective, suppress, expired);

                if (suppress)
                {
                    disabledSuppressed++;
                    continue;
                }

                if (!justified)
                    diagnostics.Add($"config: rule {f.RuleId} disabled without a waiverJustification; finding RETAINED "
                        + "(a waiver must be justified to suppress).");
                else if (expired)
                    diagnostics.Add($"config: waiver for {f.RuleId} expired {effective?.WaiverExpiry}; finding re-activated.");

                f = f with
                {
                    // Mark Waived only for a valid (justified, unexpired) annotate-only waiver (audit profile).
                    Status = justified && !expired ? RemediationStatus.Waived : f.Status,
                    WaiverJustification = effective?.WaiverJustification,
                    WaiverApprover = effective?.WaiverApprover,
                    WaiverExpiry = effective?.WaiverExpiry,
                };
            }

            // --- Path filters ---
            if (config?.Exclude is { Length: > 0 }
                && config.Exclude.Any(g => GlobMatcher.IsMatch(f.Location.FilePath, g)))
            {
                pathSuppressed++;
                continue;
            }
            if (config?.Include is { Length: > 0 }
                && !config.Include.Any(g => GlobMatcher.IsMatch(f.Location.FilePath, g)))
            {
                pathSuppressed++;
                continue;
            }

            // --- Raise-only severity floors (per-algorithm wins over per-rule) ---
            string? floorText = effective?.SeverityFloor ?? rule?.SeverityFloor;
            if (floorText is not null && Levels.ParseLevel(floorText) is { } floor && floor > f.RiskLevel)
                f = f with { RiskLevel = floor };

            // --- Policy-profile floors (raise-only; never lowers a finding) ---
            RiskLevel? policyFloor = f.QuantumVulnerability switch
            {
                QuantumVulnerability.Vulnerable => profile.QuantumVulnerableFloor,
                QuantumVulnerability.ReducedMargin => profile.ReducedMarginFloor,
                _ => null,
            };
            if (policyFloor is { } pf && pf > f.RiskLevel)
            {
                f = f with { RiskLevel = pf };
                elevatedByPolicy++;
            }

            // --- Data sensitivity: long-lived HNDL exposure -> Critical ---
            if (IsLongLivedQuantumExposure(f, config) && f.RiskLevel < RiskLevel.Critical)
            {
                f = f with { RiskLevel = RiskLevel.Critical };
                elevatedByData++;
            }

            kept.Add(f);
        }

        if (disabledSuppressed > 0)
            diagnostics.Add($"config: {disabledSuppressed} finding(s) suppressed by disabled rules (recorded waiver).");
        if (pathSuppressed > 0)
            diagnostics.Add($"config: {pathSuppressed} finding(s) suppressed by include/exclude filters.");
        if (elevatedByPolicy > 0)
            diagnostics.Add($"policy[{profile.Name}]: {elevatedByPolicy} finding(s) elevated by profile floor.");
        if (elevatedByData > 0)
            diagnostics.Add($"config: {elevatedByData} finding(s) elevated to Critical by data-sensitivity (long-lived HNDL exposure).");

        var summary = new AppliedConfigSummary
        {
            SuppressedByDisabledRule = disabledSuppressed,
            SuppressedByPathFilter = pathSuppressed,
            ElevatedByDataSensitivity = elevatedByData,
            ElevatedByPolicyProfile = elevatedByPolicy,
            Waivers = waivers.Values.ToList(),
            ConfiguredRuleIds = config?.Rules?.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList()
                ?? (IReadOnlyList<string>)Array.Empty<string>(),
        };
        return new ConfigApplicationResult(kept, summary);
    }

    private static RuleConfig? ResolveAlgorithmRule(RuleConfig? rule, string algorithmName)
    {
        if (rule?.Algorithms is null)
            return null;
        // Exact match first, then a case-insensitive contains (so "AES-128" matches a key "AES-128").
        foreach ((string key, RuleConfig rc) in rule.Algorithms)
        {
            if (string.Equals(key, algorithmName, StringComparison.OrdinalIgnoreCase)
                || algorithmName.Contains(key, StringComparison.OrdinalIgnoreCase))
            {
                return rc;
            }
        }
        return null;
    }

    private static void RecordWaiver(
        Dictionary<string, WaiverRecord> waivers, string ruleId, RuleConfig? rc, bool suppress, bool expired)
    {
        if (waivers.TryGetValue(ruleId, out WaiverRecord? existing))
            waivers[ruleId] = existing with { Count = existing.Count + 1 };
        else
            waivers[ruleId] = new WaiverRecord(
                ruleId, rc?.WaiverJustification, rc?.WaiverApprover, rc?.WaiverExpiry, suppress, expired, 1);
    }

    private static bool TryParseDate(string? value, out DateOnly date) =>
        DateOnly.TryParse(value, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.None, out date);

    private static bool IsLongLivedQuantumExposure(CryptoFinding f, CbomConfig? config)
    {
        if (config?.DataSensitivityHints is null || config.DataSensitivityHints.Count == 0)
            return false;
        if (f.QuantumVulnerability != QuantumVulnerability.Vulnerable)
            return false;
        if (f.UsageContext is not (UsageContext.AtRest or UsageContext.InTransit or UsageContext.KeyExchange))
            return false;

        foreach ((string key, DataSensitivityHint hint) in config.DataSensitivityHints)
        {
            if ((hint.DataLifetimeYears ?? 0) < CbomConfig.LongLivedYearsThreshold)
                continue;

            bool match = key.StartsWith("ns:", StringComparison.OrdinalIgnoreCase)
                ? f.Location.Namespace is { } ns && GlobMatcher.IsMatch(ns, key[3..])
                : GlobMatcher.IsMatch(f.Location.FilePath, key);
            if (match)
                return true;
        }
        return false;
    }
}
