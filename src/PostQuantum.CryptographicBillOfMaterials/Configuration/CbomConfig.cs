using System.Text.Json;
using System.Text.Json.Serialization;

namespace PostQuantum.CryptographicBillOfMaterials.Configuration;

/// <summary>Per-rule configuration. A floor can only RAISE severity, never lower it (misuse-resistant).</summary>
public sealed class RuleConfig
{
    public bool? Enabled { get; set; }
    public string? SeverityFloor { get; set; }

    /// <summary>Per-algorithm overrides keyed by algorithm/display name (e.g., "MD5", "AES-128"), so a rule
    /// can be tuned for one algorithm without disabling the whole rule id. Raise-only, like the rule floor.</summary>
    public Dictionary<string, RuleConfig>? Algorithms { get; set; }

    /// <summary>Why this rule/finding is waived. Required for a disabled rule to count as an auditable waiver.</summary>
    public string? WaiverJustification { get; set; }

    /// <summary>Who approved the waiver.</summary>
    public string? WaiverApprover { get; set; }

    /// <summary>ISO date (yyyy-MM-dd) the waiver expires; an expired waiver no longer suppresses.</summary>
    public string? WaiverExpiry { get; set; }
}

/// <summary>
/// Optional <c>cbom.config.json</c> settings (TDD §6.7). CLI options take precedence over config; config
/// takes precedence over built-in defaults. Disabling a rule is an explicit, recorded waiver — never a
/// silent drop (the scan reports how many findings were suppressed).
/// </summary>
/// <summary>
/// A data-sensitivity hint for a set of paths (glob keys), used to weight harvest-now-decrypt-later risk.
/// Long-lived confidentiality protected by quantum-vulnerable crypto is the highest-urgency PQC work.
/// </summary>
public sealed class DataSensitivityHint
{
    public int? DataLifetimeYears { get; set; }
    public string? DataClass { get; set; }
}

public sealed class CbomConfig
{
    public string[]? Include { get; set; }
    public string[]? Exclude { get; set; }
    public string? FailOn { get; set; }
    public string[]? Formats { get; set; }

    /// <summary>Built-in risk posture: general | federal | cnsa2 | audit | developer. CLI --profile overrides.</summary>
    public string? Profile { get; set; }

    public Dictionary<string, RuleConfig>? Rules { get; set; }

    /// <summary>
    /// Path-glob → sensitivity hint (e.g., "src/Payments/**": { dataLifetimeYears: 25 }). Glob keys match the
    /// finding's repository-relative path. Prefix a key with <c>ns:</c> to match the enclosing namespace
    /// instead of the path (e.g., "ns:Contoso.Payments.*").
    /// </summary>
    public Dictionary<string, DataSensitivityHint>? DataSensitivityHints { get; set; }

    /// <summary>Data lifetime (years) at/above which long-lived data elevates HNDL risk to Critical.</summary>
    public const int LongLivedYearsThreshold = 10;

    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() },
    };

    /// <summary>Load a config from a file path.</summary>
    public static CbomConfig Load(string path)
    {
        string json = File.ReadAllText(path);
        return JsonSerializer.Deserialize<CbomConfig>(json, Options)
            ?? throw new InvalidOperationException($"Failed to parse config: {path}");
    }

    /// <summary>The conventional config file name discovered next to a scan target.</summary>
    public const string FileName = "cbom.config.json";
}
