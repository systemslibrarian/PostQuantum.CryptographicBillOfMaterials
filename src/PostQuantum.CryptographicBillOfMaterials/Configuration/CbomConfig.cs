using System.Text.Json;
using System.Text.Json.Serialization;

namespace PostQuantum.CryptographicBillOfMaterials.Configuration;

/// <summary>Per-rule configuration. A floor can only RAISE severity, never lower it (misuse-resistant).</summary>
public sealed class RuleConfig
{
    public bool? Enabled { get; set; }
    public string? SeverityFloor { get; set; }
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
    public Dictionary<string, RuleConfig>? Rules { get; set; }

    /// <summary>Path-glob → sensitivity hint (e.g., "src/Payments/**": { dataLifetimeYears: 25 }).</summary>
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
