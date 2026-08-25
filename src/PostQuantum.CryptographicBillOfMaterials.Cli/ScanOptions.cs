using System.Reflection;
using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Cli;

/// <summary>Tool-wide constants.</summary>
internal static class ToolInfo
{
    public const string Name = "dotnet-cbom";
    public const string ProfileVersion = "1.0";
    public const string CycloneDxSpecVersion = "1.6";

    /// <summary>
    /// The product version, read at runtime from this assembly's informational version (set from
    /// <c>&lt;Version&gt;</c> in Directory.Build.props, which CI overrides from the release tag). Read from
    /// the assembly rather than a hardcoded constant so the reported version always matches the installed
    /// package. SourceLink appends <c>+&lt;commit&gt;</c> build metadata, which is stripped here.
    /// </summary>
    public static string Version { get; } = ReadVersion();

    private static string ReadVersion()
    {
        string? informational = typeof(ToolInfo).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (string.IsNullOrEmpty(informational))
            return "0.0.0";

        int plus = informational.IndexOf('+');
        return plus >= 0 ? informational[..plus] : informational;
    }
}

/// <summary>Parsed options for the <c>scan</c> command.</summary>
internal sealed class ScanOptions
{
    public string Target { get; set; } = ".";
    public string OutputDir { get; set; } = "cbom-out";
    public List<string> Formats { get; set; } = new() { "cyclonedx", "summary" };

    /// <summary>Minimum level that causes a non-zero (1) exit. Null means "none" (never gate on findings).</summary>
    public RiskLevel? FailOn { get; set; } = RiskLevel.High;

    public bool AllowPartial { get; set; }
    public bool Quiet { get; set; }

    /// <summary>Explicit config path; if null, a cbom.config.json near the target is auto-discovered.</summary>
    public string? ConfigPath { get; set; }

    /// <summary>Prior CBOM to diff the current scan against.</summary>
    public string? BaselinePath { get; set; }

    /// <summary>Whether --fail-on / --format were set on the CLI (CLI overrides config).</summary>
    public bool FailOnSet { get; set; }
    public bool FormatsSet { get; set; }

    /// <summary>Policy profile name from the CLI (--profile); overrides config. Null = use config/default.</summary>
    public string? Profile { get; set; }

    /// <summary>Restrict the scan to these repository-relative files (PR-aware incremental mode).</summary>
    public List<string>? ChangedFiles { get; set; }

    /// <summary>MSBuild restore behavior: null = default, true = --restore, false = --no-restore.</summary>
    public bool? Restore { get; set; }

    /// <summary>Extra MSBuild properties (name=value) to pass to the workspace loader.</summary>
    public Dictionary<string, string> MsBuildProperties { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}
