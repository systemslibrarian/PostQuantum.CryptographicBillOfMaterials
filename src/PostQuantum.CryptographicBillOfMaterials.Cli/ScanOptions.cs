using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Cli;

/// <summary>Tool-wide constants.</summary>
internal static class ToolInfo
{
    public const string Name = "dotnet-cbom";
    public const string Version = "0.1.0";
    public const string ProfileVersion = "1.0";
    public const string CycloneDxSpecVersion = "1.6";
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
}
