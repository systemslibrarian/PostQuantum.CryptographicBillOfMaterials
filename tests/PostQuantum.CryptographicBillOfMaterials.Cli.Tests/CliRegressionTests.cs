using PostQuantum.CryptographicBillOfMaterials.Configuration;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Cli.Tests;

/// <summary>
/// Regressions reported in gem2.md: the shipped example config must actually load (config loading is
/// fail-closed, so a broken example would fatally crash the tool), and `validate` must not silently pass
/// when given mutually exclusive scope flags.
/// </summary>
public class CliRegressionTests
{
    [Fact]
    public void ShippedExampleConfig_Loads()
    {
        // gem2.md #1: the example used string-keyed pseudo-comments ("// ...": "...") inside the strongly
        // typed rules dictionary, which fails to deserialize. Real // comments (which the loader skips) fix it.
        string path = Path.Combine(RepoRoot(), "samples", "cbom.config.example.json");

        CbomConfig config = CbomConfig.Load(path);

        Assert.NotNull(config.Rules);
        Assert.Equal("critical", config.Rules!["CBOM0002"].SeverityFloor);
        Assert.Equal("critical", config.Rules["CBOM0010"].Algorithms!["MD5"].SeverityFloor);
        Assert.False(config.Rules["CBOM0050"].Enabled);
        Assert.NotNull(config.DataSensitivityHints);
        Assert.Equal(25, config.DataSensitivityHints!["src/Payments/**"].DataLifetimeYears);
    }

    [Fact]
    public void Validate_BothScopeFlags_IsUsageError_NotFalsePass()
    {
        // gem2.md #2: --schema-only + --profile-only made both validation branches false, validating nothing
        // and reporting VALID. Mutually exclusive flags must now be a usage error (exit 3).
        int exit = Program.ValidateCommand(new[] { "anything.cbom.json", "--schema-only", "--profile-only" });

        Assert.Equal(3, exit);
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "CryptographicBillOfMaterials.slnx")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("repo root not found");
    }
}
