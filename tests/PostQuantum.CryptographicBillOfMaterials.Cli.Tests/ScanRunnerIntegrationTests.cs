using System.Text.Json;
using PostQuantum.CryptographicBillOfMaterials.Cli;
using PostQuantum.CryptographicBillOfMaterials.Reporting;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Cli.Tests;

/// <summary>
/// End-to-end tests of the scan orchestration (the artifact an auditor actually consumes): golden detection
/// on the vulnerable sample, fail-closed config, fail-closed partial scans, and deterministic parallel output.
/// </summary>
public class ScanRunnerIntegrationTests
{
    [Fact]
    public async Task VulnerableSample_HasGoldenFindings_AndValidatesAgainstSchemaAndProfile()
    {
        string outDir = NewTempDir();
        var options = new ScanOptions
        {
            Target = Path.Combine(RepoRoot(), "samples", "VulnerableDemo"),
            OutputDir = outDir,
            Formats = new() { "cyclonedx" },
            FailOn = Model.RiskLevel.High,
            Quiet = true,
        };

        int exit = await ScanRunner.RunAsync(options);
        Assert.Equal(1, exit); // High+ findings present, --fail-on high

        string cbomPath = Path.Combine(outDir, "cbom.cbom.json");
        Assert.True(File.Exists(cbomPath));

        // Validates against the OFFICIAL schema + the profile.
        byte[] bytes = await File.ReadAllBytesAsync(cbomPath);
        Assert.True(CycloneDxSchemaValidator.Validate(new MemoryStream(bytes)).IsValid);
        Assert.True(CbomValidator.Validate(new MemoryStream(bytes)).IsValid);

        // Golden detection set — a drift guard on the realistic end-to-end path.
        Dictionary<string, int> counts = RuleIdCounts(bytes);
        var expected = new Dictionary<string, int>
        {
            ["CBOM0001"] = 1, // AES (informational symmetric inventory)
            ["CBOM0002"] = 1, // RSA (Shor)
            ["CBOM0007"] = 1, // ECB
            ["CBOM0010"] = 2, // MD5 + SHA inventory
            ["CBOM0030"] = 1, // hardcoded key
            ["CBOM0040"] = 1, // SSL3
            ["CBOM0041"] = 1, // disabled cert validation
        };
        Assert.Equal(expected, counts);
    }

    [Fact]
    public async Task MalformedConfig_FailsClosed_WithExit3()
    {
        string dir = NewTempDir();
        await File.WriteAllTextAsync(Path.Combine(dir, "Crypto.cs"),
            "using System.Security.Cryptography; public class C { void M(){ var a = System.Security.Cryptography.MD5.Create(); } }");
        // Broken JSON (trailing comma + missing brace).
        await File.WriteAllTextAsync(Path.Combine(dir, "cbom.config.json"), "{ \"failOn\": \"high\", ");

        var options = new ScanOptions { Target = dir, OutputDir = NewTempDir(), Formats = new() { "cyclonedx" }, Quiet = true };
        int exit = await ScanRunner.RunAsync(options);

        Assert.Equal(3, exit); // never scans on defaults when a present config is broken
    }

    [Fact]
    public async Task EmptyDirectory_IsPartialScan_Exit2_NotClean()
    {
        string dir = NewTempDir(); // no .cs files
        var options = new ScanOptions { Target = dir, OutputDir = NewTempDir(), Formats = new() { "cyclonedx" }, Quiet = true };

        int exit = await ScanRunner.RunAsync(options);

        Assert.Equal(2, exit); // a project that produced no compilation is "not analyzed", never "clean"
    }

    [Fact]
    public async Task ParallelScan_OverManyFiles_IsDeterministic()
    {
        string dir = NewTempDir();
        for (int i = 0; i < 6; i++)
        {
            await File.WriteAllTextAsync(Path.Combine(dir, $"F{i}.cs"),
                $"using System.Security.Cryptography; public class C{i} {{ public RSA M() => RSA.Create(2048); }}");
        }

        string[] First() => BomRefsInOrder(RunToCbom(dir));
        string[] Second() => BomRefsInOrder(RunToCbom(dir));

        Assert.Equal(First(), Second());
    }

    // --- helpers ---

    private static byte[] RunToCbom(string targetDir)
    {
        string outDir = NewTempDir();
        var options = new ScanOptions
        {
            Target = targetDir, OutputDir = outDir, Formats = new() { "cyclonedx" },
            FailOn = null, Quiet = true,
        };
        ScanRunner.RunAsync(options).GetAwaiter().GetResult();
        return File.ReadAllBytes(Path.Combine(outDir, "cbom.cbom.json"));
    }

    private static string[] BomRefsInOrder(byte[] cbom)
    {
        using JsonDocument doc = JsonDocument.Parse(cbom);
        return doc.RootElement.GetProperty("components").EnumerateArray()
            .Where(c => c.TryGetProperty("type", out JsonElement t) && t.GetString() == "cryptographic-asset")
            .Select(c => c.GetProperty("bom-ref").GetString()!)
            .ToArray();
    }

    private static Dictionary<string, int> RuleIdCounts(byte[] cbom)
    {
        using JsonDocument doc = JsonDocument.Parse(cbom);
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (JsonElement c in doc.RootElement.GetProperty("components").EnumerateArray())
        {
            if (!c.TryGetProperty("properties", out JsonElement props))
                continue;
            foreach (JsonElement p in props.EnumerateArray())
            {
                if (p.GetProperty("name").GetString() == "cbom:rule:id")
                {
                    string id = p.GetProperty("value").GetString()!;
                    counts[id] = counts.GetValueOrDefault(id) + 1;
                }
            }
        }
        return counts;
    }

    private static string NewTempDir()
    {
        string dir = Path.Combine(Path.GetTempPath(), "cbom-it-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "CryptographicBillOfMaterials.slnx")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("repo root not found");
    }
}
