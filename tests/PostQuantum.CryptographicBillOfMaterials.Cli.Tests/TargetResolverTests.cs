using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Cli.Tests;

/// <summary>
/// A directory target and an explicit project target run the same reference-free analysis when MSBuild is
/// unavailable, but only the project target used to say so. The directory path reported "PQC Readiness 100
/// (no quantum-relevant crypto)" and exit 0 over a project full of Shor-vulnerable crypto — a fail-open in a
/// risk-scoring tool, on the shipped default (`action.yml` defaults target to ".").
/// </summary>
public class TargetResolverTests
{
    private static string NewTempDir()
    {
        string dir = Path.Combine(Path.GetTempPath(), "cbom-tr-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    [Theory]
    [InlineData("App.csproj")]
    [InlineData("App.sln")]
    [InlineData("App.slnx")]
    public async Task DirectoryTarget_ContainingAProjectFile_IsDegraded(string projectFileName)
    {
        string dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, projectFileName), "<Project />");
            File.WriteAllText(Path.Combine(dir, "Code.cs"), "public class C { }");

            var diagnostics = new List<string>();
            ResolvedScan scan = await TargetResolver.ResolveAsync(dir, diagnostics);

            Assert.All(scan.Projects, p => Assert.True(p.Degraded));
            Assert.Contains(diagnostics, d => d.Contains("directory scan:", StringComparison.Ordinal));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task DirectoryTarget_LooseSourcesOnly_IsNotDegraded()
    {
        // A directory of loose .cs files is exactly what a directory scan is for — nothing is missing, so
        // it must stay a clean exit. This is the half that must NOT regress into a blanket warning.
        string dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "Code.cs"), "public class C { }");

            var diagnostics = new List<string>();
            ResolvedScan scan = await TargetResolver.ResolveAsync(dir, diagnostics);

            Assert.All(scan.Projects, p => Assert.False(p.Degraded));
            Assert.DoesNotContain(diagnostics, d => d.Contains("directory scan:", StringComparison.Ordinal));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task DirectoryTarget_IgnoresProjectFilesUnderBinAndObj()
    {
        // Build output must not turn an honest loose scan into a partial one.
        string dir = NewTempDir();
        try
        {
            Directory.CreateDirectory(Path.Combine(dir, "obj"));
            File.WriteAllText(Path.Combine(dir, "obj", "Stale.csproj"), "<Project />");
            File.WriteAllText(Path.Combine(dir, "Code.cs"), "public class C { }");

            var diagnostics = new List<string>();
            ResolvedScan scan = await TargetResolver.ResolveAsync(dir, diagnostics);

            Assert.All(scan.Projects, p => Assert.False(p.Degraded));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
