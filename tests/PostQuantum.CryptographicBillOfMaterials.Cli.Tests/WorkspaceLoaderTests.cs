using Microsoft.Build.Locator;
using Microsoft.CodeAnalysis;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Cli.Tests;

/// <summary>
/// Guards the MSBuild project-loading path, which had no coverage at all and consequently shipped broken:
/// a net8.0-only tool on an SDK-10-only machine located zero MSBuild instances, and even where the Locator
/// succeeded the workspace had no C# language service, so every .sln/.csproj scan silently fell back to a
/// reference-free syntax scan. Third-party crypto reachable only through a PackageReference — Bouncy Castle,
/// JWT, cloud KMS — was therefore absent from the CBOM while the analyzer flagged it.
/// </summary>
public class WorkspaceLoaderTests
{
    /// <summary>
    /// Whether this host can drive MSBuild at all. The Locator cannot enumerate an SDK whose major version
    /// exceeds the running runtime's, so a net8.0 test host on a machine carrying only SDK 10 legitimately
    /// finds nothing. CI installs both bands, so the resolving branch below is the one that runs there.
    /// </summary>
    private static bool MSBuildAvailable => MSBuildLocator.QueryVisualStudioInstances().Any();

    [Fact]
    public async Task LoadAsync_RealCsproj_ResolvesReferences_OrSaysItCouldNot()
    {
        string csproj = TestPaths.RepoFile(
            "src/PostQuantum.CryptographicBillOfMaterials.Analysis",
            "PostQuantum.CryptographicBillOfMaterials.Analysis.csproj");

        var diagnostics = new List<string>();

        if (!MSBuildAvailable)
        {
            // The honest outcome on a host with no compatible SDK: the loader throws and the caller degrades.
            // Asserting this rather than skipping keeps the "silently reports success" regression covered on
            // every host, not only the ones that can load projects.
            ResolvedScan degraded = await TargetResolver.ResolveAsync(csproj, diagnostics);
            Assert.Contains(diagnostics, d => d.Contains("MSBuild load failed", StringComparison.Ordinal));
            Assert.All(degraded.Projects, p => Assert.True(p.Degraded));
            return;
        }

        IReadOnlyList<LoadedProject> loaded = await WorkspaceLoader.LoadAsync(csproj, diagnostics);

        LoadedProject project = Assert.Single(loaded, p => p.Ok);
        Assert.False(project.Degraded);
        Assert.NotEmpty(project.TargetFrameworks);
        Assert.NotNull(project.Compilation);

        // The point of loading through MSBuild at all: references resolve. A syntax-only fallback compiles
        // the same source but binds none of this.
        Compilation compilation = project.Compilation!;
        Assert.NotNull(compilation.GetTypeByMetadataName("Microsoft.CodeAnalysis.Compilation"));
        Assert.NotNull(compilation.GetTypeByMetadataName(
            "PostQuantum.CryptographicBillOfMaterials.Analysis.Engine.ScanEngine"));
    }
}
