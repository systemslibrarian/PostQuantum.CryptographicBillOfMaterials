namespace PostQuantum.CryptographicBillOfMaterials.Cli.Tests;

/// <summary>Locates files in the repository from the test bin directory.</summary>
internal static class TestPaths
{
    /// <summary>The repository root, found by walking up to the directory holding the solution file.</summary>
    public static string RepoRoot { get; } = Find();

    public static string RepoFile(params string[] segments) =>
        Path.Combine(new[] { RepoRoot }.Concat(segments).ToArray());

    private static string Find()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "CryptographicBillOfMaterials.slnx")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new DirectoryNotFoundException(
            "Could not locate the repository root from " + AppContext.BaseDirectory);
    }
}
