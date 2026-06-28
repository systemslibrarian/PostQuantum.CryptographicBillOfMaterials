using PostQuantum.CryptographicBillOfMaterials.Analysis.Engine;

namespace PostQuantum.CryptographicBillOfMaterials.Cli;

/// <summary>The set of projects to scan, plus a display name for the solution/target.</summary>
internal sealed record ResolvedScan(string SolutionName, IReadOnlyList<LoadedProject> Projects);

/// <summary>
/// Resolves a scan target (.sln/.slnx/.csproj, directory, or .cs file) into loadable projects.
/// Solutions/projects use the MSBuild loader with a no-MSBuild directory fallback; directories and loose
/// files are parsed directly against framework references.
/// </summary>
internal static class TargetResolver
{
    public static async Task<ResolvedScan> ResolveAsync(
        string target, IList<string> diagnostics,
        IReadOnlyDictionary<string, string>? msbuildProperties = null, bool? restore = null)
    {
        if (File.Exists(target))
        {
            string ext = Path.GetExtension(target).ToLowerInvariant();
            string name = Path.GetFileNameWithoutExtension(target);

            if (ext is ".sln" or ".slnx" or ".csproj")
            {
                if (restore == true)
                    RunRestore(target, diagnostics);

                try
                {
                    IReadOnlyList<LoadedProject> loaded =
                        await WorkspaceLoader.LoadAsync(target, diagnostics, msbuildProperties);
                    if (loaded.Any(p => p.Ok))
                        return new ResolvedScan(name, loaded);

                    diagnostics.Add("MSBuild load produced no usable projects; falling back to directory scan.");
                }
                catch (Exception ex)
                {
                    diagnostics.Add($"MSBuild load failed ({ex.Message}); falling back to directory scan.");
                }

                string dir = Path.GetDirectoryName(Path.GetFullPath(target)) ?? ".";
                return LooseDirectory(dir, name);
            }

            // .cs or any other single file.
            return LooseFiles(new[] { target }, name, Path.GetDirectoryName(target));
        }

        if (Directory.Exists(target))
            return LooseDirectory(target, new DirectoryInfo(target).Name);

        throw new FileNotFoundException($"Scan target not found: {target}");
    }

    private static ResolvedScan LooseDirectory(string dir, string name)
    {
        var files = Directory
            .EnumerateFiles(dir, "*.cs", SearchOption.AllDirectories)
            .Where(p => !HasSegment(p, "bin") && !HasSegment(p, "obj") && !HasSegment(p, ".git"))
            .ToList();
        return LooseFiles(files, name, dir);
    }

    private static ResolvedScan LooseFiles(IReadOnlyCollection<string> files, string name, string? dir)
    {
        if (files.Count == 0)
        {
            return new ResolvedScan(name, new[]
            {
                new LoadedProject(name, dir, Compilation: null, Array.Empty<string>(), Ok: false),
            });
        }

        var compilation = CompilationFactory.FromFiles(name, files);
        return new ResolvedScan(name, new[]
        {
            new LoadedProject(name, dir, compilation, Array.Empty<string>(), Ok: true),
        });
    }

    private static bool HasSegment(string path, string segment) =>
        path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            .Any(s => string.Equals(s, segment, StringComparison.OrdinalIgnoreCase));

    private static void RunRestore(string target, IList<string> diagnostics)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("dotnet", $"restore \"{target}\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            using System.Diagnostics.Process? p = System.Diagnostics.Process.Start(psi);
            if (p is null)
            {
                diagnostics.Add("restore: could not start 'dotnet restore'.");
                return;
            }
            p.WaitForExit();
            diagnostics.Add(p.ExitCode == 0
                ? "restore: completed."
                : $"restore: 'dotnet restore' exited {p.ExitCode} (continuing; load may be partial).");
        }
        catch (Exception ex)
        {
            diagnostics.Add($"restore: failed to run 'dotnet restore' ({ex.Message}).");
        }
    }
}
