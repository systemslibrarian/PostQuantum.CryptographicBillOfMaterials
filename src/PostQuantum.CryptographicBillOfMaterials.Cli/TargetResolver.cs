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

                // The fallback is a degraded, syntax-only scan of a target the user expected MSBuild to load
                // fully (references/dependencies unresolved) — flag it so it is never reported as a clean,
                // complete analysis (exit 2 unless --allow-partial), not silently presented as success.
                string dir = Path.GetDirectoryName(Path.GetFullPath(target)) ?? ".";
                return LooseDirectory(dir, name, degraded: true);
            }

            // .cs or any other single file.
            return LooseFiles(new[] { target }, name, Path.GetDirectoryName(target));
        }

        if (Directory.Exists(target))
        {
            // A directory holding project/solution files is a project the user expects to be analyzed WITH
            // its references; LooseDirectory resolves only the running framework's assemblies, so NuGet and
            // project references stay unresolved. That is the same incomplete analysis already flagged at
            // the .csproj fallback above — flag it here too rather than presenting it as a clean, complete
            // result. Without this, `scan .` on a real project reported "PQC Readiness 100 (no
            // quantum-relevant crypto)" and exited 0 over code full of Shor-vulnerable crypto.
            var projectFiles = Directory
                .EnumerateFiles(target, "*.*", SearchOption.AllDirectories)
                .Where(p => p.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase)
                         || p.EndsWith(".sln", StringComparison.OrdinalIgnoreCase)
                         || p.EndsWith(".slnx", StringComparison.OrdinalIgnoreCase))
                .Where(p => !HasSegment(p, "bin") && !HasSegment(p, "obj") && !HasSegment(p, ".git"))
                .ToList();

            string dirName = new DirectoryInfo(target).Name;
            if (projectFiles.Count == 0)
                return LooseDirectory(target, dirName);   // genuine loose-source scan: stays non-degraded

            diagnostics.Add(
                $"directory scan: {projectFiles.Count} project/solution file(s) under '{target}' were NOT loaded "
                + "via MSBuild (NuGet and project references unresolved; third-party crypto such as Bouncy Castle, "
                + $"JWT and cloud KMS may be missed). Scan '{Path.GetFileName(projectFiles[0])}' directly, or pass "
                + "--allow-partial to accept a partial analysis.");
            return LooseDirectory(target, dirName, degraded: true);
        }

        throw new FileNotFoundException($"Scan target not found: {target}");
    }

    private static ResolvedScan LooseDirectory(string dir, string name, bool degraded = false)
    {
        var files = Directory
            .EnumerateFiles(dir, "*.cs", SearchOption.AllDirectories)
            .Where(p => !HasSegment(p, "bin") && !HasSegment(p, "obj") && !HasSegment(p, ".git"))
            .ToList();
        return LooseFiles(files, name, dir, degraded);
    }

    private static ResolvedScan LooseFiles(IReadOnlyCollection<string> files, string name, string? dir, bool degraded = false)
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
            new LoadedProject(name, dir, compilation, Array.Empty<string>(), Ok: true, Degraded: degraded),
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
