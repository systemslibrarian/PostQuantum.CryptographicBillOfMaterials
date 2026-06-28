using Microsoft.Build.Locator;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.MSBuild;

namespace PostQuantum.CryptographicBillOfMaterials.Cli;

/// <summary>A project the loader attempted to load, with its compilation if successful.</summary>
internal sealed record LoadedProject(
    string Name,
    string? Path,
    Compilation? Compilation,
    IReadOnlyList<string> TargetFrameworks,
    bool Ok);

/// <summary>
/// Best-effort MSBuild workspace loader. Requires the .NET SDK to be present (design decision §8.3 #2).
/// Callers fall back to a no-MSBuild directory scan if this throws, so the tool always produces output.
/// </summary>
internal static class WorkspaceLoader
{
    private static bool _registered;

    private static void EnsureRegistered()
    {
        if (_registered)
            return;
        if (!MSBuildLocator.IsRegistered)
            MSBuildLocator.RegisterDefaults();
        _registered = true;
    }

    public static async Task<IReadOnlyList<LoadedProject>> LoadAsync(string slnOrProjPath, IList<string> diagnostics)
    {
        EnsureRegistered();

        using MSBuildWorkspace workspace = MSBuildWorkspace.Create();
        workspace.WorkspaceFailed += (_, e) =>
        {
            if (e.Diagnostic.Kind == WorkspaceDiagnosticKind.Failure)
                diagnostics.Add(e.Diagnostic.Message);
        };

        var projects = new List<Project>();
        string ext = System.IO.Path.GetExtension(slnOrProjPath).ToLowerInvariant();
        if (ext is ".sln" or ".slnx")
        {
            Solution solution = await workspace.OpenSolutionAsync(slnOrProjPath);
            projects.AddRange(solution.Projects);
        }
        else
        {
            projects.Add(await workspace.OpenProjectAsync(slnOrProjPath));
        }

        var result = new List<LoadedProject>();
        foreach (Project project in projects)
        {
            Compilation? compilation = null;
            bool ok = false;
            try
            {
                compilation = await project.GetCompilationAsync();
                ok = compilation is not null;
            }
            catch (Exception ex)
            {
                diagnostics.Add($"{project.Name}: {ex.Message}");
            }

            var frameworks = new List<string>();
            if (project.ParseOptions is not null && !string.IsNullOrEmpty(project.Name))
            {
                // Best-effort: MSBuildWorkspace yields one Project per TFM, named "Proj(net8.0)".
                int open = project.Name.IndexOf('(');
                if (open >= 0 && project.Name.EndsWith(")", StringComparison.Ordinal))
                    frameworks.Add(project.Name.Substring(open + 1, project.Name.Length - open - 2));
            }

            result.Add(new LoadedProject(project.Name, project.FilePath, compilation, frameworks, ok));
        }

        return result;
    }
}
