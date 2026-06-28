using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Engine;

/// <summary>
/// Builds a Roslyn <see cref="Compilation"/> from loose C# source files, referencing the running
/// framework's assemblies. This enables a no-MSBuild "directory scan" path so the tool runs even when a
/// project cannot be loaded via MSBuild (BCL crypto symbols still resolve). Project-reference and NuGet
/// resolution require the MSBuild workspace path instead.
/// </summary>
public static class CompilationFactory
{
    /// <summary>Build a compilation from a set of source file paths.</summary>
    public static Compilation FromFiles(string assemblyName, IEnumerable<string> filePaths)
    {
        var trees = filePaths.Select(path =>
            CSharpSyntaxTree.ParseText(File.ReadAllText(path), path: path));
        return Create(assemblyName, trees);
    }

    /// <summary>Build a compilation from a single in-memory source string.</summary>
    public static Compilation FromSource(string source, string path = "Source.cs") =>
        Create("LooseScan", new[] { CSharpSyntaxTree.ParseText(source, path: path) });

    private static Compilation Create(string assemblyName, IEnumerable<SyntaxTree> trees)
    {
        string tpa = AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES") as string ?? string.Empty;
        var references = tpa
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Select(p => (MetadataReference)MetadataReference.CreateFromFile(p));

        return CSharpCompilation.Create(
            assemblyName,
            trees,
            references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
    }
}
