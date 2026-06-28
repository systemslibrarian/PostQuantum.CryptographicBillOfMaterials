using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace PostQuantum.CryptographicBillOfMaterials.Tests;

/// <summary>Compiles a C# snippet in-memory against the running framework's reference assemblies.</summary>
internal static class TestCompilation
{
    public static Compilation Create(string source, string path = "Test.cs")
    {
        SyntaxTree tree = CSharpSyntaxTree.ParseText(source, path: path);

        string tpa = AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES") as string ?? string.Empty;
        var references = tpa
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Select(p => (MetadataReference)MetadataReference.CreateFromFile(p))
            .ToList();

        return CSharpCompilation.Create(
            "TestAsm",
            new[] { tree },
            references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
    }
}
