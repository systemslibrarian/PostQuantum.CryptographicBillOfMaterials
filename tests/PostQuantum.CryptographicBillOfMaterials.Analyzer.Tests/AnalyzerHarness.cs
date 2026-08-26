using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using PostQuantum.CryptographicBillOfMaterials.Analyzer;

namespace PostQuantum.CryptographicBillOfMaterials.Analyzer.Tests;

/// <summary>
/// Runs <see cref="CryptoDiagnosticAnalyzer"/> over an in-memory compilation built against curated .NET 8
/// reference assemblies, so tests assert exactly what the IDE/build would surface — rule ids, severities,
/// and lines — without a live runtime or external analyzer-testing harness.
/// </summary>
internal static class AnalyzerHarness
{
    public static async Task<ImmutableArray<Diagnostic>> RunAsync(string source, string path = "Test.cs")
    {
        SyntaxTree tree = CSharpSyntaxTree.ParseText(source, path: path);
        var compilation = CSharpCompilation.Create(
            assemblyName: "AnalyzerTestAssembly",
            syntaxTrees: new[] { tree },
            references: Basic.Reference.Assemblies.Net80.References.All,
            options: new CSharpCompilationOptions(
                OutputKind.DynamicallyLinkedLibrary,
                nullableContextOptions: NullableContextOptions.Enable));

        CompilationWithAnalyzers withAnalyzers = compilation.WithAnalyzers(
            ImmutableArray.Create<DiagnosticAnalyzer>(new CryptoDiagnosticAnalyzer()));

        ImmutableArray<Diagnostic> all = await withAnalyzers.GetAnalyzerDiagnosticsAsync();

        // AD0001 means the analyzer itself threw. The CBOM filter below would silently discard it, so a
        // crash would otherwise sail through CI as "no findings".
        Diagnostic? crash = all.FirstOrDefault(d => d.Id == "AD0001");
        if (crash is not null)
            throw new Xunit.Sdk.XunitException("Analyzer crashed (AD0001): " + crash.GetMessage());

        return all.Where(d => d.Id.StartsWith("CBOM", StringComparison.Ordinal)).ToImmutableArray();
    }

    /// <summary>1-based start line of a diagnostic in the test source.</summary>
    public static int Line(this Diagnostic d) => d.Location.GetLineSpan().StartLinePosition.Line + 1;
}
