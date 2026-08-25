using System.Text;
using Xunit;
using Xunit.Abstractions;

namespace PostQuantum.CryptographicBillOfMaterials.Tests.Benchmark;

/// <summary>
/// CI gate + evidence generator for detector accuracy. Running the test suite refreshes
/// <c>benchmark/ACCURACY.md</c> and fails if the tool regresses on the labeled corpus (a missed expected
/// finding, or a spurious one). The corpus is the contract: changing detection behavior must update it.
/// </summary>
public sealed class AccuracyBenchmarkTests
{
    private readonly ITestOutputHelper _output;

    public AccuracyBenchmarkTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void Corpus_HasNoFalseNegatives_NoFalsePositives_AndRefreshesReport()
    {
        AccuracyBenchmark.Results results = AccuracyBenchmark.Run();
        string report = AccuracyBenchmark.RenderReport(results);

        // Refresh the published evidence next to the corpus, best-effort (skip silently if read-only CI).
        TryWriteReport(report);

        _output.WriteLine(report);

        Assert.True(results.FileCount >= 10, $"Corpus too small ({results.FileCount} files)");

        string fn = string.Join("; ", results.Files
            .Where(f => f.FalseNegatives.Count > 0)
            .Select(f => $"{f.File}: missed {string.Join(",", f.FalseNegatives)}"));
        Assert.True(results.TotalFalseNegatives == 0, "False negatives (missed expected findings): " + fn);

        string fp = string.Join("; ", results.Files
            .Where(f => f.FalsePositives.Count > 0)
            .Select(f => $"{f.File}: spurious {string.Join(",", f.FalsePositives)}"));
        Assert.True(results.TotalFalsePositives == 0, "False positives (spurious findings): " + fp);

        string sev = string.Join("; ", results.Files
            .Where(f => f.SeverityMismatches.Count > 0)
            .Select(f => $"{f.File}: {string.Join(",", f.SeverityMismatches)}"));
        Assert.True(results.TotalSeverityMismatches == 0, "Severity-pin mismatches: " + sev);
    }

    private static void TryWriteReport(string report)
    {
        try
        {
            File.WriteAllText(
                Path.Combine(AccuracyBenchmark.BenchmarkDir, "ACCURACY.md"), report, new UTF8Encoding(false));
        }
        catch (IOException) { /* best-effort: a read-only checkout must not fail the gate */ }
        catch (UnauthorizedAccessException) { /* ditto */ }
    }
}
