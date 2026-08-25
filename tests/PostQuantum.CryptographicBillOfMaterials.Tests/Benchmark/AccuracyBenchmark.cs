using System.Text;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Engine;
using PostQuantum.CryptographicBillOfMaterials.Knowledge;
using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Tests.Benchmark;

/// <summary>
/// Runs the real detector pipeline over the labeled corpus in <c>/benchmark/corpus</c> and measures
/// precision/recall against independently-authored ground truth. Each corpus file declares the findings it
/// should produce (<c>// EXPECT: CBOM0002, ...</c>) or that it must produce none (<c>// EXPECT-CLEAN</c>),
/// so the corpus measures both detection (recall) and over-flagging / false positives (precision). This is
/// what turns "we think it's accurate" into reproducible, auditable evidence.
/// </summary>
internal static class AccuracyBenchmark
{
    public sealed record RuleScore(string RuleId, int TruePositives, int FalsePositives, int FalseNegatives)
    {
        public double Precision => TruePositives + FalsePositives == 0 ? 1.0 : (double)TruePositives / (TruePositives + FalsePositives);
        public double Recall => TruePositives + FalseNegatives == 0 ? 1.0 : (double)TruePositives / (TruePositives + FalseNegatives);
        public double F1 => Precision + Recall == 0 ? 0 : 2 * Precision * Recall / (Precision + Recall);
    }

    public sealed record FileResult(string File, IReadOnlyList<string> Expected, IReadOnlyList<string> Actual,
        IReadOnlyList<string> FalsePositives, IReadOnlyList<string> FalseNegatives,
        IReadOnlyList<string> SeverityMismatches);

    public sealed record Results(
        IReadOnlyList<FileResult> Files,
        IReadOnlyList<RuleScore> PerRule,
        int TotalTruePositives,
        int TotalFalsePositives,
        int TotalFalseNegatives)
    {
        public int FileCount => Files.Count;
        public int TotalSeverityMismatches => Files.Sum(f => f.SeverityMismatches.Count);
        public double Precision => TotalTruePositives + TotalFalsePositives == 0 ? 1.0 : (double)TotalTruePositives / (TotalTruePositives + TotalFalsePositives);
        public double Recall => TotalTruePositives + TotalFalseNegatives == 0 ? 1.0 : (double)TotalTruePositives / (TotalTruePositives + TotalFalseNegatives);
        public double F1 => Precision + Recall == 0 ? 0 : 2 * Precision * Recall / (Precision + Recall);
    }

    private static readonly ScanEngine Engine = new(DetectorRegistry.CreateDefault(KnowledgeBase.LoadDefault()));

    /// <summary>The <c>/benchmark</c> directory (parent of the corpus), located by walking up from the test
    /// output directory. Used both to read the corpus and to write the report to the same place.</summary>
    public static string BenchmarkDir => Directory.GetParent(LocateCorpus())!.FullName;

    public static Results Run()
    {
        string corpusDir = LocateCorpus();
        var fileResults = new List<FileResult>();
        var tpByRule = new Dictionary<string, int>(StringComparer.Ordinal);
        var fpByRule = new Dictionary<string, int>(StringComparer.Ordinal);
        var fnByRule = new Dictionary<string, int>(StringComparer.Ordinal);

        foreach (string path in Directory.EnumerateFiles(corpusDir, "*.cs").OrderBy(p => p, StringComparer.Ordinal))
        {
            string source = File.ReadAllText(path);
            List<Expectation> expectations = ParseExpectations(source);
            List<string> expected = expectations.Select(e => e.RuleId).ToList();

            IReadOnlyList<CryptoFinding> findings = Engine.AnalyzeCompilation(
                TestCompilation.Create(source, Path.GetFileName(path)));
            List<string> actual = findings.Select(f => f.RuleId).OrderBy(x => x, StringComparer.Ordinal).ToList();

            // Severity check: for each expectation that pins a level (CBOM0050@High), at least one detected
            // finding of that rule must carry that level. This is what proves context discrimination
            // (benign Random=Low vs key-material Random=High; AES-256=Informational vs DES=High).
            var severityMismatches = new List<string>();
            foreach (Expectation e in expectations.Where(e => e.Level is not null))
            {
                bool ok = findings.Any(f =>
                    f.RuleId == e.RuleId && f.RiskLevel.ToString().Equals(e.Level, StringComparison.OrdinalIgnoreCase));
                if (!ok)
                {
                    string got = string.Join("/", findings.Where(f => f.RuleId == e.RuleId)
                        .Select(f => f.RiskLevel.ToString()).DefaultIfEmpty("none"));
                    severityMismatches.Add($"{e.RuleId} expected {e.Level}, got {got}");
                }
            }

            // File-granularity multiset comparison by rule id.
            var expectedCounts = CountById(expected);
            var actualCounts = CountById(actual);
            var fps = new List<string>();
            var fns = new List<string>();

            foreach (string rule in expectedCounts.Keys.Union(actualCounts.Keys))
            {
                int exp = expectedCounts.GetValueOrDefault(rule);
                int act = actualCounts.GetValueOrDefault(rule);
                int tp = Math.Min(exp, act);
                int fp = Math.Max(0, act - exp);
                int fn = Math.Max(0, exp - act);

                Add(tpByRule, rule, tp);
                Add(fpByRule, rule, fp);
                Add(fnByRule, rule, fn);
                for (int i = 0; i < fp; i++) fps.Add(rule);
                for (int i = 0; i < fn; i++) fns.Add(rule);
            }

            fileResults.Add(new FileResult(Path.GetFileName(path), expected, actual, fps, fns, severityMismatches));
        }

        var perRule = tpByRule.Keys.Union(fpByRule.Keys).Union(fnByRule.Keys)
            .OrderBy(r => r, StringComparer.Ordinal)
            .Select(r => new RuleScore(r, tpByRule.GetValueOrDefault(r), fpByRule.GetValueOrDefault(r), fnByRule.GetValueOrDefault(r)))
            .ToList();

        return new Results(
            fileResults, perRule,
            tpByRule.Values.Sum(), fpByRule.Values.Sum(), fnByRule.Values.Sum());
    }

    private sealed record Expectation(string RuleId, string? Level);

    private static List<Expectation> ParseExpectations(string source)
    {
        var expected = new List<Expectation>();
        using var reader = new StringReader(source);
        string? line;
        bool annotated = false;
        while ((line = reader.ReadLine()) is not null)
        {
            string trimmed = line.Trim();
            if (trimmed.StartsWith("// EXPECT-CLEAN", StringComparison.Ordinal))
            {
                annotated = true;
                continue;
            }
            const string marker = "// EXPECT:";
            int idx = trimmed.IndexOf(marker, StringComparison.Ordinal);
            if (idx < 0)
                continue;
            annotated = true;
            string rest = trimmed[(idx + marker.Length)..];
            foreach (string token in rest.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                // "CBOM0050@High" -> rule + optional pinned severity level.
                string[] parts = token.Split('@', 2, StringSplitOptions.TrimEntries);
                expected.Add(new Expectation(parts[0], parts.Length > 1 ? parts[1] : null));
            }
        }

        if (!annotated)
            throw new InvalidOperationException(
                "Corpus file has no '// EXPECT:' or '// EXPECT-CLEAN' annotation; ground truth is required.");

        return expected;
    }

    private static Dictionary<string, int> CountById(IEnumerable<string> ids)
    {
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (string id in ids)
            Add(counts, id, 1);
        return counts;
    }

    private static void Add(Dictionary<string, int> map, string key, int n) =>
        map[key] = map.GetValueOrDefault(key) + n;

    private static string LocateCorpus()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            string candidate = Path.Combine(dir.FullName, "benchmark", "corpus");
            if (Directory.Exists(candidate))
                return candidate;
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("Could not locate /benchmark/corpus from " + AppContext.BaseDirectory);
    }

    /// <summary>Renders the accuracy results as the published <c>benchmark/ACCURACY.md</c> evidence report.</summary>
    public static string RenderReport(Results r)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Accuracy benchmark");
        sb.AppendLine();
        sb.AppendLine("Generated by the `AccuracyBenchmark` test from the labeled corpus in [`corpus/`](corpus/).");
        sb.AppendLine("Each corpus file declares the findings it should produce (independently-authored ground");
        sb.AppendLine("truth); the real detector pipeline is run over it and compared. **This measures the tool");
        sb.AppendLine("against its own claimed coverage on curated cases — it is not a claim about arbitrary code.**");
        sb.AppendLine("See [README.md](README.md) for methodology and limits.");
        sb.AppendLine();
        sb.AppendLine("## Headline");
        sb.AppendLine();
        sb.AppendLine($"- Corpus files: **{r.FileCount}**");
        sb.AppendLine($"- True positives: **{r.TotalTruePositives}** · False positives: **{r.TotalFalsePositives}** · False negatives: **{r.TotalFalseNegatives}**");
        sb.AppendLine($"- **Precision: {r.Precision:P1}** · **Recall: {r.Recall:P1}** · **F1: {r.F1:P1}**");
        sb.AppendLine($"- Severity-pin checks failed: **{r.TotalSeverityMismatches}** (context discrimination, e.g. benign vs key-material `Random`)");
        sb.AppendLine();
        sb.AppendLine("## Per-rule");
        sb.AppendLine();
        sb.AppendLine("| Rule | TP | FP | FN | Precision | Recall |");
        sb.AppendLine("| --- | --- | --- | --- | --- | --- |");
        foreach (RuleScore s in r.PerRule)
            sb.AppendLine($"| {s.RuleId} | {s.TruePositives} | {s.FalsePositives} | {s.FalseNegatives} | {s.Precision:P0} | {s.Recall:P0} |");
        sb.AppendLine();
        sb.AppendLine("## Per-file");
        sb.AppendLine();
        sb.AppendLine("| File | Expected | Detected | False positives | False negatives |");
        sb.AppendLine("| --- | --- | --- | --- | --- |");
        foreach (FileResult f in r.Files)
        {
            string exp = f.Expected.Count == 0 ? "(clean)" : string.Join(" ", f.Expected);
            string act = f.Actual.Count == 0 ? "(none)" : string.Join(" ", f.Actual);
            string fp = f.FalsePositives.Count == 0 ? "—" : string.Join(" ", f.FalsePositives);
            string fn = f.FalseNegatives.Count == 0 ? "—" : string.Join(" ", f.FalseNegatives);
            string sev = f.SeverityMismatches.Count == 0 ? string.Empty : "  ⚠ " + string.Join("; ", f.SeverityMismatches);
            sb.AppendLine($"| {f.File} | {exp} | {act} | {fp} | {fn}{sev} |");
        }
        sb.AppendLine();
        sb.AppendLine("> Out of corpus scope: **CBOM0081** (package-manifest inventory) is evaluated from");
        sb.AppendLine("> `project.assets.json`, not source, so it is exercised by CLI tests rather than this");
        sb.AppendLine("> source corpus. Symbol-based third-party rules (KMS, Bouncy Castle) use in-file stubs.");
        return sb.ToString();
    }
}
