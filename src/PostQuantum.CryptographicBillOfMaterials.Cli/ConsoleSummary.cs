using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Cli;

/// <summary>Prints a concise, honest scan summary to the console.</summary>
internal static class ConsoleSummary
{
    public static void Print(CbomDocument document, IReadOnlyList<string> diagnostics, ScanOptions options)
    {
        ScanMetadata m = document.Metadata;
        Console.WriteLine($"{m.ToolName} {m.ToolVersion}  ·  CycloneDX {m.CycloneDxSpecVersion}  ·  profile {m.ProfileVersion}");

        int totalProjects = m.ProjectsAnalyzed + m.ProjectsFailed;
        string coverage = $"Analyzed {m.ProjectsAnalyzed}/{totalProjects} projects";
        if (m.ProjectsFailed > 0)
            coverage += $"   (!) {m.ProjectsFailed} failed to load — reported as NOT analyzed";
        Console.WriteLine(coverage);

        var findings = document.AllFindings.ToList();
        Console.WriteLine();
        Console.WriteLine(
            $"Findings: {findings.Count}   (Critical {Count(findings, RiskLevel.Critical)} · " +
            $"High {Count(findings, RiskLevel.High)} · Medium {Count(findings, RiskLevel.Medium)} · " +
            $"Low {Count(findings, RiskLevel.Low)} · Info {Count(findings, RiskLevel.Informational)})");

        int pqc = findings.Count(f => f.QuantumVulnerability == QuantumVulnerability.PostQuantum);
        if (pqc > 0)
            Console.WriteLine($"PQC positive signals: {pqc}");

        var top = findings
            .Where(f => f.RiskLevel >= RiskLevel.Medium)
            .OrderByDescending(f => f.RiskLevel)
            .ThenByDescending(f => f.RiskScore)
            .Take(8)
            .ToList();
        if (top.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("Top findings");
            foreach (CryptoFinding f in top)
                Console.WriteLine(
                    $"  {f.RiskLevel,-8} {f.RuleId}  {f.AlgorithmName}  " +
                    $"{Path.GetFileName(f.Location.FilePath)}:{f.Location.Line}");
        }

        Console.WriteLine();
        Console.WriteLine($"PQC Readiness: solution {document.SolutionReadinessScore}");
        foreach (ProjectInventory p in document.Projects.Where(p => p.Analyzed))
            Console.WriteLine(
                $"  {p.Name}: {p.ReadinessScore}" + (p.ReadinessTrivial ? " (no quantum-relevant crypto)" : string.Empty));

        if (diagnostics.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine($"Diagnostics: {diagnostics.Count}");
            foreach (string d in diagnostics.Take(5))
                Console.WriteLine($"  - {d}");
            if (diagnostics.Count > 5)
                Console.WriteLine($"  … and {diagnostics.Count - 5} more");
        }

        Console.WriteLine();
        Console.WriteLine($"Wrote reports to: {options.OutputDir}");
        Console.WriteLine(
            "Note: a clean scan means \"no detectable issues in analyzed source,\" not \"the system is quantum-safe.\"");
    }

    private static int Count(IEnumerable<CryptoFinding> findings, RiskLevel level) =>
        findings.Count(f => f.RiskLevel == level);
}
