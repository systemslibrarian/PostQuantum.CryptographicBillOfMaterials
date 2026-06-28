namespace PostQuantum.CryptographicBillOfMaterials.Model;

/// <summary>Scan-level metadata recorded in the CBOM.</summary>
public sealed record ScanMetadata
{
    public required string ToolName { get; init; }
    public required string ToolVersion { get; init; }
    public required string ProfileVersion { get; init; }
    public required string CycloneDxSpecVersion { get; init; }
    public DateTimeOffset Timestamp { get; init; }
    public string? SolutionName { get; init; }
    public IReadOnlyList<string> TargetFrameworks { get; init; } = Array.Empty<string>();

    /// <summary>Number of projects successfully analyzed. Part of the fail-closed coverage signal.</summary>
    public int ProjectsAnalyzed { get; init; }

    /// <summary>Number of projects that failed to load/compile. A failed project is "not analyzed," never "clean."</summary>
    public int ProjectsFailed { get; init; }
}

/// <summary>Per-project inventory.</summary>
public sealed record ProjectInventory
{
    public required string Name { get; init; }
    public string? FilePath { get; init; }
    public bool Analyzed { get; init; } = true;
    public IReadOnlyList<CryptoFinding> Findings { get; init; } = Array.Empty<CryptoFinding>();
    public int ReadinessScore { get; init; }

    /// <summary>True when the project has no quantum-relevant crypto; a score of 100 then means "nothing to assess."</summary>
    public bool ReadinessTrivial { get; init; }
}

/// <summary>The root CBOM document: solution → project → finding.</summary>
public sealed record CbomDocument
{
    public required ScanMetadata Metadata { get; init; }
    public IReadOnlyList<ProjectInventory> Projects { get; init; } = Array.Empty<ProjectInventory>();
    public int SolutionReadinessScore { get; init; }

    /// <summary>All findings across every project.</summary>
    public IEnumerable<CryptoFinding> AllFindings => Projects.SelectMany(p => p.Findings);
}
