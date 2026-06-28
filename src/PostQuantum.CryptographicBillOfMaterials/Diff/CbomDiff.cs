using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Diff;

/// <summary>How a finding changed between a baseline and the current scan.</summary>
public enum FindingDelta
{
    New,
    Unchanged,
    Resolved,
    RiskIncreased,
}

/// <summary>One finding's change between two CBOMs. Exactly one of Baseline/Current is null for New/Resolved.</summary>
public sealed record FindingDiff(CryptoFinding? Baseline, CryptoFinding? Current, FindingDelta Delta)
{
    /// <summary>A non-null finding to display for this diff item.</summary>
    public CryptoFinding Representative => Current ?? Baseline!;
}

/// <summary>The computed difference between two CBOMs.</summary>
public sealed record CbomDiff
{
    public required IReadOnlyList<FindingDiff> Items { get; init; }
    public int BaselineReadiness { get; init; }
    public int CurrentReadiness { get; init; }
    public int BaselineQuantumVulnerable { get; init; }
    public int CurrentQuantumVulnerable { get; init; }

    public int NewCount => Items.Count(i => i.Delta is FindingDelta.New);
    public int ResolvedCount => Items.Count(i => i.Delta is FindingDelta.Resolved);
    public int UnchangedCount => Items.Count(i => i.Delta is FindingDelta.Unchanged);
    public int RegressedCount => Items.Count(i => i.Delta is FindingDelta.RiskIncreased);

    /// <summary>True when no finding moved to a higher risk level (a CI-friendly regression gate).</summary>
    public bool NoRegressions => RegressedCount == 0;
}

/// <summary>Compares two CBOMs by stable bom-ref to show migration progress or regression (TDD §5.3).</summary>
public static class DiffEngine
{
    public static CbomDiff Compare(CbomDocument baseline, CbomDocument current)
    {
        Dictionary<string, CryptoFinding> baselineIndex = Index(baseline.AllFindings);
        Dictionary<string, CryptoFinding> currentIndex = Index(current.AllFindings);

        var items = new List<FindingDiff>();

        foreach ((string key, CryptoFinding cur) in currentIndex)
        {
            if (baselineIndex.TryGetValue(key, out CryptoFinding? bas))
            {
                FindingDelta delta = cur.RiskLevel > bas.RiskLevel
                    ? FindingDelta.RiskIncreased
                    : FindingDelta.Unchanged;
                items.Add(new FindingDiff(bas, cur, delta));
            }
            else
            {
                items.Add(new FindingDiff(null, cur, FindingDelta.New));
            }
        }

        foreach ((string key, CryptoFinding bas) in baselineIndex)
        {
            if (!currentIndex.ContainsKey(key))
                items.Add(new FindingDiff(bas, null, FindingDelta.Resolved));
        }

        return new CbomDiff
        {
            Items = items,
            BaselineReadiness = baseline.SolutionReadinessScore,
            CurrentReadiness = current.SolutionReadinessScore,
            BaselineQuantumVulnerable = CountVulnerable(baseline),
            CurrentQuantumVulnerable = CountVulnerable(current),
        };
    }

    private static Dictionary<string, CryptoFinding> Index(IEnumerable<CryptoFinding> findings)
    {
        var index = new Dictionary<string, CryptoFinding>(StringComparer.Ordinal);
        foreach (CryptoFinding f in findings)
            index[Key(f)] = f; // last-wins on the rare duplicate key
        return index;
    }

    private static string Key(CryptoFinding f) =>
        f.BomRef ?? $"{f.RuleId}:{f.Location.FilePath}:{f.Location.Line}:{f.AlgorithmName}";

    private static int CountVulnerable(CbomDocument doc) =>
        doc.AllFindings.Count(f => f.QuantumVulnerability == QuantumVulnerability.Vulnerable);
}
