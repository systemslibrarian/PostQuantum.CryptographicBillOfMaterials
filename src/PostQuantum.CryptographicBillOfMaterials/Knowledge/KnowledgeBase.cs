using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Knowledge;

/// <summary>
/// The algorithm knowledge base, loaded from the embedded <c>algorithms.json</c>. Central source of
/// quantum/classical verdicts, OIDs, NIST levels, citations, and standards-based recommendations.
/// </summary>
/// <remarks>
/// This file is the dependency-free core (no <c>System.Text.Json</c>) so it can be shared-source compiled
/// into the netstandard2.0 Roslyn analyzer. The System.Text.Json loader lives in the
/// <c>KnowledgeBase.Json.cs</c> partial (CLI path); the analyzer uses <c>LoadPortable</c> in
/// <c>KnowledgeBase.Portable.cs</c>, backed by <see cref="MiniJson"/>.
/// </remarks>
public sealed partial class KnowledgeBase
{
    private readonly Dictionary<string, AlgorithmInfo> _byName;
    private readonly Dictionary<string, MigrationPlaybook> _playbooksById;

    /// <summary>Knowledge-base content version (independent of code version).</summary>
    public string Version { get; }

    /// <summary>Migration-playbook content version (from <c>playbooks.json</c>).</summary>
    public string PlaybooksVersion { get; }

    private KnowledgeBase(
        string version,
        IEnumerable<AlgorithmInfo> algorithms,
        string playbooksVersion,
        IEnumerable<MigrationPlaybook> playbooks)
    {
        Version = version;
        _byName = algorithms.ToDictionary(a => a.Name, StringComparer.OrdinalIgnoreCase);
        PlaybooksVersion = playbooksVersion;
        _playbooksById = playbooks.ToDictionary(p => p.Id, StringComparer.Ordinal);
    }

    /// <summary>All known algorithms.</summary>
    public IReadOnlyCollection<AlgorithmInfo> Algorithms => _byName.Values;

    /// <summary>Look up an algorithm by canonical name (case-insensitive); null if unknown.</summary>
    public AlgorithmInfo? Lookup(string name) =>
        _byName.TryGetValue(name, out var info) ? info : null;

    /// <summary>All migration playbooks, in declared order.</summary>
    public IReadOnlyCollection<MigrationPlaybook> Playbooks => _playbooksById.Values;

    /// <summary>Look up a migration playbook by id; null if unknown.</summary>
    public MigrationPlaybook? Playbook(string id) =>
        _playbooksById.TryGetValue(id, out var pb) ? pb : null;

    /// <summary>
    /// The migration playbooks that apply to an algorithm, in declared order, de-duplicated. Returns empty
    /// for unknown algorithms or those needing no migration.
    /// </summary>
    public IReadOnlyList<MigrationPlaybook> PlaybooksForAlgorithm(string name)
    {
        AlgorithmInfo? info = Lookup(name);
        if (info is null || info.MigrationPlaybookIds.Count == 0)
            return Array.Empty<MigrationPlaybook>();

        return info.MigrationPlaybookIds
            .Distinct(StringComparer.Ordinal)
            .Select(Playbook)
            .Where(p => p is not null)
            .Select(p => p!)
            .ToList();
    }

    /// <summary>Build a runtime <see cref="Recommendation"/> for an algorithm, or null if none is defined.</summary>
    public Recommendation? BuildRecommendation(string name)
    {
        AlgorithmInfo? info = Lookup(name);
        if (info?.Recommendation is null)
            return null;

        var options = info.Recommendation.Options
            .Select(o => new RecommendationOption(o.Description, o.Basis, o.Tradeoffs, o.ResultingVulnerability))
            .ToList();
        return new Recommendation(info.Recommendation.Summary, options);
    }
}
