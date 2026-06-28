using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Knowledge;

/// <summary>
/// The algorithm knowledge base, loaded from the embedded <c>algorithms.json</c>. Central source of
/// quantum/classical verdicts, OIDs, NIST levels, citations, and standards-based recommendations.
/// </summary>
public sealed class KnowledgeBase
{
    private readonly Dictionary<string, AlgorithmInfo> _byName;

    /// <summary>Knowledge-base content version (independent of code version).</summary>
    public string Version { get; }

    private KnowledgeBase(string version, IEnumerable<AlgorithmInfo> algorithms)
    {
        Version = version;
        _byName = algorithms.ToDictionary(a => a.Name, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>All known algorithms.</summary>
    public IReadOnlyCollection<AlgorithmInfo> Algorithms => _byName.Values;

    /// <summary>Look up an algorithm by canonical name (case-insensitive); null if unknown.</summary>
    public AlgorithmInfo? Lookup(string name) =>
        _byName.TryGetValue(name, out var info) ? info : null;

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: false) },
    };

    /// <summary>Load the built-in knowledge base embedded in this assembly.</summary>
    public static KnowledgeBase LoadDefault()
    {
        Assembly asm = typeof(KnowledgeBase).Assembly;
        string resourceName = asm.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith("algorithms.json", StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException("Embedded algorithms.json resource was not found.");

        using Stream stream = asm.GetManifestResourceStream(resourceName)!;
        KnowledgeFile doc = JsonSerializer.Deserialize<KnowledgeFile>(stream, SerializerOptions)
            ?? throw new InvalidOperationException("Failed to parse algorithms.json.");

        return new KnowledgeBase(doc.Version, doc.Algorithms);
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

    private sealed class KnowledgeFile
    {
        public string Version { get; init; } = "";
        public List<AlgorithmInfo> Algorithms { get; init; } = new();
    }
}
