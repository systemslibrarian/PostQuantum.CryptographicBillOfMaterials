using System.Globalization;
using System.Reflection;
using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Knowledge;

/// <summary>
/// Dependency-free load path for <see cref="KnowledgeBase"/>, backed by <see cref="MiniJson"/> instead of
/// System.Text.Json. This is the path the Roslyn analyzer uses (the analyzer's dependency closure must stay
/// limited to the compiler libraries). It produces the same data as <c>LoadDefault</c>.
/// </summary>
public sealed partial class KnowledgeBase
{
    /// <summary>Load the built-in knowledge base using the dependency-free <see cref="MiniJson"/> reader.</summary>
    public static KnowledgeBase LoadPortable()
    {
        Assembly asm = typeof(KnowledgeBase).Assembly;
        string resourceName = asm.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith("algorithms.json", StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException("Embedded algorithms.json resource was not found.");

        string json;
        using (Stream stream = asm.GetManifestResourceStream(resourceName)!)
        using (var reader = new StreamReader(stream))
            json = reader.ReadToEnd();

        var root = (Dictionary<string, object?>)MiniJson.Parse(json)!;
        string version = AsString(root.GetValueOrDefault("version")) ?? "";
        var algorithms = new List<AlgorithmInfo>();
        if (root.GetValueOrDefault("algorithms") is List<object?> list)
        {
            foreach (object? item in list)
                if (item is Dictionary<string, object?> a)
                    algorithms.Add(ReadAlgorithm(a));
        }

        return new KnowledgeBase(version, algorithms);
    }

    private static AlgorithmInfo ReadAlgorithm(Dictionary<string, object?> a) => new()
    {
        Name = AsString(a.GetValueOrDefault("name")) ?? "",
        Primitive = AsString(a.GetValueOrDefault("primitive")),
        DefaultKeyBits = AsInt(a.GetValueOrDefault("defaultKeyBits")),
        ClassicalSecurityLevel = AsInt(a.GetValueOrDefault("classicalSecurityLevel")),
        NistQuantumSecurityLevel = AsInt(a.GetValueOrDefault("nistQuantumSecurityLevel")),
        Oid = AsString(a.GetValueOrDefault("oid")),
        QuantumVulnerability = AsEnum<QuantumVulnerability>(a.GetValueOrDefault("quantumVulnerability")),
        QuantumThreat = AsEnum<QuantumThreat>(a.GetValueOrDefault("quantumThreat")),
        ClassicalWeakness = AsEnum<ClassicalWeakness>(a.GetValueOrDefault("classicalWeakness")),
        Basis = AsString(a.GetValueOrDefault("basis")) ?? "",
        Recommendation = a.GetValueOrDefault("recommendation") is Dictionary<string, object?> r
            ? ReadRecommendation(r)
            : null,
    };

    private static RecommendationData ReadRecommendation(Dictionary<string, object?> r)
    {
        var options = new List<RecommendationOptionData>();
        if (r.GetValueOrDefault("options") is List<object?> opts)
        {
            foreach (object? o in opts)
            {
                if (o is not Dictionary<string, object?> od)
                    continue;
                options.Add(new RecommendationOptionData
                {
                    Description = AsString(od.GetValueOrDefault("description")) ?? "",
                    Basis = AsString(od.GetValueOrDefault("basis")) ?? "",
                    Tradeoffs = AsString(od.GetValueOrDefault("tradeoffs")),
                    ResultingVulnerability = od.ContainsKey("resultingVulnerability")
                        ? AsEnum<QuantumVulnerability>(od.GetValueOrDefault("resultingVulnerability"))
                        : null,
                });
            }
        }
        return new RecommendationData
        {
            Summary = AsString(r.GetValueOrDefault("summary")) ?? "",
            Options = options,
        };
    }

    private static string? AsString(object? v) => v as string;

    private static int? AsInt(object? v) => v is double d ? (int)d : (int?)null;

    private static TEnum AsEnum<TEnum>(object? v) where TEnum : struct, Enum =>
        v is string s && Enum.TryParse(s, ignoreCase: true, out TEnum result)
            ? result
            : default;
}
