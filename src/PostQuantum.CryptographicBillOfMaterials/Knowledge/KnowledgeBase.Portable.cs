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
        var root = ReadEmbeddedObject("algorithms.json");
        string version = AsString(root.GetValueOrDefault("version")) ?? "";
        var algorithms = new List<AlgorithmInfo>();
        if (root.GetValueOrDefault("algorithms") is List<object?> list)
        {
            foreach (object? item in list)
                if (item is Dictionary<string, object?> a)
                    algorithms.Add(ReadAlgorithm(a));
        }

        var pbRoot = ReadEmbeddedObject("playbooks.json");
        string playbooksVersion = AsString(pbRoot.GetValueOrDefault("version")) ?? "";
        var playbooks = new List<MigrationPlaybook>();
        if (pbRoot.GetValueOrDefault("playbooks") is List<object?> pbList)
        {
            foreach (object? item in pbList)
                if (item is Dictionary<string, object?> pb)
                    playbooks.Add(ReadPlaybook(pb));
        }

        return new KnowledgeBase(version, algorithms, playbooksVersion, playbooks);
    }

    /// <summary>Read an embedded JSON resource by file name and parse it into a MiniJson object.</summary>
    private static Dictionary<string, object?> ReadEmbeddedObject(string fileName)
    {
        Assembly asm = typeof(KnowledgeBase).Assembly;
        string resourceName = asm.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith(fileName, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException($"Embedded {fileName} resource was not found.");

        string json;
        using (Stream stream = asm.GetManifestResourceStream(resourceName)!)
        using (var reader = new StreamReader(stream))
            json = reader.ReadToEnd();

        return (Dictionary<string, object?>)MiniJson.Parse(json)!;
    }

    /// <summary>
    /// The analyzer surfaces a playbook's identity and headline guidance, not its full worked code, so this
    /// reader takes the scalar fields and the ordered steps and leaves approaches and references to the
    /// System.Text.Json path. Keeping it shallow is deliberate: MiniJson exists to bound the analyzer's
    /// dependency closure, not to grow a second full deserializer that can drift from the first.
    /// </summary>
    private static MigrationPlaybook ReadPlaybook(Dictionary<string, object?> p)
    {
        var steps = new List<string>();
        if (p.GetValueOrDefault("steps") is List<object?> stepList)
        {
            foreach (object? s in stepList)
                if (s is string str)
                    steps.Add(str);
        }

        return new MigrationPlaybook
        {
            Id = AsString(p.GetValueOrDefault("id")) ?? "",
            Title = AsString(p.GetValueOrDefault("title")) ?? "",
            AppliesTo = AsString(p.GetValueOrDefault("appliesTo")) ?? "",
            Target = AsString(p.GetValueOrDefault("target")) ?? "",
            Steps = steps,
        };
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
        MigrationPlaybookIds = AsStringList(a.GetValueOrDefault("migrationPlaybookIds")),
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

    private static List<string> AsStringList(object? v)
    {
        var result = new List<string>();
        if (v is List<object?> list)
        {
            foreach (object? item in list)
                if (item is string s)
                    result.Add(s);
        }
        return result;
    }

    private static int? AsInt(object? v) => v is double d ? (int)d : (int?)null;

    private static TEnum AsEnum<TEnum>(object? v) where TEnum : struct, Enum =>
        v is string s && Enum.TryParse(s, ignoreCase: true, out TEnum result)
            ? result
            : default;
}
