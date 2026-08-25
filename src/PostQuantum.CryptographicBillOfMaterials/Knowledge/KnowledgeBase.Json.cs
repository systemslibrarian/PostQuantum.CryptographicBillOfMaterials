using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PostQuantum.CryptographicBillOfMaterials.Knowledge;

/// <summary>
/// System.Text.Json load path for <see cref="KnowledgeBase"/>. Kept in its own partial so the STJ
/// dependency stays out of the dependency-free core that is shared-source compiled into the Roslyn
/// analyzer. Used by the CLI and library consumers; the analyzer uses <see cref="KnowledgeBase.LoadPortable"/>.
/// </summary>
public sealed partial class KnowledgeBase
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: false) },
    };

    /// <summary>Load the built-in knowledge base embedded in this assembly (System.Text.Json path).</summary>
    public static KnowledgeBase LoadDefault()
    {
        KnowledgeFile doc = LoadEmbedded<KnowledgeFile>("algorithms.json");
        PlaybookFile playbooks = LoadEmbedded<PlaybookFile>("playbooks.json");
        return new KnowledgeBase(doc.Version, doc.Algorithms, playbooks.Version, playbooks.Playbooks);
    }

    /// <summary>Deserialize an embedded JSON resource by file name.</summary>
    private static T LoadEmbedded<T>(string fileName)
    {
        using Stream stream = OpenEmbedded(fileName);
        return JsonSerializer.Deserialize<T>(stream, SerializerOptions)
            ?? throw new InvalidOperationException($"Failed to parse {fileName}.");
    }

    /// <summary>Open an embedded JSON resource stream by file name (shared by both load paths).</summary>
    private static Stream OpenEmbedded(string fileName)
    {
        Assembly asm = typeof(KnowledgeBase).Assembly;
        string resourceName = asm.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith(fileName, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException($"Embedded {fileName} resource was not found.");
        return asm.GetManifestResourceStream(resourceName)!;
    }

    private sealed class KnowledgeFile
    {
        public string Version { get; init; } = "";
        public List<AlgorithmInfo> Algorithms { get; init; } = new();
    }

    private sealed class PlaybookFile
    {
        public string Version { get; init; } = "";
        public List<MigrationPlaybook> Playbooks { get; init; } = new();
    }
}
