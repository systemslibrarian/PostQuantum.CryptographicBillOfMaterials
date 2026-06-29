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
        using Stream stream = OpenEmbeddedAlgorithms();
        KnowledgeFile doc = JsonSerializer.Deserialize<KnowledgeFile>(stream, SerializerOptions)
            ?? throw new InvalidOperationException("Failed to parse algorithms.json.");

        return new KnowledgeBase(doc.Version, doc.Algorithms);
    }

    /// <summary>Open the embedded <c>algorithms.json</c> resource stream (shared by both load paths).</summary>
    private static Stream OpenEmbeddedAlgorithms()
    {
        Assembly asm = typeof(KnowledgeBase).Assembly;
        string resourceName = asm.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith("algorithms.json", StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException("Embedded algorithms.json resource was not found.");
        return asm.GetManifestResourceStream(resourceName)!;
    }

    private sealed class KnowledgeFile
    {
        public string Version { get; init; } = "";
        public List<AlgorithmInfo> Algorithms { get; init; } = new();
    }
}
