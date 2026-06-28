using System.Globalization;
using System.Text.Json;
using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Reporting;

/// <summary>
/// Reads a CycloneDX CBOM produced by <see cref="CycloneDxReporter"/> back into a <see cref="CbomDocument"/>
/// for diffing/baselining. Reconstructs the fields needed for comparison (bom-ref, risk, quantum verdict,
/// rule, location); fields not persisted in the profile (e.g., Category, Title) are filled with safe
/// placeholders and are not used by the diff.
/// </summary>
public static class CbomReader
{
    public static CbomDocument Read(Stream stream)
    {
        using JsonDocument doc = JsonDocument.Parse(stream);
        JsonElement root = doc.RootElement;

        JsonElement metadata = root.TryGetProperty("metadata", out JsonElement md) ? md : default;
        IReadOnlyDictionary<string, string> metaProps = ReadProperties(metadata);

        string solutionName = metadata.TryGetProperty("component", out JsonElement comp)
            && comp.TryGetProperty("name", out JsonElement nm)
                ? nm.GetString() ?? "solution"
                : "solution";

        var findingsByProject = new Dictionary<string, List<CryptoFinding>>(StringComparer.Ordinal);
        if (root.TryGetProperty("components", out JsonElement components)
            && components.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement component in components.EnumerateArray())
            {
                if (!IsCryptographicAsset(component))
                    continue;

                CryptoFinding? finding = ReadFinding(component, out string project);
                if (finding is null)
                    continue;

                if (!findingsByProject.TryGetValue(project, out List<CryptoFinding>? list))
                    findingsByProject[project] = list = new List<CryptoFinding>();
                list.Add(finding);
            }
        }

        var projects = findingsByProject
            .Select(kvp => new ProjectInventory { Name = kvp.Key, Findings = kvp.Value, Analyzed = true })
            .ToList();

        return new CbomDocument
        {
            Metadata = new ScanMetadata
            {
                ToolName = ReadToolName(metadata),
                ToolVersion = ReadToolVersion(metadata),
                ProfileVersion = metaProps.GetValueOrDefault("cbom:profile:version", "1.0"),
                CycloneDxSpecVersion = root.TryGetProperty("specVersion", out JsonElement sv)
                    ? sv.GetString() ?? "1.6"
                    : "1.6",
                Timestamp = ReadTimestamp(metadata),
                SolutionName = solutionName,
                ProjectsAnalyzed = ParseInt(metaProps.GetValueOrDefault("cbom:coverage:projectsAnalyzed")),
                ProjectsFailed = ParseInt(metaProps.GetValueOrDefault("cbom:coverage:projectsFailed")),
            },
            Projects = projects,
            SolutionReadinessScore = ParseInt(metaProps.GetValueOrDefault("cbom:readiness:score")),
        };
    }

    private static bool IsCryptographicAsset(JsonElement component) =>
        component.TryGetProperty("type", out JsonElement t)
        && t.GetString() == "cryptographic-asset";

    private static CryptoFinding? ReadFinding(JsonElement component, out string project)
    {
        project = "(unknown)";
        IReadOnlyDictionary<string, string> props = ReadProperties(component);
        project = props.GetValueOrDefault("cbom:project", "(unknown)");

        string name = component.TryGetProperty("name", out JsonElement nm) ? nm.GetString() ?? "" : "";
        string? bomRef = component.TryGetProperty("bom-ref", out JsonElement br) ? br.GetString() : null;

        (string file, int line) = ReadLocation(component);

        return new CryptoFinding
        {
            RuleId = props.GetValueOrDefault("cbom:rule:id", "UNKNOWN"),
            Title = name,
            Category = RuleCategory.SymmetricEncryption, // placeholder; not used by diff
            AlgorithmName = name,
            RiskBasis = props.GetValueOrDefault("cbom:risk:basis", ""),
            RiskLevel = ParseEnum(props.GetValueOrDefault("cbom:risk:level"), RiskLevel.Informational),
            RiskScore = ParseInt(props.GetValueOrDefault("cbom:risk:score")),
            QuantumVulnerability = ParseQuantum(props.GetValueOrDefault("cbom:quantum:vulnerable")),
            AssetType = ParseAssetType(component),
            Location = new SourceLocation(file, line),
            BomRef = bomRef,
        };
    }

    private static (string file, int line) ReadLocation(JsonElement component)
    {
        if (component.TryGetProperty("evidence", out JsonElement ev)
            && ev.TryGetProperty("occurrences", out JsonElement occ)
            && occ.ValueKind == JsonValueKind.Array
            && occ.GetArrayLength() > 0)
        {
            JsonElement first = occ[0];
            string file = first.TryGetProperty("location", out JsonElement loc) ? loc.GetString() ?? "" : "";
            int line = first.TryGetProperty("line", out JsonElement ln) && ln.TryGetInt32(out int v) ? v : 0;
            return (file, line);
        }
        return ("", 0);
    }

    private static CryptoAssetType ParseAssetType(JsonElement component)
    {
        if (component.TryGetProperty("cryptoProperties", out JsonElement cp)
            && cp.TryGetProperty("assetType", out JsonElement at))
        {
            return at.GetString() switch
            {
                "certificate" => CryptoAssetType.Certificate,
                "protocol" => CryptoAssetType.Protocol,
                "related-crypto-material" => CryptoAssetType.RelatedCryptoMaterial,
                _ => CryptoAssetType.Algorithm,
            };
        }
        return CryptoAssetType.Algorithm;
    }

    private static QuantumVulnerability ParseQuantum(string? value) => value switch
    {
        "true" => QuantumVulnerability.Vulnerable,
        "reduced-margin" => QuantumVulnerability.ReducedMargin,
        _ => QuantumVulnerability.NotVulnerable,
    };

    private static IReadOnlyDictionary<string, string> ReadProperties(JsonElement owner)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (owner.ValueKind == JsonValueKind.Object
            && owner.TryGetProperty("properties", out JsonElement props)
            && props.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement p in props.EnumerateArray())
            {
                if (p.TryGetProperty("name", out JsonElement n) && p.TryGetProperty("value", out JsonElement v))
                    result[n.GetString() ?? ""] = v.GetString() ?? "";
            }
        }
        return result;
    }

    private static string ReadToolName(JsonElement metadata) =>
        TryFirstTool(metadata, "name") ?? "dotnet-cbom";

    private static string ReadToolVersion(JsonElement metadata) =>
        TryFirstTool(metadata, "version") ?? "0.0.0";

    private static string? TryFirstTool(JsonElement metadata, string field)
    {
        if (metadata.TryGetProperty("tools", out JsonElement tools)
            && tools.TryGetProperty("components", out JsonElement comps)
            && comps.ValueKind == JsonValueKind.Array
            && comps.GetArrayLength() > 0
            && comps[0].TryGetProperty(field, out JsonElement f))
        {
            return f.GetString();
        }
        return null;
    }

    private static DateTimeOffset ReadTimestamp(JsonElement metadata) =>
        metadata.TryGetProperty("timestamp", out JsonElement ts)
        && ts.GetString() is { } s
        && DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTimeOffset v)
            ? v
            : default;

    private static int ParseInt(string? value) =>
        int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int v) ? v : 0;

    private static TEnum ParseEnum<TEnum>(string? value, TEnum fallback) where TEnum : struct, Enum =>
        Enum.TryParse(value, ignoreCase: true, out TEnum v) ? v : fallback;
}
