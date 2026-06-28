using System.Text.Json;

namespace PostQuantum.CryptographicBillOfMaterials.Reporting;

/// <summary>A single validation problem. <see cref="Severity"/> is "error" or "warning".</summary>
public sealed record ValidationIssue(string Severity, string Location, string Message);

/// <summary>The outcome of validating a CBOM document.</summary>
public sealed record ValidationResult(IReadOnlyList<ValidationIssue> Issues)
{
    public bool IsValid => !Issues.Any(i => i.Severity == "error");
    public int ErrorCount => Issues.Count(i => i.Severity == "error");
    public int WarningCount => Issues.Count(i => i.Severity == "warning");
}

/// <summary>
/// Validates a CBOM against the structural requirements of CycloneDX 1.6 and the <c>dotnet-cbom</c>
/// profile (TDD §3.4): required cbom:* properties, evidence locations, risk verdicts, and rule IDs.
/// This is a focused structural + profile validator; full JSON-Schema-draft validation against the
/// official bom-1.6.schema.json is a separate, heavier check (see docs/KNOWN-GAPS.md).
/// </summary>
public static class CbomValidator
{
    private static readonly HashSet<string> AssetTypes = new(StringComparer.Ordinal)
    {
        "algorithm", "certificate", "protocol", "related-crypto-material",
    };

    public static ValidationResult Validate(Stream cbomJson)
    {
        var issues = new List<ValidationIssue>();

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(cbomJson);
        }
        catch (JsonException ex)
        {
            return new ValidationResult(new[] { new ValidationIssue("error", "$", $"Invalid JSON: {ex.Message}") });
        }

        using (doc)
        {
            JsonElement root = doc.RootElement;

            RequireString(root, "bomFormat", "CycloneDX", "$.bomFormat", issues);
            RequireString(root, "specVersion", "1.6", "$.specVersion", issues);

            if (!root.TryGetProperty("metadata", out JsonElement metadata))
            {
                issues.Add(new ValidationIssue("error", "$.metadata", "Missing metadata."));
            }
            else
            {
                IReadOnlyDictionary<string, string> metaProps = ReadProperties(metadata);
                RequireProperty(metaProps, "cbom:profile:version", "$.metadata.properties", issues, "error");
                RequireProperty(metaProps, "cbom:readiness:score", "$.metadata.properties", issues, "warning");
                RequireProperty(metaProps, "cbom:coverage:projectsAnalyzed", "$.metadata.properties", issues, "warning");
            }

            if (root.TryGetProperty("components", out JsonElement components)
                && components.ValueKind == JsonValueKind.Array)
            {
                int i = 0;
                foreach (JsonElement component in components.EnumerateArray())
                {
                    ValidateComponent(component, $"$.components[{i}]", issues);
                    i++;
                }
            }
        }

        return new ValidationResult(issues);
    }

    private static void ValidateComponent(JsonElement component, string path, List<ValidationIssue> issues)
    {
        string? type = component.TryGetProperty("type", out JsonElement t) ? t.GetString() : null;
        if (type != "cryptographic-asset")
            return; // only profile-validate crypto assets

        if (!HasNonEmptyString(component, "bom-ref"))
            issues.Add(new ValidationIssue("error", $"{path}.bom-ref", "cryptographic-asset missing bom-ref."));
        if (!HasNonEmptyString(component, "name"))
            issues.Add(new ValidationIssue("error", $"{path}.name", "cryptographic-asset missing name."));

        if (component.TryGetProperty("cryptoProperties", out JsonElement cp)
            && cp.TryGetProperty("assetType", out JsonElement at))
        {
            string? assetType = at.GetString();
            if (assetType is null || !AssetTypes.Contains(assetType))
                issues.Add(new ValidationIssue("error", $"{path}.cryptoProperties.assetType",
                    $"Invalid assetType '{assetType}'."));
        }
        else
        {
            issues.Add(new ValidationIssue("error", $"{path}.cryptoProperties.assetType",
                "cryptographic-asset missing cryptoProperties.assetType."));
        }

        IReadOnlyDictionary<string, string> props = ReadProperties(component);
        RequireProperty(props, "cbom:risk:level", $"{path}.properties", issues, "error");
        RequireProperty(props, "cbom:rule:id", $"{path}.properties", issues, "error");
        RequireProperty(props, "cbom:risk:basis", $"{path}.properties", issues, "warning");
        RequireProperty(props, "cbom:detection:confidence", $"{path}.properties", issues, "warning");

        bool hasOccurrence = component.TryGetProperty("evidence", out JsonElement ev)
            && ev.TryGetProperty("occurrences", out JsonElement occ)
            && occ.ValueKind == JsonValueKind.Array
            && occ.GetArrayLength() > 0;
        bool isConfig = props.GetValueOrDefault("cbom:detection:method") == "Config";
        if (!hasOccurrence && !isConfig)
            issues.Add(new ValidationIssue("warning", $"{path}.evidence.occurrences",
                "cryptographic-asset has no source occurrence and is not a config-method finding."));
    }

    private static void RequireString(JsonElement root, string name, string expected, string path, List<ValidationIssue> issues)
    {
        string? actual = root.TryGetProperty(name, out JsonElement e) ? e.GetString() : null;
        if (actual != expected)
            issues.Add(new ValidationIssue("error", path, $"Expected {name}='{expected}', found '{actual ?? "(missing)"}'."));
    }

    private static void RequireProperty(IReadOnlyDictionary<string, string> props, string name, string path,
        List<ValidationIssue> issues, string severity)
    {
        if (!props.ContainsKey(name))
            issues.Add(new ValidationIssue(severity, path, $"Missing profile property '{name}'."));
    }

    private static bool HasNonEmptyString(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out JsonElement e) && !string.IsNullOrEmpty(e.GetString());

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
}
