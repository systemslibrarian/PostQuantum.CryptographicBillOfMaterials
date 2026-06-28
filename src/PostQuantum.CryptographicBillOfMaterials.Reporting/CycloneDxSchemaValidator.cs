using System.Reflection;
using System.Text.Json.Nodes;
using Json.Schema;

namespace PostQuantum.CryptographicBillOfMaterials.Reporting;

/// <summary>
/// Validates a CBOM against the <em>official</em> CycloneDX 1.6 JSON Schema (<c>bom-1.6.schema.json</c> plus
/// its referenced <c>spdx</c> and <c>jsf</c> schemas), all bundled as embedded resources so validation works
/// fully offline with no network or external download. This is the heavyweight, draft-07 schema check that
/// complements the lighter <see cref="CbomValidator"/> profile check.
/// </summary>
public static class CycloneDxSchemaValidator
{
    private const int MaxReportedErrors = 50;

    private static readonly Lazy<(JsonSchema Schema, EvaluationOptions Options)> Loaded = new(Load);

    /// <summary>Validate a CBOM JSON stream against the official CycloneDX 1.6 schema.</summary>
    public static ValidationResult Validate(Stream cbomJson)
    {
        JsonNode? node;
        try
        {
            node = JsonNode.Parse(cbomJson);
        }
        catch (Exception ex)
        {
            return new ValidationResult(new[] { new ValidationIssue("error", "$", $"Invalid JSON: {ex.Message}") });
        }

        if (node is null)
            return new ValidationResult(new[] { new ValidationIssue("error", "$", "Empty document.") });

        (JsonSchema schema, EvaluationOptions options) = Loaded.Value;

        EvaluationResults results;
        try
        {
            results = schema.Evaluate(node, options);
        }
        catch (Exception ex)
        {
            return new ValidationResult(new[]
            {
                new ValidationIssue("error", "$", $"Schema evaluation failed: {ex.Message}"),
            });
        }

        if (results.IsValid)
            return new ValidationResult(Array.Empty<ValidationIssue>());

        var issues = new List<ValidationIssue>();
        foreach (EvaluationResults detail in Flatten(results))
        {
            if (!detail.HasErrors || detail.Errors is null)
                continue;
            foreach (KeyValuePair<string, string> error in detail.Errors)
            {
                string location = detail.InstanceLocation.ToString() is { Length: > 0 } loc ? loc : "$";
                issues.Add(new ValidationIssue("error", location, $"[{error.Key}] {error.Value}"));
                if (issues.Count >= MaxReportedErrors)
                    return new ValidationResult(issues);
            }
        }

        // The evaluator reported invalid but produced no leaf error message: surface a generic failure.
        if (issues.Count == 0)
            issues.Add(new ValidationIssue("error", "$", "Document does not conform to the CycloneDX 1.6 schema."));

        return new ValidationResult(issues);
    }

    private static IEnumerable<EvaluationResults> Flatten(EvaluationResults results)
    {
        yield return results;
        foreach (EvaluationResults child in results.Details)
            foreach (EvaluationResults descendant in Flatten(child))
                yield return descendant;
    }

    private static (JsonSchema, EvaluationOptions) Load()
    {
        JsonSchema bom = LoadSchema("bom-1.6.schema.json");
        JsonSchema spdx = LoadSchema("spdx.schema.json");
        JsonSchema jsf = LoadSchema("jsf-0.82.schema.json");

        var options = new EvaluationOptions { OutputFormat = OutputFormat.List };
        // Register the referenced schemas by their $id so the bom schema's relative $refs resolve offline.
        options.SchemaRegistry.Register(spdx);
        options.SchemaRegistry.Register(jsf);
        options.SchemaRegistry.Register(bom);
        return (bom, options);
    }

    private static JsonSchema LoadSchema(string fileName)
    {
        Assembly asm = typeof(CycloneDxSchemaValidator).Assembly;
        string resource = asm.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith(fileName, StringComparison.Ordinal))
            ?? throw new InvalidOperationException($"Embedded schema '{fileName}' not found.");
        using Stream stream = asm.GetManifestResourceStream(resource)!;
        using var reader = new StreamReader(stream);
        return JsonSchema.FromText(reader.ReadToEnd());
    }
}
