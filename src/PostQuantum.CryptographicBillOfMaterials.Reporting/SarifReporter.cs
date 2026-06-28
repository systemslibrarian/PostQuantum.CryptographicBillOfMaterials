using System.Text.Json;
using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Reporting;

/// <summary>
/// Renders the CBOM as a <see href="https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html">SARIF 2.1.0</see>
/// log so findings surface in code-scanning tools (GitHub, IDEs).
/// </summary>
public sealed class SarifReporter : IReportRenderer
{
    private const string SchemaUri =
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

    private const string InformationUri =
        "https://github.com/systemslibrarian/PostQuantum.CryptographicBillOfMaterials";

    private static readonly JsonSerializerOptions SerializerOptions = new() { WriteIndented = true };

    /// <inheritdoc />
    public string FormatName => "sarif";

    /// <inheritdoc />
    public string FileExtension => ".sarif";

    /// <inheritdoc />
    public void Render(CbomDocument document, Stream output)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(output);

        var findings = document.AllFindings.ToList();

        var log = new Dictionary<string, object?>
        {
            ["$schema"] = SchemaUri,
            ["version"] = "2.1.0",
            ["runs"] = new object[]
            {
                new Dictionary<string, object?>
                {
                    ["tool"] = new Dictionary<string, object?>
                    {
                        ["driver"] = new Dictionary<string, object?>
                        {
                            ["name"] = "dotnet-cbom",
                            ["version"] = document.Metadata.ToolVersion,
                            ["informationUri"] = InformationUri,
                            ["rules"] = BuildRules(findings),
                        },
                    },
                    ["results"] = findings.Select(BuildResult).ToArray(),
                },
            },
        };

        var json = JsonSerializer.SerializeToUtf8Bytes(log, SerializerOptions);
        output.Write(json, 0, json.Length);
    }

    private static object[] BuildRules(IEnumerable<CryptoFinding> findings)
    {
        var rules = new List<object>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var finding in findings)
        {
            if (!seen.Add(finding.RuleId))
            {
                continue;
            }

            rules.Add(new Dictionary<string, object?>
            {
                ["id"] = finding.RuleId,
                ["name"] = finding.Title,
                ["shortDescription"] = new Dictionary<string, object?> { ["text"] = finding.Title },
                ["fullDescription"] = new Dictionary<string, object?> { ["text"] = finding.RiskBasis },
            });
        }

        return rules.ToArray();
    }

    private static Dictionary<string, object?> BuildResult(CryptoFinding finding)
    {
        return new Dictionary<string, object?>
        {
            ["ruleId"] = finding.RuleId,
            ["level"] = Level(finding.RiskLevel),
            ["message"] = new Dictionary<string, object?>
            {
                ["text"] = $"{finding.Title}: {finding.AlgorithmName} — {finding.Recommendation.Summary}",
            },
            ["locations"] = new object[]
            {
                new Dictionary<string, object?>
                {
                    ["physicalLocation"] = new Dictionary<string, object?>
                    {
                        ["artifactLocation"] = new Dictionary<string, object?>
                        {
                            ["uri"] = finding.Location.FilePath,
                        },
                        ["region"] = new Dictionary<string, object?>
                        {
                            ["startLine"] = finding.Location.Line,
                        },
                    },
                },
            },
        };
    }

    private static string Level(RiskLevel level) => level switch
    {
        RiskLevel.Critical => "error",
        RiskLevel.High => "error",
        RiskLevel.Medium => "warning",
        _ => "note",
    };
}
