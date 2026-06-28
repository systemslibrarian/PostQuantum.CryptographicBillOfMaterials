using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Reporting;

/// <summary>
/// Renders the CBOM as a valid <see href="https://cyclonedx.org/docs/1.6/json/">CycloneDX 1.6</see> BOM.
/// </summary>
/// <remarks>
/// Each finding becomes a <c>cryptographic-asset</c> component. Standard CycloneDX
/// <c>cryptoProperties</c> carry the algorithm shape; source locations live in
/// <c>evidence.occurrences</c> and detection confidence in <c>evidence.identity</c>.
/// All PQC posture and risk data that CycloneDX has no native field for is emitted as a profile
/// extension via <c>properties</c> entries under the <c>cbom:</c> namespace.
/// The <c>serialNumber</c> is a deterministic UUID derived from the solution name + timestamp,
/// so re-running the same scan produces byte-identical output.
/// </remarks>
public sealed class CycloneDxReporter : IReportRenderer
{
    private static readonly JsonSerializerOptions SerializerOptions = new() { WriteIndented = true };

    /// <inheritdoc />
    public string FormatName => "cyclonedx";

    /// <inheritdoc />
    public string FileExtension => ".cbom.json";

    /// <inheritdoc />
    public void Render(CbomDocument document, Stream output)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(output);

        var metadata = document.Metadata;

        var bom = new Dictionary<string, object?>
        {
            ["bomFormat"] = "CycloneDX",
            ["specVersion"] = "1.6",
            ["serialNumber"] = "urn:uuid:" + DeterministicSerialNumber(metadata),
            ["version"] = 1,
            ["metadata"] = BuildMetadata(document),
            ["components"] = BuildComponents(document),
        };

        var json = JsonSerializer.SerializeToUtf8Bytes(bom, SerializerOptions);
        output.Write(json, 0, json.Length);
    }

    private static Dictionary<string, object?> BuildMetadata(CbomDocument document)
    {
        var m = document.Metadata;
        return new Dictionary<string, object?>
        {
            ["timestamp"] = m.Timestamp.ToString("O"),
            ["tools"] = new Dictionary<string, object?>
            {
                ["components"] = new object[]
                {
                    new Dictionary<string, object?>
                    {
                        ["type"] = "application",
                        ["name"] = m.ToolName,
                        ["version"] = m.ToolVersion,
                    },
                },
            },
            ["component"] = new Dictionary<string, object?>
            {
                ["type"] = "application",
                ["bom-ref"] = "root",
                ["name"] = m.SolutionName ?? "solution",
            },
            ["properties"] = new object[]
            {
                Property("cbom:profile:version", m.ProfileVersion),
                Property("cbom:readiness:score", document.SolutionReadinessScore.ToString()),
                Property("cbom:readiness:formulaVersion", "1.0"),
                Property("cbom:coverage:projectsAnalyzed", m.ProjectsAnalyzed.ToString()),
                Property("cbom:coverage:projectsFailed", m.ProjectsFailed.ToString()),
                Property("cbom:cyclonedx:specVersion", m.CycloneDxSpecVersion),
            },
        };
    }

    private static List<object> BuildComponents(CbomDocument document)
    {
        var components = new List<object>();
        foreach (var project in document.Projects)
        {
            foreach (var finding in project.Findings)
            {
                components.Add(BuildComponent(finding, project.Name));
            }
        }

        return components;
    }

    private static Dictionary<string, object?> BuildComponent(CryptoFinding finding, string projectName)
    {
        var component = new Dictionary<string, object?>
        {
            ["type"] = "cryptographic-asset",
            ["bom-ref"] = finding.BomRef ?? FallbackBomRef(finding),
            ["name"] = finding.AlgorithmName,
            ["cryptoProperties"] = BuildCryptoProperties(finding),
            ["evidence"] = BuildEvidence(finding),
            ["properties"] = BuildProperties(finding, projectName),
        };

        return component;
    }

    private static Dictionary<string, object?> BuildCryptoProperties(CryptoFinding finding)
    {
        var crypto = new Dictionary<string, object?>
        {
            ["assetType"] = AssetType(finding.AssetType),
        };

        if (finding.AssetType == CryptoAssetType.Algorithm)
        {
            var algo = OmitNulls(new Dictionary<string, object?>
            {
                ["primitive"] = finding.Primitive,
                ["parameterSetIdentifier"] = finding.KeySizeBits?.ToString(),
                ["curve"] = finding.Curve,
                ["mode"] = finding.Mode,
                ["padding"] = finding.Padding,
                ["classicalSecurityLevel"] = finding.ClassicalSecurityLevel,
                ["nistQuantumSecurityLevel"] = finding.NistQuantumSecurityLevel,
            });

            if (algo.Count > 0)
            {
                crypto["algorithmProperties"] = algo;
            }
        }

        if (finding.Oid is not null)
        {
            crypto["oid"] = finding.Oid;
        }

        return crypto;
    }

    private static Dictionary<string, object?> BuildEvidence(CryptoFinding finding)
    {
        return new Dictionary<string, object?>
        {
            ["occurrences"] = new object[]
            {
                new Dictionary<string, object?>
                {
                    ["location"] = finding.Location.FilePath,
                    ["line"] = finding.Location.Line,
                },
            },
            ["identity"] = new object[]
            {
                new Dictionary<string, object?>
                {
                    ["field"] = "name",
                    ["confidence"] = ConfidenceScore(finding.Confidence),
                },
            },
        };
    }

    private static List<object> BuildProperties(CryptoFinding finding, string projectName)
    {
        var properties = new List<object>
        {
            Property("cbom:risk:level", finding.RiskLevel.ToString()),
            Property("cbom:risk:score", finding.RiskScore.ToString()),
            Property("cbom:risk:basis", finding.RiskBasis),
            Property("cbom:quantum:vulnerable", QuantumVulnerable(finding.QuantumVulnerability)),
            Property("cbom:quantum:threat", finding.QuantumThreat.ToString()),
            Property("cbom:detection:confidence", finding.Confidence.ToString()),
            Property("cbom:detection:method", finding.DetectionMethod.ToString()),
            Property("cbom:rule:id", finding.RuleId),
            Property("cbom:usage:context", finding.UsageContext.ToString()),
            Property("cbom:project", projectName),
        };

        if (finding.Recommendation.Options.Count > 0)
        {
            properties.Add(Property("cbom:recommendation:summary", finding.Recommendation.Summary));
            var options = finding.Recommendation.Options
                .Select(o => $"{o.Description}|{o.Basis}")
                .ToArray();
            properties.Add(Property(
                "cbom:recommendation:options",
                JsonSerializer.Serialize(options)));
        }

        return properties;
    }

    private static Dictionary<string, object?> Property(string name, string value) =>
        new() { ["name"] = name, ["value"] = value };

    private static Dictionary<string, object?> OmitNulls(Dictionary<string, object?> source)
    {
        var result = new Dictionary<string, object?>();
        foreach (var pair in source)
        {
            if (pair.Value is not null)
            {
                result[pair.Key] = pair.Value;
            }
        }

        return result;
    }

    private static string AssetType(CryptoAssetType type) => type switch
    {
        CryptoAssetType.Algorithm => "algorithm",
        CryptoAssetType.Certificate => "certificate",
        CryptoAssetType.Protocol => "protocol",
        CryptoAssetType.RelatedCryptoMaterial => "related-crypto-material",
        _ => "algorithm",
    };

    private static string QuantumVulnerable(QuantumVulnerability vulnerability) => vulnerability switch
    {
        QuantumVulnerability.Vulnerable => "true",
        QuantumVulnerability.ReducedMargin => "reduced-margin",
        QuantumVulnerability.NotVulnerable => "false",
        QuantumVulnerability.PostQuantum => "false",
        _ => "false",
    };

    private static double ConfidenceScore(DetectionConfidence confidence) => confidence switch
    {
        DetectionConfidence.Confirmed => 0.97,
        DetectionConfidence.High => 0.9,
        DetectionConfidence.Medium => 0.65,
        DetectionConfidence.Low => 0.35,
        _ => 0.35,
    };

    private static string FallbackBomRef(CryptoFinding finding) =>
        $"{finding.RuleId}:{finding.Location.FilePath}:{finding.Location.Line}";

    private static Guid DeterministicSerialNumber(ScanMetadata metadata)
    {
        var seed = (metadata.SolutionName ?? "solution") + "|" + metadata.Timestamp.ToString("O");
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(seed));
        var bytes = new byte[16];
        Array.Copy(hash, bytes, 16);
        return new Guid(bytes);
    }
}
