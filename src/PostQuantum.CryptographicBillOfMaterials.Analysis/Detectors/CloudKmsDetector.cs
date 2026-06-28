using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Rules;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detectors;

/// <summary>
/// Positive inventory signal: use of a managed cloud KMS client (Azure Key Vault, AWS KMS, GCP KMS),
/// indicating keys are stored/rotated by a managed service rather than handled in application code.
/// </summary>
internal sealed class CloudKmsDetector : DetectorBase
{
    private static readonly HashSet<string> KmsClientTypes = new(StringComparer.Ordinal)
    {
        "KeyClient",                        // Azure Key Vault (Azure.Security.KeyVault.Keys)
        "CryptographyClient",               // Azure Key Vault
        "CertificateClient",                // Azure Key Vault (Azure.Security.KeyVault.Certificates)
        "AmazonKeyManagementServiceClient", // AWS KMS
        "KeyManagementServiceClient",       // GCP KMS
    };

    public override DetectorMetadata Metadata { get; } = new(
        "CBOM0070", "Cloud KMS client in use", RuleCategory.CloudKms, RiskLevel.Informational,
        "Cloud KMS provides managed key storage and rotation (inventory signal).");

    public override IReadOnlyCollection<SyntaxKind> SyntaxKinds { get; } =
        new[] { SyntaxKind.ObjectCreationExpression, SyntaxKind.InvocationExpression };

    public override void Inspect(DetectionContext ctx)
    {
        ITypeSymbol? type = ResolveInstantiatedType(ctx);
        if (type is null || !KmsClientTypes.Contains(type.Name))
            return;

        const string basis = "Cloud KMS provides managed key storage and rotation (inventory signal).";

        var recommendation = new Recommendation(
            "Confirm key material uses PQC-capable key types as the provider makes them available.",
            new[]
            {
                new RecommendationOption(
                    "Track provider PQC roadmaps and prefer post-quantum key types/algorithms once supported.",
                    basis, null, QuantumVulnerability.NotVulnerable),
            });

        ctx.Report(FindingFactory.Create(
            Metadata, ctx, ctx.Node,
            displayName: type.Name,
            quantumVulnerability: QuantumVulnerability.NotVulnerable,
            classicalWeakness: ClassicalWeakness.None,
            usage: UsageContext.AtRest,
            confidence: DetectionConfidence.High,
            basis: basis,
            recommendation: recommendation,
            assetType: CryptoAssetType.RelatedCryptoMaterial,
            primitive: "kms"));
    }
}
