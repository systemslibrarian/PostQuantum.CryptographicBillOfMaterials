using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Rules;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detectors;

/// <summary>
/// Cloud KMS inventory. Records that a managed KMS client is in use (Azure Key Vault, AWS KMS, GCP KMS),
/// and — going deeper than "a KMS is used" — recognizes key-creation options that mint a *classical
/// asymmetric* key (RSA/EC) inside the KMS, which is Shor-vulnerable even though it is managed. Region and
/// account are typically supplied at runtime and remain an inherent blind spot (see KNOWN-GAPS).
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

    // Key-creation option/request types that specify a classical asymmetric key spec.
    private static readonly Dictionary<string, string> AsymmetricKeyOptions = new(StringComparer.Ordinal)
    {
        ["CreateRsaKeyOptions"] = "RSA",   // Azure
        ["CreateEcKeyOptions"] = "EC",     // Azure
    };

    public override DetectorMetadata Metadata { get; } = new(
        "CBOM0070", "Cloud KMS client in use", RuleCategory.CloudKms, RiskLevel.Informational,
        "Cloud KMS provides managed key storage and rotation; classical asymmetric keys minted in a KMS are still Shor-vulnerable.");

    public override IReadOnlyCollection<SyntaxKind> SyntaxKinds { get; } =
        new[] { SyntaxKind.ObjectCreationExpression, SyntaxKind.InvocationExpression };

    public override void Inspect(DetectionContext ctx)
    {
        if (ctx.Node is ObjectCreationExpressionSyntax oce
            && SimpleTypeName(oce.Type) is { } typeName
            && AsymmetricKeyOptions.TryGetValue(typeName, out string? family))
        {
            ReportManagedAsymmetricKey(ctx, oce, family);
            return;
        }

        ITypeSymbol? type = ResolveInstantiatedType(ctx);
        if (type is null)
            return;

        if (AsymmetricKeyOptions.TryGetValue(type.Name, out string? f2))
        {
            ReportManagedAsymmetricKey(ctx, ctx.Node, f2);
            return;
        }

        if (KmsClientTypes.Contains(type.Name))
            ReportClientInventory(ctx, type.Name);
    }

    private void ReportManagedAsymmetricKey(DetectionContext ctx, SyntaxNode node, string family)
    {
        string display = family == "RSA" ? "KMS-managed RSA key" : "KMS-managed EC key";
        var recommendation = new Recommendation(
            "Plan to rotate this KMS key to a post-quantum or hybrid key type as the provider offers one.",
            new[]
            {
                new RecommendationOption(
                    "Track the provider's PQC roadmap; create ML-KEM/ML-DSA (or hybrid) keys once available, and shorten rotation for the classical key meanwhile.",
                    "NIST IR 8547 (DRAFT); CNSA 2.0; provider KMS documentation.", null, QuantumVulnerability.PostQuantum),
            });

        ctx.Report(FindingFactory.Create(
            Metadata, ctx, node,
            displayName: display,
            quantumVulnerability: QuantumVulnerability.Vulnerable,
            classicalWeakness: ClassicalWeakness.None,
            usage: family == "RSA" ? UsageContext.KeyExchange : UsageContext.Signing,
            confidence: DetectionConfidence.High,
            basis: "A classical asymmetric key (RSA/EC) created in a managed KMS is still broken by Shor's algorithm; managed storage does not change the algorithm's quantum posture (NIST IR 8547 DRAFT; CNSA 2.0).",
            recommendation: recommendation,
            assetType: CryptoAssetType.RelatedCryptoMaterial,
            primitive: "kms-key"));
    }

    private void ReportClientInventory(DetectionContext ctx, string clientName)
    {
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
            displayName: clientName,
            quantumVulnerability: QuantumVulnerability.NotVulnerable,
            classicalWeakness: ClassicalWeakness.None,
            usage: UsageContext.AtRest,
            confidence: DetectionConfidence.High,
            basis: basis,
            recommendation: recommendation,
            assetType: CryptoAssetType.RelatedCryptoMaterial,
            primitive: "kms"));
    }

    private static string? SimpleTypeName(SyntaxNode? type) => type switch
    {
        IdentifierNameSyntax id => id.Identifier.ValueText,
        QualifiedNameSyntax q => q.Right.Identifier.ValueText,
        GenericNameSyntax g => g.Identifier.ValueText,
        _ => null,
    };
}
