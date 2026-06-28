using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Rules;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detectors;

/// <summary>
/// X.509 certificate inventory. Loading a certificate (<c>X509Certificate2</c>) is recorded as a
/// certificate asset for completeness; minting one (<c>CertificateRequest</c>) is classified by the key
/// algorithm, so an RSA/ECDSA-signed certificate is surfaced as Shor-vulnerable signing material — the
/// dominant kind of long-lived public-key asset a PQC migration has to find.
/// </summary>
internal sealed class CertificateInventoryDetector : DetectorBase
{
    private static readonly HashSet<string> LoadTypes = new(StringComparer.Ordinal)
    {
        "X509Certificate2", "X509Certificate",
    };

    public override DetectorMetadata Metadata { get; } = new(
        "CBOM0042", "X.509 certificate", RuleCategory.DigitalSignature, RiskLevel.Informational,
        "X.509 certificates bind identities with public-key signatures; RSA/ECDSA signatures are Shor-vulnerable (NIST IR 8547 DRAFT; CNSA 2.0).");

    public override IReadOnlyCollection<SyntaxKind> SyntaxKinds { get; } =
        new[] { SyntaxKind.ObjectCreationExpression };

    public override void Inspect(DetectionContext ctx)
    {
        var oce = (ObjectCreationExpressionSyntax)ctx.Node;
        ITypeSymbol? type = ResolveInstantiatedType(ctx);
        string typeName = type?.Name ?? SimpleTypeName(oce.Type) ?? string.Empty;

        if (typeName == "CertificateRequest")
            InspectCertificateRequest(ctx, oce);
        else if (LoadTypes.Contains(typeName))
            InspectCertificateLoad(ctx, oce);
    }

    /// <summary>A new certificate is being minted; classify by the signing key algorithm.</summary>
    private void InspectCertificateRequest(DetectionContext ctx, ObjectCreationExpressionSyntax oce)
    {
        string? keyAlg = oce.ArgumentList is { } args ? SigningKeyAlgorithm(ctx, args) : null;

        if (keyAlg is "RSA" or "ECDSA" or "DSA" or "ECDH")
        {
            UsageContext usage = UsageContext.Signing;
            var recommendation = new Recommendation(
                "Track this certificate for PQC migration; plan a move to a NIST PQC signature once your PKI/CA supports it.",
                new[]
                {
                    new RecommendationOption(
                        "Adopt ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) certificates when your CA/runtime supports them; meanwhile use RSA-3072+/P-384 and shorten certificate lifetimes.",
                        "NIST IR 8547 (DRAFT); CNSA 2.0; FIPS 204/205.", null, QuantumVulnerability.PostQuantum),
                });

            ctx.Report(FindingFactory.Create(
                Metadata, ctx, oce,
                displayName: $"X.509 certificate request ({keyAlg})",
                quantumVulnerability: QuantumVulnerability.Vulnerable,
                classicalWeakness: ClassicalWeakness.None,
                usage: usage,
                confidence: DetectionConfidence.High,
                basis: "Certificate signed with a Shor-vulnerable public-key algorithm (RSA/ECDSA/DSA); the signature can be forged by a CRQC (NIST IR 8547 DRAFT; CNSA 2.0).",
                recommendation: recommendation,
                assetType: CryptoAssetType.Certificate,
                primitive: "x509"));
        }
        else
        {
            ReportInventory(ctx, oce, "X.509 certificate request");
        }
    }

    private void InspectCertificateLoad(DetectionContext ctx, ObjectCreationExpressionSyntax oce) =>
        ReportInventory(ctx, oce, "X.509 certificate");

    /// <summary>Informational inventory: a certificate is present but its signature algorithm is not statically visible.</summary>
    private void ReportInventory(DetectionContext ctx, ObjectCreationExpressionSyntax oce, string display)
    {
        var recommendation = new Recommendation(
            "Inventory this certificate's signature and public-key algorithm at runtime to assess PQC exposure.",
            new[]
            {
                new RecommendationOption(
                    "Enumerate the chain's SignatureAlgorithm and public-key sizes; flag RSA/ECDSA leaves and roots for PQC migration planning.",
                    "NIST IR 8547 (DRAFT); CNSA 2.0.", null, null),
            });

        ctx.Report(FindingFactory.Create(
            Metadata, ctx, oce,
            displayName: display,
            quantumVulnerability: QuantumVulnerability.NotVulnerable,
            classicalWeakness: ClassicalWeakness.None,
            usage: UsageContext.Signing,
            confidence: DetectionConfidence.Medium,
            basis: "Certificate loaded; its signature/public-key algorithm is not statically visible. Recorded for inventory completeness (cannot be classified as clean).",
            recommendation: recommendation,
            assetType: CryptoAssetType.Certificate,
            method: DetectionMethod.Heuristic,
            primitive: "x509"));
    }

    /// <summary>Find an argument whose type maps to a known public-key family (the certificate's signing key).</summary>
    private static string? SigningKeyAlgorithm(DetectionContext ctx, ArgumentListSyntax args)
    {
        foreach (ArgumentSyntax arg in args.Arguments)
        {
            if (ctx.SemanticModel.GetTypeInfo(arg.Expression).Type is { } t
                && AlgorithmMap.FromTypeName(FullName(t)) is { } mapped
                && mapped is "RSA" or "ECDSA" or "ECDH" or "DSA")
            {
                return mapped;
            }
        }
        return null;
    }

    private static string? SimpleTypeName(SyntaxNode? typeOrExpr) => typeOrExpr switch
    {
        IdentifierNameSyntax id => id.Identifier.ValueText,
        QualifiedNameSyntax q => q.Right.Identifier.ValueText,
        GenericNameSyntax g => g.Identifier.ValueText,
        _ => null,
    };
}
