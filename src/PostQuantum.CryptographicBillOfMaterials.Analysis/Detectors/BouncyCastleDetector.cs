using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Rules;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detectors;

/// <summary>
/// Dependency-aware inventory for Bouncy Castle (<c>Org.BouncyCastle.*</c>), the most common third-party
/// .NET crypto provider. Bouncy Castle types frequently do not resolve in the no-MSBuild fallback scan, so
/// this detector matches by type name gated on a Bouncy Castle <c>using</c>/namespace, then classifies the
/// primitive. This makes crypto that lives outside the BCL visible to the inventory (CWE-only otherwise).
/// </summary>
internal sealed class BouncyCastleDetector : DetectorBase
{
    private readonly record struct Verdict(
        string Name,
        string Primitive,
        QuantumVulnerability Quantum,
        ClassicalWeakness Classical,
        UsageContext Usage,
        string Basis);

    // Curated map of Bouncy Castle engine/signer/digest types to a documented verdict.
    private static readonly Dictionary<string, Verdict> Types = new(StringComparer.Ordinal)
    {
        ["RsaEngine"] = new("RSA (Bouncy Castle)", "rsa", QuantumVulnerability.Vulnerable, ClassicalWeakness.None, UsageContext.KeyExchange, "RSA is broken by Shor's algorithm (NIST IR 8547 DRAFT; CNSA 2.0)."),
        ["RsaBlindedEngine"] = new("RSA (Bouncy Castle)", "rsa", QuantumVulnerability.Vulnerable, ClassicalWeakness.None, UsageContext.KeyExchange, "RSA is broken by Shor's algorithm (NIST IR 8547 DRAFT; CNSA 2.0)."),
        ["Pkcs1Encoding"] = new("RSA (Bouncy Castle)", "rsa", QuantumVulnerability.Vulnerable, ClassicalWeakness.None, UsageContext.KeyExchange, "RSA is broken by Shor's algorithm (NIST IR 8547 DRAFT; CNSA 2.0)."),
        ["OaepEncoding"] = new("RSA-OAEP (Bouncy Castle)", "rsa", QuantumVulnerability.Vulnerable, ClassicalWeakness.None, UsageContext.KeyExchange, "RSA is broken by Shor's algorithm (NIST IR 8547 DRAFT; CNSA 2.0)."),
        ["ECDsaSigner"] = new("ECDSA (Bouncy Castle)", "ecdsa", QuantumVulnerability.Vulnerable, ClassicalWeakness.None, UsageContext.Signing, "ECDSA is broken by Shor's algorithm (NIST IR 8547 DRAFT; CNSA 2.0)."),
        ["ECKeyPairGenerator"] = new("EC key (Bouncy Castle)", "ec", QuantumVulnerability.Vulnerable, ClassicalWeakness.None, UsageContext.KeyExchange, "Elliptic-curve crypto is broken by Shor's algorithm (NIST IR 8547 DRAFT; CNSA 2.0)."),
        ["Ed25519Signer"] = new("Ed25519 (Bouncy Castle)", "eddsa", QuantumVulnerability.Vulnerable, ClassicalWeakness.None, UsageContext.Signing, "EdDSA (Ed25519) is an elliptic-curve signature broken by Shor's algorithm (NIST IR 8547 DRAFT)."),
        ["Ed448Signer"] = new("Ed448 (Bouncy Castle)", "eddsa", QuantumVulnerability.Vulnerable, ClassicalWeakness.None, UsageContext.Signing, "EdDSA (Ed448) is an elliptic-curve signature broken by Shor's algorithm (NIST IR 8547 DRAFT)."),
        ["DsaSigner"] = new("DSA (Bouncy Castle)", "dsa", QuantumVulnerability.Vulnerable, ClassicalWeakness.None, UsageContext.Signing, "DSA is broken by Shor's algorithm (NIST IR 8547 DRAFT)."),
        ["DHBasicAgreement"] = new("Diffie-Hellman (Bouncy Castle)", "dh", QuantumVulnerability.Vulnerable, ClassicalWeakness.None, UsageContext.KeyExchange, "Finite-field Diffie-Hellman is broken by Shor's algorithm (NIST IR 8547 DRAFT)."),
        ["ECDHBasicAgreement"] = new("ECDH (Bouncy Castle)", "ecdh", QuantumVulnerability.Vulnerable, ClassicalWeakness.None, UsageContext.KeyExchange, "ECDH is broken by Shor's algorithm (NIST IR 8547 DRAFT; CNSA 2.0)."),
        ["MD5Digest"] = new("MD5 (Bouncy Castle)", "hash", QuantumVulnerability.NotVulnerable, ClassicalWeakness.Broken, UsageContext.Hashing, "MD5 is collision-broken and must not be used (RFC 6151; SP 800-131A)."),
        ["Sha1Digest"] = new("SHA-1 (Bouncy Castle)", "hash", QuantumVulnerability.NotVulnerable, ClassicalWeakness.Broken, UsageContext.Hashing, "SHA-1 is collision-broken (SHATTERED; SP 800-131A)."),
        ["DesEngine"] = new("DES (Bouncy Castle)", "block-cipher", QuantumVulnerability.NotVulnerable, ClassicalWeakness.Broken, UsageContext.AtRest, "DES has a 56-bit key and is brute-forceable (SP 800-131A)."),
        ["DesEdeEngine"] = new("3DES (Bouncy Castle)", "block-cipher", QuantumVulnerability.NotVulnerable, ClassicalWeakness.Deprecated, UsageContext.AtRest, "3DES is deprecated and disallowed after 2023 (SP 800-131A Rev. 2)."),
        ["RC4Engine"] = new("RC4 (Bouncy Castle)", "stream-cipher", QuantumVulnerability.NotVulnerable, ClassicalWeakness.Broken, UsageContext.InTransit, "RC4 is broken and prohibited (RFC 7465)."),
    };

    // PQC types are a positive signal; recorded separately so they raise readiness.
    private static readonly Dictionary<string, string> PqcTypes = new(StringComparer.Ordinal)
    {
        ["MLKemKeyPairGenerator"] = "ML-KEM",
        ["KyberKeyPairGenerator"] = "ML-KEM (Kyber)",
        ["MLDsaSigner"] = "ML-DSA",
        ["DilithiumSigner"] = "ML-DSA (Dilithium)",
        ["SlhDsaSigner"] = "SLH-DSA",
        ["SphincsPlusSigner"] = "SLH-DSA (SPHINCS+)",
    };

    public override DetectorMetadata Metadata { get; } = new(
        "CBOM0080", "Bouncy Castle cryptography", RuleCategory.AsymmetricEncryption, RiskLevel.High,
        "Crypto performed via the Bouncy Castle provider is inventoried by type; RSA/EC/DSA/EdDSA are Shor-vulnerable.");

    public override IReadOnlyCollection<SyntaxKind> SyntaxKinds { get; } =
        new[] { SyntaxKind.ObjectCreationExpression };

    public override void Inspect(DetectionContext ctx)
    {
        var oce = (ObjectCreationExpressionSyntax)ctx.Node;
        string? typeName = SimpleTypeName(oce.Type);
        if (typeName is null)
            return;

        bool known = Types.ContainsKey(typeName) || PqcTypes.ContainsKey(typeName);
        if (!known)
            return;

        // Confirm Bouncy Castle to avoid colliding with same-named user types: either the symbol resolves
        // into Org.BouncyCastle, or the file imports a Bouncy Castle namespace.
        if (!IsBouncyCastle(ctx, oce))
            return;

        if (PqcTypes.TryGetValue(typeName, out string? pqcName))
        {
            ReportPqc(ctx, oce, pqcName);
            return;
        }

        Verdict v = Types[typeName];
        RiskLevel? floor = v.Classical == ClassicalWeakness.Broken ? RiskLevel.High : null;

        var recommendation = new Recommendation(
            v.Quantum == QuantumVulnerability.Vulnerable
                ? "Plan migration of this Bouncy Castle public-key usage to a NIST PQC algorithm."
                : "Replace this weak/legacy Bouncy Castle primitive with a current standard.",
            new[]
            {
                new RecommendationOption(
                    v.Quantum == QuantumVulnerability.Vulnerable
                        ? "Move to ML-KEM (FIPS 203) for key establishment or ML-DSA/SLH-DSA (FIPS 204/205) for signatures, optionally in a hybrid with the classical algorithm during transition."
                        : "Use AES-256-GCM / SHA-256+ via the platform's validated crypto; remove the broken/legacy primitive.",
                    v.Basis, null,
                    v.Quantum == QuantumVulnerability.Vulnerable ? QuantumVulnerability.PostQuantum : QuantumVulnerability.NotVulnerable),
            });

        ctx.Report(FindingFactory.Create(
            Metadata, ctx, oce,
            displayName: v.Name,
            quantumVulnerability: v.Quantum,
            classicalWeakness: v.Classical,
            usage: v.Usage,
            confidence: DetectionConfidence.High,
            basis: v.Basis,
            recommendation: recommendation,
            floor: floor,
            assetType: CryptoAssetType.Algorithm,
            method: DetectionMethod.Heuristic,
            primitive: v.Primitive));
    }

    private void ReportPqc(DetectionContext ctx, ObjectCreationExpressionSyntax oce, string name)
    {
        ctx.Report(FindingFactory.Create(
            Metadata, ctx, oce,
            displayName: $"{name} (Bouncy Castle)",
            quantumVulnerability: QuantumVulnerability.PostQuantum,
            classicalWeakness: ClassicalWeakness.None,
            usage: UsageContext.KeyExchange,
            confidence: DetectionConfidence.High,
            basis: "NIST-standardized post-quantum algorithm via Bouncy Castle (FIPS 203/204/205). Positive signal.",
            recommendation: Recommendation.None,
            assetType: CryptoAssetType.Algorithm,
            method: DetectionMethod.Heuristic,
            primitive: "pqc"));
    }

    private static bool IsBouncyCastle(DetectionContext ctx, ObjectCreationExpressionSyntax oce)
    {
        if (ctx.SemanticModel.GetSymbolInfo(oce).Symbol is IMethodSymbol ctor)
        {
            string ns = ctor.ContainingType.ContainingNamespace?.ToDisplayString() ?? string.Empty;
            if (ns.StartsWith("Org.BouncyCastle", StringComparison.Ordinal))
                return true;
            // If the type resolved to a non-BouncyCastle namespace, it is a same-named user type: skip.
            if (!string.IsNullOrEmpty(ns))
                return false;
        }

        // Unresolved (typical in the fallback scan): accept if the file imports Bouncy Castle.
        SyntaxNode root = oce.SyntaxTree.GetRoot();
        return root.DescendantNodes().OfType<UsingDirectiveSyntax>()
            .Any(u => u.Name?.ToString().StartsWith("Org.BouncyCastle", StringComparison.Ordinal) == true);
    }

    private static string? SimpleTypeName(SyntaxNode? type) => type switch
    {
        IdentifierNameSyntax id => id.Identifier.ValueText,
        QualifiedNameSyntax q => q.Right.Identifier.ValueText,
        GenericNameSyntax g => g.Identifier.ValueText,
        _ => null,
    };
}
