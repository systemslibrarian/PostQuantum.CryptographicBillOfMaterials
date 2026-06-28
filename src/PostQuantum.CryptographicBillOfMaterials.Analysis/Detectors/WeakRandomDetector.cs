using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Rules;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detectors;

/// <summary>
/// Detects construction of <c>System.Random</c>, a non-cryptographic RNG. Base case is low-noise (a weak
/// RNG for gameplay is not a vulnerability), but when the surrounding code suggests the random material
/// flows into a key, token, IV, nonce, salt, or password the finding is elevated to a real weakness — the
/// distinction the roadmap calls for (CWE-338).
/// </summary>
internal sealed class WeakRandomDetector : DetectorBase
{
    private const string SystemRandomType = "System.Random";

    /// <summary>Identifier substrings that indicate the random output is security-sensitive material.</summary>
    private static readonly string[] SensitiveTokens =
    {
        "key", "secret", "token", "password", "passwd", "pwd", "iv", "nonce", "salt",
        "otp", "apikey", "session", "credential", "cipher", "crypto", "sign",
    };

    public override DetectorMetadata Metadata { get; } = new(
        "CBOM0050", "Non-cryptographic random number generator", RuleCategory.Randomness, RiskLevel.Low,
        "System.Random is not cryptographically secure; use RandomNumberGenerator for security-sensitive values (CWE-338).");

    public override IReadOnlyCollection<SyntaxKind> SyntaxKinds { get; } =
        new[] { SyntaxKind.ObjectCreationExpression };

    public override void Inspect(DetectionContext ctx)
    {
        ITypeSymbol? type = ResolveInstantiatedType(ctx);
        if (type is null || FullName(type) != SystemRandomType)
            return;

        bool sensitive = FlowsIntoSensitiveMaterial(ctx.Node);

        const string baseBasis =
            "System.Random is not cryptographically secure; if used for keys/tokens/IVs use RandomNumberGenerator (CWE-338).";
        const string sensitiveBasis =
            "System.Random output flows into security-sensitive material (key/token/IV/nonce/salt). Its 31-bit, "
            + "predictable, seedable state makes the produced secret recoverable (CWE-338, CWE-330).";

        string basis = sensitive ? sensitiveBasis : baseBasis;

        var recommendation = new Recommendation(
            sensitive
                ? "Replace System.Random with a cryptographically secure RNG for this secret material."
                : "For any security-sensitive values, use a cryptographically secure RNG.",
            new[]
            {
                new RecommendationOption(
                    "Use System.Security.Cryptography.RandomNumberGenerator (e.g., GetBytes/GetInt32) for keys, tokens, salts, IVs, and nonces.",
                    basis, null, QuantumVulnerability.NotVulnerable),
            });

        ctx.Report(FindingFactory.Create(
            Metadata, ctx, ctx.Node,
            displayName: sensitive
                ? "System.Random for security-sensitive material"
                : "System.Random (non-cryptographic RNG)",
            quantumVulnerability: QuantumVulnerability.NotVulnerable,
            classicalWeakness: sensitive ? ClassicalWeakness.Broken : ClassicalWeakness.Suboptimal,
            usage: sensitive ? UsageContext.Auth : UsageContext.Unknown,
            confidence: sensitive ? DetectionConfidence.High : DetectionConfidence.Medium,
            basis: basis,
            recommendation: recommendation,
            floor: sensitive ? RiskLevel.High : null,
            assetType: CryptoAssetType.RelatedCryptoMaterial,
            method: DetectionMethod.Heuristic,
            primitive: "rng"));
    }

    /// <summary>
    /// Heuristic: does the enclosing method, the variable the RNG is stored in, or any identifier in the
    /// enclosing statement name security-sensitive material? Scoped to the enclosing member to stay low-FP.
    /// </summary>
    private static bool FlowsIntoSensitiveMaterial(SyntaxNode node)
    {
        // 1. The variable the new Random() initializes, or the assignment target.
        for (SyntaxNode? n = node.Parent; n is not null; n = n.Parent)
        {
            switch (n)
            {
                case VariableDeclaratorSyntax v when NameIsSensitive(v.Identifier.ValueText):
                    return true;
                case AssignmentExpressionSyntax a when ExpressionNameIsSensitive(a.Left):
                    return true;
                case StatementSyntax stmt:
                    if (stmt.DescendantTokens().Any(t =>
                            t.IsKind(SyntaxKind.IdentifierToken) && NameIsSensitive(t.ValueText)))
                        return true;
                    goto checkMember;
            }
        }

    checkMember:
        // 2. The enclosing member name (e.g., GenerateKey, CreateToken).
        SyntaxNode? member = node.FirstAncestorOrSelf<MemberDeclarationSyntax>();
        return member switch
        {
            MethodDeclarationSyntax m => NameIsSensitive(m.Identifier.ValueText),
            PropertyDeclarationSyntax p => NameIsSensitive(p.Identifier.ValueText),
            _ => false,
        };
    }

    private static bool ExpressionNameIsSensitive(ExpressionSyntax expr) => expr switch
    {
        IdentifierNameSyntax id => NameIsSensitive(id.Identifier.ValueText),
        MemberAccessExpressionSyntax m => NameIsSensitive(m.Name.Identifier.ValueText),
        _ => false,
    };

    private static bool NameIsSensitive(string name)
    {
        foreach (string token in SensitiveTokens)
            if (name.Contains(token, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }
}
