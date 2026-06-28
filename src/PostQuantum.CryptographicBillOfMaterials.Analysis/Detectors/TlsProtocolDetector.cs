using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Rules;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detectors;

/// <summary>Detects use of deprecated/insecure TLS protocol versions (SSL 2/3, TLS 1.0/1.1).</summary>
internal sealed class TlsProtocolDetector : DetectorBase
{
    private static readonly HashSet<string> Deprecated =
        new(StringComparer.Ordinal) { "Ssl2", "Ssl3", "Tls", "Tls11" };

    public override DetectorMetadata Metadata { get; } = new(
        "CBOM0040", "Deprecated TLS/SSL protocol version", RuleCategory.Tls, RiskLevel.High,
        "SSL 2.0/3.0 and TLS 1.0/1.1 are deprecated/insecure (NIST SP 800-52 Rev. 2; RFC 8996).");

    public override IReadOnlyCollection<SyntaxKind> SyntaxKinds { get; } =
        new[] { SyntaxKind.SimpleMemberAccessExpression };

    public override void Inspect(DetectionContext ctx)
    {
        var member = (MemberAccessExpressionSyntax)ctx.Node;
        string name = member.Name.Identifier.ValueText;
        if (!Deprecated.Contains(name))
            return;

        if (ctx.SemanticModel.GetSymbolInfo(member).Symbol is not IFieldSymbol field)
            return;
        if (field.ContainingType?.Name != "SslProtocols")
            return;

        bool broken = name is "Ssl2" or "Ssl3";
        string display = name switch
        {
            "Ssl2" => "SSL 2.0",
            "Ssl3" => "SSL 3.0",
            "Tls" => "TLS 1.0",
            "Tls11" => "TLS 1.1",
            _ => name,
        };

        var recommendation = new Recommendation(
            "Require TLS 1.2 or, preferably, TLS 1.3.",
            new[]
            {
                new RecommendationOption(
                    "Use SslProtocols.Tls13 (or Tls12); prefer letting the OS negotiate via SslProtocols.None.",
                    "NIST SP 800-52 Rev. 2; RFC 8996.", null, QuantumVulnerability.NotVulnerable),
            });

        ctx.Report(FindingFactory.Create(
            Metadata, ctx, ctx.Node,
            displayName: display,
            quantumVulnerability: QuantumVulnerability.NotVulnerable,
            classicalWeakness: broken ? ClassicalWeakness.Broken : ClassicalWeakness.Deprecated,
            usage: UsageContext.InTransit,
            confidence: DetectionConfidence.Confirmed,
            basis: Metadata.Basis,
            recommendation: recommendation,
            floor: RiskLevel.High,
            assetType: CryptoAssetType.Protocol,
            primitive: "tls"));
    }
}
