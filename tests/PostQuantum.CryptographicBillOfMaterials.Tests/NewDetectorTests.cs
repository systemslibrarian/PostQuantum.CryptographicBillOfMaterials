using PostQuantum.CryptographicBillOfMaterials.Analysis.Engine;
using PostQuantum.CryptographicBillOfMaterials.Knowledge;
using PostQuantum.CryptographicBillOfMaterials.Model;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Tests;

public class NewDetectorTests
{
    private static IReadOnlyList<CryptoFinding> Scan(string source)
    {
        var engine = new ScanEngine(DetectorRegistry.CreateDefault(KnowledgeBase.LoadDefault()));
        return engine.AnalyzeCompilation(TestCompilation.Create(source));
    }

    [Fact]
    public void DetectsDisabledCertValidation_InObjectInitializer()
    {
        const string src = """
            using System.Net.Http;
            public class C
            {
                public HttpClient Make() => new HttpClient(new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = (_, _, _, _) => true
                });
            }
            """;

        CryptoFinding f = Assert.Single(Scan(src), x => x.RuleId == "CBOM0041");
        Assert.Equal(RiskLevel.Critical, f.RiskLevel);
    }

    [Fact]
    public void DetectsDeprecatedTlsProtocol()
    {
        const string src = """
            using System.Net.Http;
            using System.Security.Authentication;
            public class C
            {
                public HttpClientHandler Make() => new HttpClientHandler { SslProtocols = SslProtocols.Ssl3 };
            }
            """;

        CryptoFinding f = Assert.Single(Scan(src), x => x.RuleId == "CBOM0040");
        Assert.Equal(RiskLevel.High, f.RiskLevel);
        Assert.Equal("SSL 3.0", f.AlgorithmName);
    }

    [Fact]
    public void DetectsJwtSignatureValidationDisabled_ViaInitializer()
    {
        // Stub type named TokenValidationParameters; the detector matches by type name.
        const string src = """
            public class TokenValidationParameters
            {
                public bool RequireSignedTokens { get; set; }
                public bool ValidateIssuerSigningKey { get; set; }
            }
            public class C
            {
                public TokenValidationParameters Make() =>
                    new TokenValidationParameters { RequireSignedTokens = false };
            }
            """;

        CryptoFinding f = Assert.Single(Scan(src), x => x.RuleId == "CBOM0021");
        Assert.Equal(RiskLevel.Critical, f.RiskLevel);
        Assert.Equal(RuleCategory.Jwt, f.Category);
    }

    [Fact]
    public void ConfigFindings_DoNotCountTowardReadiness()
    {
        // A file with ONLY a TLS config issue has no quantum-relevant crypto -> readiness stays trivial/100.
        const string src = """
            using System.Net.Http;
            using System.Security.Authentication;
            public class C
            {
                public HttpClientHandler Make() => new HttpClientHandler { SslProtocols = SslProtocols.Tls11 };
            }
            """;

        IReadOnlyList<CryptoFinding> findings = Scan(src);
        Assert.Contains(findings, x => x.RuleId == "CBOM0040");
        var readiness = PostQuantum.CryptographicBillOfMaterials.Scoring.ReadinessCalculator.Calculate(findings);
        Assert.True(readiness.Trivial);
    }
}
