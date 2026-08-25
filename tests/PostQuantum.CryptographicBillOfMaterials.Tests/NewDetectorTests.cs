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
    public void DetectsMlKem_EvenWhenTypeDoesNotResolve()
    {
        // The in-box PQC types only exist on .NET 10+. When the scan host predates them (here: the net8.0
        // test compilation has no MLKem), the detector must still credit the post-quantum usage via syntactic
        // fallback — adopting PQC shouldn't go unrecorded just because of the scan SDK.
        const string src = """
            namespace App
            {
                public class C
                {
                    public object Establish() =>
                        System.Security.Cryptography.MLKem.GenerateKey(null!);
                }
            }
            """;

        CryptoFinding f = Assert.Single(Scan(src), x => x.RuleId == "CBOM0090");
        Assert.Equal("ML-KEM", f.AlgorithmName);
        Assert.Equal(QuantumVulnerability.PostQuantum, f.QuantumVulnerability);
    }

    [Fact]
    public void DoesNotFlagUserTypeSharingABclCryptoName()
    {
        // Regression: AlgorithmMap matched the bare type name, so a user type named RSA/DES/etc. in another
        // namespace was mis-flagged as the BCL algorithm. Only System.Security.Cryptography types count.
        const string src = """
            namespace Acme.Trading
            {
                public class RSA { }   // "Reservation Scheduling Adapter"
                public class DES { }   // "Data Entry System"
                public class C
                {
                    public object A() => new RSA();
                    public object B() => new DES();
                }
            }
            """;

        Assert.DoesNotContain(Scan(src), x => x.RuleId is "CBOM0002" or "CBOM0001");
    }

    [Fact]
    public void DetectsDisabledCertValidation_ViaAddAssignment()
    {
        // Regression: the detector only handled `=`, missing the common `+=` delegate subscription used with
        // ServicePointManager.ServerCertificateValidationCallback.
        const string src = """
            using System.Net;
            public class C
            {
                public void Setup() =>
                    ServicePointManager.ServerCertificateValidationCallback += (s, c, ch, e) => true;
            }
            """;

        CryptoFinding f = Assert.Single(Scan(src), x => x.RuleId == "CBOM0041");
        Assert.Equal(RiskLevel.Critical, f.RiskLevel);
    }

    [Fact]
    public void Rsa1024_IsBrokenNotMerelyDeprecated()
    {
        const string src = """
            using System.Security.Cryptography;
            public class C { public RSA M() => RSA.Create(1024); }
            """;

        CryptoFinding f = Assert.Single(Scan(src), x => x.RuleId == "CBOM0002");
        Assert.Equal(ClassicalWeakness.Broken, f.ClassicalWeakness);
    }

    [Fact]
    public void DoesNotFlagUserTypeNamedLikePqc()
    {
        // Regression: a user-defined type whose name merely starts with a PQC prefix (App.MLKemWidget) must
        // NOT be counted as in-box ML-KEM. Only System.Security.Cryptography PQC types qualify on the resolved
        // path. (Reported in chat.md #2.)
        const string src = """
            namespace App
            {
                public sealed class MLKemWidget { }
                public sealed class C { public object Make() => new MLKemWidget(); }
            }
            """;

        Assert.DoesNotContain(Scan(src), x => x.RuleId == "CBOM0090");
    }

    [Fact]
    public void DoesNotMiscreditNonPqcStaticCalls()
    {
        // Guard the syntactic fallback against false positives: a resolvable, non-PQC static call must not
        // produce a CBOM0090 positive.
        const string src = """
            using System.Security.Cryptography;
            public class C
            {
                public byte[] Hash(byte[] d) => SHA256.HashData(d);
            }
            """;

        Assert.DoesNotContain(Scan(src), x => x.RuleId == "CBOM0090");
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
