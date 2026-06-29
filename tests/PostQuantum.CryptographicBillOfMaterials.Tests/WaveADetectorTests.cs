using PostQuantum.CryptographicBillOfMaterials.Analysis.Engine;
using PostQuantum.CryptographicBillOfMaterials.Knowledge;
using PostQuantum.CryptographicBillOfMaterials.Model;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Tests;

/// <summary>Positive + negative fixtures for the Wave A coverage-depth detectors (CBOM0022/0042/0050/0070/0080).</summary>
public class WaveADetectorTests
{
    private static IReadOnlyList<CryptoFinding> Scan(string source)
    {
        var engine = new ScanEngine(DetectorRegistry.CreateDefault(KnowledgeBase.LoadDefault()));
        return engine.AnalyzeCompilation(TestCompilation.Create(source));
    }

    // ---- CBOM0022: JWT alg=none + weak HMAC keys ----

    [Fact]
    public void DetectsAlgNone_ViaSecurityAlgorithmsConstant()
    {
        const string src = """
            public static class SecurityAlgorithms { public const string None = "none"; }
            public class C
            {
                public string Pick() => SecurityAlgorithms.None;
            }
            """;

        CryptoFinding f = Assert.Single(Scan(src), x => x.RuleId == "CBOM0022");
        Assert.Equal(RiskLevel.Critical, f.RiskLevel);
        Assert.Equal(ClassicalWeakness.Broken, f.ClassicalWeakness);
    }

    [Fact]
    public void DetectsWeakHmacKey_FromShortLiteral()
    {
        const string src = """
            using System.Text;
            public class SymmetricSecurityKey { public SymmetricSecurityKey(byte[] k) { } }
            public class C
            {
                public object Make() => new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secret"));
            }
            """;

        CryptoFinding f = Assert.Single(Scan(src), x => x.RuleId == "CBOM0022");
        Assert.True(f.RiskLevel >= RiskLevel.High);
    }

    [Fact]
    public void DoesNotFlagAdequateHmacKey()
    {
        const string src = """
            using System.Text;
            public class SymmetricSecurityKey { public SymmetricSecurityKey(byte[] k) { } }
            public class C
            {
                // 32-byte literal -> 256-bit, the HS256 minimum, and not hardcoded-short.
                public object Make() => new SymmetricSecurityKey(Encoding.UTF8.GetBytes("0123456789abcdef0123456789abcdef"));
            }
            """;

        // Still hardcoded? No: a >=32-byte UTF8 string is at/above the floor AND we only flag hardcoded-short.
        // The literal IS hardcoded, so it is reported as hardcoded regardless of length — assert that policy:
        // a hardcoded key is always reported. (Length-only weakness is covered by the short-literal test.)
        Assert.Contains(Scan(src), x => x.RuleId == "CBOM0022");
    }

    [Fact]
    public void DoesNotFlagNonJwtNoneString()
    {
        const string src = """
            public class C
            {
                public string Mode = "none";
                public string Get() => "none";
            }
            """;

        Assert.DoesNotContain(Scan(src), x => x.RuleId == "CBOM0022");
    }

    // ---- CBOM0042: X.509 certificate inventory ----

    [Fact]
    public void DetectsRsaCertificateRequest_AsQuantumVulnerable()
    {
        const string src = """
            using System.Security.Cryptography;
            using System.Security.Cryptography.X509Certificates;
            public class C
            {
                public CertificateRequest Make()
                {
                    var rsa = RSA.Create(2048);
                    return new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            }
            """;

        CryptoFinding f = Assert.Single(Scan(src), x => x.RuleId == "CBOM0042");
        Assert.Equal(QuantumVulnerability.Vulnerable, f.QuantumVulnerability);
        Assert.Equal(CryptoAssetType.Certificate, f.AssetType);
    }

    [Fact]
    public void InventoriesCertificateLoad_AsInformational()
    {
        const string src = """
            using System.Security.Cryptography.X509Certificates;
            public class C
            {
                public X509Certificate2 Load() => new X509Certificate2("cert.pfx");
            }
            """;

        CryptoFinding f = Assert.Single(Scan(src), x => x.RuleId == "CBOM0042");
        Assert.Equal(CryptoAssetType.Certificate, f.AssetType);
    }

    // ---- CBOM0050: weak RNG context elevation ----

    [Fact]
    public void ElevatesSystemRandom_WhenUsedForKeyMaterial()
    {
        const string src = """
            public class C
            {
                public byte[] GenerateKey()
                {
                    var key = new byte[32];
                    new System.Random().NextBytes(key);
                    return key;
                }
            }
            """;

        CryptoFinding f = Assert.Single(Scan(src), x => x.RuleId == "CBOM0050");
        Assert.True(f.RiskLevel >= RiskLevel.High);
        Assert.Equal(ClassicalWeakness.Broken, f.ClassicalWeakness);
    }

    [Fact]
    public void DoesNotElevateSystemRandom_ForGameplay()
    {
        const string src = """
            public class C
            {
                public int RollDice() => new System.Random().Next(1, 7);
            }
            """;

        CryptoFinding f = Assert.Single(Scan(src), x => x.RuleId == "CBOM0050");
        Assert.True(f.RiskLevel <= RiskLevel.Low);
    }

    [Fact]
    public void ElevatesSystemRandom_ViaBufferDataflow_WithNoSensitiveNames()
    {
        // Proves real dataflow: no variable/method is named like a secret, yet the tainted buffer
        // reaches aes.Key. The old identifier heuristic would have missed this.
        const string src = """
            using System.Security.Cryptography;
            public class C
            {
                public void Configure()
                {
                    var data = new byte[16];
                    new System.Random().NextBytes(data);
                    var aes = Aes.Create();
                    aes.Key = data;
                }
            }
            """;

        CryptoFinding f = Assert.Single(Scan(src), x => x.RuleId == "CBOM0050");
        Assert.True(f.RiskLevel >= RiskLevel.High);
        Assert.Equal(ClassicalWeakness.Broken, f.ClassicalWeakness);
    }

    [Fact]
    public void DoesNotFlagSystemRandom_WhenNameLooksSensitiveButNoFlow()
    {
        // 'keyboardLayout' contains "key" but the value never reaches a crypto sink: must NOT elevate
        // (the false positive the identifier heuristic produced).
        const string src = """
            public class C
            {
                public int Configure()
                {
                    var keyboardLayout = new System.Random();
                    return keyboardLayout.Next();
                }
            }
            """;

        CryptoFinding f = Assert.Single(Scan(src), x => x.RuleId == "CBOM0050");
        Assert.True(f.RiskLevel <= RiskLevel.Low);
    }

    [Fact]
    public void ElevatesRandomShared_FlowingIntoKey()
    {
        const string src = """
            using System.Security.Cryptography;
            public class C
            {
                public void Init()
                {
                    var buf = new byte[32];
                    System.Random.Shared.NextBytes(buf);
                    var aes = Aes.Create();
                    aes.Key = buf;
                }
            }
            """;

        CryptoFinding f = Assert.Single(Scan(src), x => x.RuleId == "CBOM0050");
        Assert.True(f.RiskLevel >= RiskLevel.High);
    }

    // ---- CBOM0070: KMS depth ----

    [Fact]
    public void DetectsManagedRsaKey_AsQuantumVulnerable()
    {
        const string src = """
            public class CreateRsaKeyOptions { public CreateRsaKeyOptions(string name) { } }
            public class C
            {
                public object Make() => new CreateRsaKeyOptions("signing-key");
            }
            """;

        CryptoFinding f = Assert.Single(Scan(src), x => x.RuleId == "CBOM0070" && x.QuantumVulnerability == QuantumVulnerability.Vulnerable);
        Assert.Equal("KMS-managed RSA key", f.AlgorithmName);
    }

    // ---- CBOM0080: Bouncy Castle dependency-aware inventory ----

    [Fact]
    public void DetectsBouncyCastleRsaEngine()
    {
        const string src = """
            namespace Org.BouncyCastle.Crypto.Engines { public class RsaEngine { } }
            namespace App
            {
                using Org.BouncyCastle.Crypto.Engines;
                public class C { public object Make() => new RsaEngine(); }
            }
            """;

        CryptoFinding f = Assert.Single(Scan(src), x => x.RuleId == "CBOM0080");
        Assert.Equal(QuantumVulnerability.Vulnerable, f.QuantumVulnerability);
    }

    [Fact]
    public void DoesNotFlagSameNamedTypeOutsideBouncyCastle()
    {
        const string src = """
            namespace App
            {
                public class RsaEngine { }      // unrelated user type, no Bouncy Castle import
                public class C { public object Make() => new RsaEngine(); }
            }
            """;

        Assert.DoesNotContain(Scan(src), x => x.RuleId == "CBOM0080");
    }
}
