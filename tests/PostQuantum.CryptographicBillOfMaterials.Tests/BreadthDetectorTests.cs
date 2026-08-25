using PostQuantum.CryptographicBillOfMaterials.Analysis.Engine;
using PostQuantum.CryptographicBillOfMaterials.Knowledge;
using PostQuantum.CryptographicBillOfMaterials.Model;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Tests;

public class BreadthDetectorTests
{
    private static IReadOnlyList<CryptoFinding> Scan(string source)
    {
        var engine = new ScanEngine(DetectorRegistry.CreateDefault(KnowledgeBase.LoadDefault()));
        return engine.AnalyzeCompilation(TestCompilation.Create(source));
    }

    [Fact]
    public void DetectsPasswordDeriveBytes_AsHigh()
    {
        const string src = """
            using System.Security.Cryptography;
            public class C
            {
                public byte[] Derive()
                {
                    byte[] pw = new byte[8];
                    byte[] salt = new byte[8];
                    var d = new PasswordDeriveBytes(pw, salt);
                    return d.GetBytes(16);
                }
            }
            """;

        CryptoFinding f = Assert.Single(Scan(src), x => x.RuleId == "CBOM0060");
        Assert.Equal(RiskLevel.High, f.RiskLevel);
    }

    [Fact]
    public void DetectsLowIterationPbkdf2()
    {
        const string src = """
            using System.Security.Cryptography;
            public class C
            {
                public byte[] Derive()
                {
                    byte[] pw = new byte[8];
                    byte[] salt = new byte[8];
                    var d = new Rfc2898DeriveBytes(pw, salt, 1000);
                    return d.GetBytes(16);
                }
            }
            """;

        CryptoFinding f = Assert.Single(Scan(src), x => x.RuleId == "CBOM0060");
        Assert.True(f.RiskLevel >= RiskLevel.Low);
        Assert.True(f.RiskLevel < RiskLevel.High);
        Assert.Equal(ClassicalWeakness.Suboptimal, f.ClassicalWeakness);
    }

    [Fact]
    public void DoesNotFlagAdequateIterationPbkdf2()
    {
        const string src = """
            using System.Security.Cryptography;
            public class C
            {
                public byte[] Derive()
                {
                    byte[] pw = new byte[8];
                    byte[] salt = new byte[8];
                    var d = new Rfc2898DeriveBytes(pw, salt, 700000);
                    return d.GetBytes(16);
                }
            }
            """;

        Assert.DoesNotContain(Scan(src), x => x.RuleId == "CBOM0060");
    }

    [Fact]
    public void Pbkdf2_SaltSizeOverload_ReadsIterationsNotSaltSize()
    {
        // Regression: Rfc2898DeriveBytes(string, int saltSize, int iterations) puts saltSize first; the old
        // "first int arg" logic read 16 and false-flagged strong code. The iteration count (700000) is read.
        const string src = """
            using System.Security.Cryptography;
            public class C
            {
                public byte[] Derive() => new Rfc2898DeriveBytes("pw", 16, 700000).GetBytes(16);
            }
            """;

        Assert.DoesNotContain(Scan(src), x => x.RuleId == "CBOM0060");
    }

    [Fact]
    public void Pbkdf2_DefaultIterationOverload_IsFlagged()
    {
        // Regression: the (string password, byte[] salt) overload defaults to 1000 iterations (weak) but has
        // no iterations argument, so it was silently missed. It must now be flagged at the 1000 default.
        const string src = """
            using System.Security.Cryptography;
            public class C
            {
                public byte[] Derive() => new Rfc2898DeriveBytes("password", new byte[16]).GetBytes(16);
            }
            """;

        CryptoFinding f = Assert.Single(Scan(src), x => x.RuleId == "CBOM0060");
        Assert.Contains("1000", f.AlgorithmName);
    }

    [Fact]
    public void DetectsSystemRandom_AsLow()
    {
        const string src = """
            public class C
            {
                public int Roll() => new System.Random().Next();
            }
            """;

        CryptoFinding f = Assert.Single(Scan(src), x => x.RuleId == "CBOM0050");
        Assert.True(f.RiskLevel <= RiskLevel.Low);
    }
}
