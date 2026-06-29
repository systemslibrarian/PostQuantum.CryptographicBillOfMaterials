using Microsoft.CodeAnalysis;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Analyzer.Tests;

/// <summary>
/// Behavioural tests for the analyzer: the in-editor surface must match the CLI engine — correct rule ids,
/// correct per-finding severity, and no noise on clean code.
/// </summary>
public class CryptoDiagnosticAnalyzerTests
{
    private const string VulnerableSource = """
        using System.Net.Http;
        using System.Security.Authentication;
        using System.Security.Cryptography;

        public static class Crypto
        {
            public static byte[] EncryptBadly(byte[] data)
            {
                using var aes = Aes.Create();
                aes.Mode = CipherMode.ECB;
                aes.Key = new byte[] { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
                using var enc = aes.CreateEncryptor();
                return enc.TransformFinalBlock(data, 0, data.Length);
            }

            public static RSA MakeKey() => RSA.Create(2048);
            public static byte[] Legacy(byte[] d) => MD5.HashData(d);
            public static byte[] Good(byte[] d) => SHA384.HashData(d);

            public static HttpClient Insecure()
            {
                var handler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
                    SslProtocols = SslProtocols.Tls,
                };
                return new HttpClient(handler);
            }
        }
        """;

    [Fact]
    public async Task VulnerableSample_ProducesExpectedRulesAndSeverities()
    {
        var diagnostics = await AnalyzerHarness.RunAsync(VulnerableSource);
        var ids = diagnostics.Select(d => d.Id).ToHashSet();

        // The high-signal rules must all fire.
        Assert.Contains("CBOM0002", ids); // RSA — quantum vulnerable
        Assert.Contains("CBOM0007", ids); // ECB mode
        Assert.Contains("CBOM0030", ids); // hardcoded key
        Assert.Contains("CBOM0041", ids); // cert validation disabled
        Assert.Contains("CBOM0010", ids); // hash usage (MD5 + SHA-384)
    }

    [Fact]
    public async Task RsaCreate_IsAQuantumVulnerableWarning()
    {
        var diagnostics = await AnalyzerHarness.RunAsync(VulnerableSource);
        Diagnostic rsa = Assert.Single(diagnostics, d => d.Id == "CBOM0002");
        Assert.Equal(DiagnosticSeverity.Warning, rsa.Severity);
        Assert.Equal(16, rsa.Line()); // RSA.Create(2048)
    }

    [Fact]
    public async Task HashRule_SeverityIsPerFinding_Md5Warning_Sha384Info()
    {
        // Regression guard: MD5 and SHA-384 share rule CBOM0010, but severity must reflect the per-finding
        // computed risk — broken MD5 is a warning, clean SHA-384 is a quiet informational hint. A single
        // rule-default severity would wrongly flatten both.
        var hashFindings = (await AnalyzerHarness.RunAsync(VulnerableSource))
            .Where(d => d.Id == "CBOM0010")
            .ToList();

        Assert.Contains(hashFindings, d => d.Severity == DiagnosticSeverity.Warning); // MD5
        Assert.Contains(hashFindings, d => d.Severity == DiagnosticSeverity.Info);     // SHA-384
    }

    [Fact]
    public async Task CleanCode_ProducesNoWarnings()
    {
        // Negative case: modern authenticated encryption with a generated key must not raise any warning.
        const string clean = """
            using System.Security.Cryptography;

            public static class Safe
            {
                public static byte[] Hash(byte[] d) => SHA384.HashData(d);
                public static (byte[], byte[]) Encrypt(byte[] data, byte[] nonce)
                {
                    using var aes = new AesGcm(RandomNumberGenerator.GetBytes(32), 16);
                    var ct = new byte[data.Length];
                    var tag = new byte[16];
                    aes.Encrypt(nonce, data, ct, tag);
                    return (ct, tag);
                }
            }
            """;

        var warnings = (await AnalyzerHarness.RunAsync(clean))
            .Where(d => d.Severity == DiagnosticSeverity.Warning)
            .ToList();

        Assert.Empty(warnings);
    }
}
