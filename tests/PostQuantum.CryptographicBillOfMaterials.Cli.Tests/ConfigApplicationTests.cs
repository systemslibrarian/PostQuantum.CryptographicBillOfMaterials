using PostQuantum.CryptographicBillOfMaterials.Cli;
using PostQuantum.CryptographicBillOfMaterials.Configuration;
using PostQuantum.CryptographicBillOfMaterials.Model;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Cli.Tests;

/// <summary>Policy-profile, waiver, per-algorithm, and data-sensitivity behavior of the config pipeline.</summary>
public class ConfigApplicationTests
{
    private static CryptoFinding Finding(
        string rule, string algo, RiskLevel level,
        QuantumVulnerability qv = QuantumVulnerability.NotVulnerable,
        UsageContext usage = UsageContext.Unknown,
        string file = "src/App/Crypto.cs", string? ns = null) =>
        new()
        {
            RuleId = rule,
            Title = "t",
            Category = RuleCategory.SymmetricEncryption,
            AlgorithmName = algo,
            RiskBasis = "basis",
            RiskLevel = level,
            QuantumVulnerability = qv,
            UsageContext = usage,
            Location = new SourceLocation(file, 1, null, ns),
            BomRef = $"crypto/{algo}/{rule}",
        };

    private static ConfigApplicationResult Apply(
        IReadOnlyList<CryptoFinding> findings, CbomConfig? config, string profile) =>
        ConfigApplication.Apply(findings, config, PolicyProfile.Get(profile), new List<string>());

    [Fact]
    public void Cnsa2_ElevatesReducedMargin_ToHigh()
    {
        var f = Finding("CBOM0003", "AES-128", RiskLevel.Medium, QuantumVulnerability.ReducedMargin);
        var result = Apply(new[] { f }, null, "cnsa2");
        Assert.Equal(RiskLevel.High, result.Findings[0].RiskLevel);
        Assert.Equal(1, result.Summary.ElevatedByPolicyProfile);
        Assert.Equal("cnsa2", result.Findings[0].PolicyProfile);
    }

    [Fact]
    public void Federal_ElevatesQuantumVulnerable_ToHigh()
    {
        var f = Finding("CBOM0002", "RSA", RiskLevel.Medium, QuantumVulnerability.Vulnerable);
        var result = Apply(new[] { f }, null, "federal");
        Assert.Equal(RiskLevel.High, result.Findings[0].RiskLevel);
    }

    [Fact]
    public void Profiles_NeverLowerRisk()
    {
        var f = Finding("CBOM0002", "RSA", RiskLevel.Critical, QuantumVulnerability.Vulnerable);
        foreach (string profile in PolicyProfile.Names)
            Assert.Equal(RiskLevel.Critical, Apply(new[] { f }, null, profile).Findings[0].RiskLevel);
    }

    [Fact]
    public void Waiver_Suppresses_UnderGeneral_AndRecords()
    {
        var config = new CbomConfig
        {
            Rules = new() { ["CBOM0010"] = new RuleConfig { Enabled = false, WaiverJustification = "legacy", WaiverApprover = "ciso" } },
        };
        var result = Apply(new[] { Finding("CBOM0010", "MD5", RiskLevel.High) }, config, "general");

        Assert.Empty(result.Findings);
        Assert.Equal(1, result.Summary.SuppressedByDisabledRule);
        WaiverRecord w = Assert.Single(result.Summary.Waivers);
        Assert.True(w.Suppressed);
        Assert.Equal("legacy", w.Justification);
    }

    [Fact]
    public void Waiver_Annotates_UnderAudit()
    {
        var config = new CbomConfig
        {
            Rules = new() { ["CBOM0010"] = new RuleConfig { Enabled = false, WaiverJustification = "accepted risk" } },
        };
        var result = Apply(new[] { Finding("CBOM0010", "MD5", RiskLevel.High) }, config, "audit");

        CryptoFinding kept = Assert.Single(result.Findings);
        Assert.Equal(RemediationStatus.Waived, kept.Status);
        Assert.Equal("accepted risk", kept.WaiverJustification);
        Assert.False(Assert.Single(result.Summary.Waivers).Suppressed);
    }

    [Fact]
    public void ExpiredWaiver_ReactivatesFinding()
    {
        var config = new CbomConfig
        {
            Rules = new() { ["CBOM0010"] = new RuleConfig { Enabled = false, WaiverExpiry = "2000-01-01" } },
        };
        var result = Apply(new[] { Finding("CBOM0010", "MD5", RiskLevel.High) }, config, "general");

        CryptoFinding kept = Assert.Single(result.Findings);
        Assert.NotEqual(RemediationStatus.Waived, kept.Status);
        Assert.True(Assert.Single(result.Summary.Waivers).Expired);
    }

    [Fact]
    public void PerAlgorithm_Floor_RaisesOnlyMatchingAlgorithm()
    {
        var config = new CbomConfig
        {
            Rules = new()
            {
                ["CBOM0010"] = new RuleConfig
                {
                    Algorithms = new() { ["MD5"] = new RuleConfig { SeverityFloor = "critical" } },
                },
            },
        };
        var findings = new[]
        {
            Finding("CBOM0010", "MD5", RiskLevel.High),
            Finding("CBOM0010", "SHA-256", RiskLevel.Informational),
        };
        var result = Apply(findings, config, "general");

        Assert.Equal(RiskLevel.Critical, result.Findings.Single(f => f.AlgorithmName == "MD5").RiskLevel);
        Assert.Equal(RiskLevel.Informational, result.Findings.Single(f => f.AlgorithmName == "SHA-256").RiskLevel);
    }

    [Fact]
    public void DataSensitivity_PathHint_ElevatesToCritical()
    {
        var config = new CbomConfig
        {
            DataSensitivityHints = new() { ["src/App/**"] = new DataSensitivityHint { DataLifetimeYears = 25 } },
        };
        var f = Finding("CBOM0002", "RSA", RiskLevel.High, QuantumVulnerability.Vulnerable, UsageContext.AtRest);
        var result = Apply(new[] { f }, config, "general");

        Assert.Equal(RiskLevel.Critical, result.Findings[0].RiskLevel);
        Assert.Equal(1, result.Summary.ElevatedByDataSensitivity);
    }

    [Fact]
    public void DataSensitivity_NamespaceHint_ElevatesToCritical()
    {
        var config = new CbomConfig
        {
            DataSensitivityHints = new() { ["ns:Contoso.Billing.*"] = new DataSensitivityHint { DataLifetimeYears = 30 } },
        };
        var f = Finding("CBOM0002", "RSA", RiskLevel.High, QuantumVulnerability.Vulnerable,
            UsageContext.KeyExchange, ns: "Contoso.Billing.Vault");
        var result = Apply(new[] { f }, config, "general");

        Assert.Equal(RiskLevel.Critical, result.Findings[0].RiskLevel);
    }
}
