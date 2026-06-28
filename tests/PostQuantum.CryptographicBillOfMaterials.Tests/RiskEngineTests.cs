using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Risk;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Tests;

public class RiskEngineTests
{
    [Fact]
    public void SafePrimitive_ScoresZero_Informational()
    {
        RiskResult result = RiskEngine.Evaluate(new RiskInput(
            QuantumVulnerability.NotVulnerable, ClassicalWeakness.None, UsageContext.AtRest,
            DetectionConfidence.Confirmed));

        Assert.Equal(0, result.Score);
        Assert.Equal(RiskLevel.Informational, result.Level);
    }

    [Fact]
    public void LowConfidence_CannotLowerFindingBelowFloor()
    {
        // A broken hash at low confidence still cannot drop below its High floor (fail-closed).
        RiskResult result = RiskEngine.Evaluate(new RiskInput(
            QuantumVulnerability.NotVulnerable, ClassicalWeakness.Broken, UsageContext.Hashing,
            DetectionConfidence.Low, Floor: RiskLevel.High));

        Assert.Equal(RiskLevel.High, result.Level);
    }

    [Fact]
    public void RsaKeyExchange_ScoresHigh()
    {
        RiskResult result = RiskEngine.Evaluate(new RiskInput(
            QuantumVulnerability.Vulnerable, ClassicalWeakness.None, UsageContext.KeyExchange,
            DetectionConfidence.Confirmed, Floor: RiskLevel.High));

        // 0.45*1.0 + 0.20*1.0 = 0.65 -> 65
        Assert.Equal(65, result.Score);
        Assert.Equal(RiskLevel.High, result.Level);
    }

    [Fact]
    public void Floor_OnlyRaises_NeverLowers()
    {
        // Critical-by-formula finding with a Low floor stays Critical.
        RiskResult result = RiskEngine.Evaluate(new RiskInput(
            QuantumVulnerability.Vulnerable, ClassicalWeakness.Broken, UsageContext.KeyExchange,
            DetectionConfidence.Confirmed, Floor: RiskLevel.Low));

        Assert.Equal(RiskLevel.Critical, result.Level);
    }
}
