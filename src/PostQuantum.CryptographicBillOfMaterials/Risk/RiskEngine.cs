using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Risk;

/// <summary>Inputs to the finding-level risk formula.</summary>
public sealed record RiskInput(
    QuantumVulnerability QuantumVulnerability,
    ClassicalWeakness ClassicalWeakness,
    UsageContext UsageContext,
    DetectionConfidence Confidence,
    RiskLevel? Floor = null);

/// <summary>Result of scoring a finding.</summary>
public sealed record RiskResult(int Score, RiskLevel Level);

/// <summary>
/// Transparent, deterministic finding-level risk scoring (TDD §5.1). Every factor is a pure function
/// so any score can be recomputed by hand from the CBOM. Floors can only raise a level, never lower it,
/// and detection confidence can never push a finding below its floor (fail-closed).
/// </summary>
public static class RiskEngine
{
    /// <summary>Version of the scoring formula, recorded in the CBOM for reproducibility.</summary>
    public const string FormulaVersion = "1.0";

    /// <summary>Quantum factor Q (TDD §5.1).</summary>
    public static double QuantumFactor(QuantumVulnerability v) => v switch
    {
        QuantumVulnerability.Vulnerable => 1.0,
        QuantumVulnerability.ReducedMargin => 0.4,
        _ => 0.0,
    };

    /// <summary>Classical-weakness factor C (TDD §5.1).</summary>
    public static double ClassicalFactor(ClassicalWeakness w) => w switch
    {
        ClassicalWeakness.Broken => 1.0,
        ClassicalWeakness.Deprecated => 0.7,
        ClassicalWeakness.Suboptimal => 0.4,
        _ => 0.0,
    };

    /// <summary>Usage-exposure factor X (TDD §5.1).</summary>
    public static double ExposureFactor(UsageContext u) => u switch
    {
        UsageContext.KeyExchange or UsageContext.InTransit or UsageContext.AtRest => 1.0,
        UsageContext.Signing or UsageContext.Auth => 0.7,
        UsageContext.Hashing => 0.4,
        _ => 0.6,
    };

    /// <summary>Confidence adjustment, clamped to [0.9, 1.0] so it can never hide a high-risk finding.</summary>
    public static double ConfidenceAdjustment(DetectionConfidence c) => c switch
    {
        DetectionConfidence.Confirmed or DetectionConfidence.High => 1.0,
        DetectionConfidence.Medium => 0.95,
        _ => 0.9,
    };

    /// <summary>Map a 0–100 score to a level.</summary>
    public static RiskLevel Band(int score) => score switch
    {
        >= 80 => RiskLevel.Critical,
        >= 60 => RiskLevel.High,
        >= 40 => RiskLevel.Medium,
        >= 20 => RiskLevel.Low,
        _ => RiskLevel.Informational,
    };

    /// <summary>Score and classify a finding.</summary>
    public static RiskResult Evaluate(RiskInput input)
    {
        double q = QuantumFactor(input.QuantumVulnerability);
        double c = ClassicalFactor(input.ClassicalWeakness);
        double x = ExposureFactor(input.UsageContext);

        // A primitive that is strong on BOTH axes carries no inherent risk regardless of exposure:
        // exposure of safe crypto is not a finding. (Refinement to the additive formula in TDD §5.1.)
        double raw = (q <= 0 && c <= 0)
            ? 0.0
            : Clamp01(0.45 * q + 0.35 * c + 0.20 * x) * ConfidenceAdjustment(input.Confidence);

        int score = (int)Math.Round(100 * raw, MidpointRounding.AwayFromZero);
        RiskLevel level = Band(score);

        // Floors apply AFTER banding, so they can only raise. Confidence cannot lower past a floor.
        if (input.Floor is { } floor && floor > level)
            level = floor;

        return new RiskResult(score, level);
    }

    private static double Clamp01(double v) => v < 0 ? 0 : v > 1 ? 1 : v;
}
