using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Risk;

namespace PostQuantum.CryptographicBillOfMaterials.Scoring;

/// <summary>The PQC Readiness Score and the arithmetic behind it (shown verbatim in reports).</summary>
public sealed record ReadinessResult(int Score, bool Trivial, double SafeWeight, double TotalWeight);

/// <summary>
/// Transparent PQC Readiness Score (TDD §5.2): of the cryptography we can see that quantum matters for,
/// how much is already quantum-safe? Only quantum-relevant algorithm/protocol findings count; classical-only
/// findings (e.g., hardcoded keys, cipher-mode misuse) are reported separately and excluded here.
/// </summary>
public static class ReadinessCalculator
{
    public const string FormulaVersion = "1.0";

    /// <summary>Base weight by quantum verdict; hybrid PQC earns a small bonus toward the recommended end state.</summary>
    public static double BaseWeight(CryptoFinding f) => f.QuantumVulnerability switch
    {
        QuantumVulnerability.Vulnerable => 1.0,
        QuantumVulnerability.ReducedMargin => 0.5,
        QuantumVulnerability.PostQuantum => f.IsHybrid ? 1.1 : 1.0,
        QuantumVulnerability.NotVulnerable => 1.0,
        _ => 0.0,
    };

    /// <summary>
    /// A finding counts toward readiness only if it represents a quantum-relevant algorithm/protocol.
    /// Classical-only or configuration findings (cipher-mode misuse, hardcoded secrets, JWT/TLS config,
    /// weak randomness) are reported separately and excluded so they neither help nor hurt the PQC score.
    /// </summary>
    public static bool IsQuantumRelevant(CryptoFinding f) =>
        f.AssetType is CryptoAssetType.Algorithm or CryptoAssetType.Protocol
        && f.Primitive != "block-cipher-mode"
        && f.Category is not (RuleCategory.Jwt or RuleCategory.Tls
            or RuleCategory.HardcodedSecret or RuleCategory.Randomness);

    /// <summary>Compute the readiness score for a set of findings.</summary>
    public static ReadinessResult Calculate(IEnumerable<CryptoFinding> findings)
    {
        double safe = 0, total = 0;
        foreach (var f in findings)
        {
            if (!IsQuantumRelevant(f)) continue;
            double w = BaseWeight(f) * RiskEngine.ExposureFactor(f.UsageContext);
            total += w;
            if (f.QuantumVulnerability is QuantumVulnerability.NotVulnerable or QuantumVulnerability.PostQuantum)
                safe += w;
        }

        if (total <= 0)
            return new ReadinessResult(100, true, 0, 0);

        int score = (int)Math.Round(100 * safe / total, MidpointRounding.AwayFromZero);
        return new ReadinessResult(score, false, safe, total);
    }
}
