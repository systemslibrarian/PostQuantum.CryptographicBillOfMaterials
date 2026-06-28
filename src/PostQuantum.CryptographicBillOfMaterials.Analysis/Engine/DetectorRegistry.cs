using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Detectors;
using PostQuantum.CryptographicBillOfMaterials.Knowledge;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Engine;

/// <summary>Holds the set of active detectors. Extension point for plugin-supplied detectors (TDD §7.3).</summary>
public sealed class DetectorRegistry
{
    private readonly List<ICryptoDetector> _detectors;

    public DetectorRegistry(IEnumerable<ICryptoDetector> detectors) => _detectors = detectors.ToList();

    public IReadOnlyList<ICryptoDetector> Detectors => _detectors;

    /// <summary>The built-in detector set for v1.</summary>
    public static DetectorRegistry CreateDefault(KnowledgeBase knowledgeBase) => new(new ICryptoDetector[]
    {
        new SymmetricCipherDetector(knowledgeBase),
        new EcbModeDetector(knowledgeBase),
        new HashAlgorithmDetector(knowledgeBase),
        new AsymmetricAlgorithmDetector(knowledgeBase),
        new HardcodedKeyDetector(knowledgeBase),
        new JwtSignatureValidationDetector(),
        new TlsProtocolDetector(),
        new CertificateValidationDetector(),
        new PqcPositiveDetector(knowledgeBase),
    });
}
