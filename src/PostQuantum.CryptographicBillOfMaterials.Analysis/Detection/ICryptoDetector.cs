using Microsoft.CodeAnalysis.CSharp;
using PostQuantum.CryptographicBillOfMaterials.Rules;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;

/// <summary>
/// A focused cryptographic detector. Detectors declare the syntax kinds they care about so the engine
/// can dispatch only relevant nodes to them, then resolve symbols themselves inside <see cref="Inspect"/>.
/// </summary>
public interface ICryptoDetector
{
    /// <summary>Static metadata (rule id, category, mandatory basis).</summary>
    DetectorMetadata Metadata { get; }

    /// <summary>The syntax kinds this detector subscribes to.</summary>
    IReadOnlyCollection<SyntaxKind> SyntaxKinds { get; }

    /// <summary>Inspect a single node and report any findings via <see cref="DetectionContext.Report"/>.</summary>
    void Inspect(DetectionContext context);
}
