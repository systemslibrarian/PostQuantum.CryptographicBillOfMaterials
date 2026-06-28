using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Reporting;

/// <summary>
/// Renders a <see cref="CbomDocument"/> to a particular report format and writes it to a stream.
/// Implementations are synchronous and stream-based so callers control buffering and disposal.
/// </summary>
public interface IReportRenderer
{
    /// <summary>Short, stable identifier for the format (e.g. <c>cyclonedx</c>, <c>sarif</c>, <c>markdown</c>).</summary>
    string FormatName { get; }

    /// <summary>The file extension (including the leading dot) conventionally used for this format.</summary>
    string FileExtension { get; }

    /// <summary>Renders <paramref name="document"/> to <paramref name="output"/>. The stream is not closed.</summary>
    void Render(CbomDocument document, Stream output);
}
