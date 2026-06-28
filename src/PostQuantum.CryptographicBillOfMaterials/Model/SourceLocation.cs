namespace PostQuantum.CryptographicBillOfMaterials.Model;

/// <summary>A 1-based source location for a finding.</summary>
/// <param name="FilePath">Path to the source file (as reported by the compilation).</param>
/// <param name="Line">1-based line number.</param>
/// <param name="Column">Optional 1-based column number.</param>
public sealed record SourceLocation(string FilePath, int Line, int? Column = null);
