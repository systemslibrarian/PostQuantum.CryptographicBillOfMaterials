namespace PostQuantum.CryptographicBillOfMaterials.Model;

/// <summary>A 1-based source location for a finding.</summary>
/// <param name="FilePath">Path to the source file (as reported by the compilation).</param>
/// <param name="Line">1-based line number.</param>
/// <param name="Column">Optional 1-based column number.</param>
/// <param name="Namespace">Enclosing namespace of the finding, when resolvable (for namespace-scoped policy).</param>
/// <param name="Symbol">Enclosing type/member symbol path, when resolvable (e.g., <c>Contoso.Billing.Vault.Encrypt</c>).</param>
public sealed record SourceLocation(string FilePath, int Line, int? Column = null, string? Namespace = null, string? Symbol = null);
