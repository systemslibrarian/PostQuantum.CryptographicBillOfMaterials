using System.Security.Cryptography;
using System.Text;
using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;

/// <summary>
/// Builds stable CycloneDX bom-refs from a normalized (rule, algorithm, location) tuple plus a short hash,
/// so findings can be matched across scans for baselining (TDD §5.3, §8.3 decision 4).
/// </summary>
internal static class BomRef
{
    public static string Create(string algorithm, SourceLocation location, string ruleId)
    {
        string normalized = $"{ruleId}|{algorithm}|{location.FilePath}|{location.Line}";
        return $"crypto/{Slug(algorithm)}/{ShortHash(normalized)}";
    }

    private static string ShortHash(string value)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(hash, 0, 6).ToLowerInvariant();
    }

    private static string Slug(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (char c in value)
            sb.Append(char.IsLetterOrDigit(c) || c == '-' ? char.ToLowerInvariant(c) : '-');
        return sb.ToString();
    }
}
