using System.Security.Cryptography;
using System.Text;
using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;

/// <summary>
/// Builds stable CycloneDX bom-refs from a normalized (rule, algorithm, location) tuple plus a short hash,
/// so findings can be matched across scans for baselining (TDD §5.3, §8.3 decision 4).
/// </summary>
public static class BomRef
{
    public static string Create(string algorithm, SourceLocation location, string ruleId)
    {
        string normalized = $"{ruleId}|{algorithm}|{location.FilePath}|{location.Line}";
        return $"crypto/{Slug(algorithm)}/{ShortHash(normalized)}";
    }

    private static string ShortHash(string value)
    {
        // Instance API + manual hex so the shared source also compiles on netstandard2.0 (the analyzer),
        // where SHA256.HashData / Convert.ToHexString do not exist. Output is identical: the lowercase hex
        // of the first 6 bytes (12 chars).
        using var sha = SHA256.Create();
        byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(value));
        var sb = new StringBuilder(12);
        for (int i = 0; i < 6; i++)
            sb.Append(hash[i].ToString("x2"));
        return sb.ToString();
    }

    private static string Slug(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (char c in value)
            sb.Append(char.IsLetterOrDigit(c) || c == '-' ? char.ToLowerInvariant(c) : '-');
        return sb.ToString();
    }
}
