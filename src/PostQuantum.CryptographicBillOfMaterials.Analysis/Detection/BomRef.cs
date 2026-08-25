using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;

/// <summary>
/// Builds stable CycloneDX bom-refs from a normalized (rule, algorithm, file, occurrence) tuple plus a short
/// hash, so findings can be matched across scans for baselining (TDD §5.3, §8.3 decision 4). The source
/// <em>line</em> is deliberately NOT part of the identity: it would shift on any unrelated edit (adding a
/// using/comment above the finding) and break baseline matching. The occurrence ordinal disambiguates
/// multiple findings of the same rule+algorithm in the same file (assigned in document order by the
/// post-processor) and keeps every bom-ref unique.
/// </summary>
public static class BomRef
{
    public static string Create(string algorithm, string filePath, string ruleId, int occurrence = 0)
    {
        string normalized = $"{ruleId}|{algorithm}|{filePath}|{occurrence}";
        return $"crypto/{Slug(algorithm)}/{ShortHash(normalized)}";
    }

    private static string ShortHash(string value)
    {
        // Instance API and manual hex on purpose: this file is shared-source compiled into the
        // netstandard2.0 Roslyn analyzer, where SHA256.HashData and Convert.ToHexString do not exist.
        byte[] hash;
        using (var sha = SHA256.Create())
            hash = sha.ComputeHash(Encoding.UTF8.GetBytes(value));

        var sb = new StringBuilder(12);
        for (int i = 0; i < 6; i++)
            sb.Append(hash[i].ToString("x2", CultureInfo.InvariantCulture));
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
