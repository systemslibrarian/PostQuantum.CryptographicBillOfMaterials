namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;

/// <summary>Maps .NET BCL cryptographic type names to canonical knowledge-base algorithm names.</summary>
internal static class AlgorithmMap
{
    public static string? FromTypeName(string fullName)
    {
        // Only the real BCL crypto namespace counts. Matching the bare type name alone would mis-flag a
        // user-defined type that merely shares a BCL crypto name (e.g. Acme.Trading.RSA) — the same
        // false-positive class fixed in PqcPositiveDetector.
        int dot = fullName.LastIndexOf('.');
        // Substring rather than a range expression: System.Index/System.Range are unavailable in the
        // netstandard2.0 analyzer that shares this file.
        if (dot < 0 || !string.Equals(fullName.Substring(0, dot), "System.Security.Cryptography", StringComparison.Ordinal))
            return null;
        string simple = fullName.Substring(dot + 1);

        return simple switch
        {
            "Aes" or "AesManaged" or "AesCng" or "AesCryptoServiceProvider" or "AesGcm" or "AesCcm" => "AES",
            "TripleDES" or "TripleDESCng" or "TripleDESCryptoServiceProvider" => "3DES",
            "DES" or "DESCryptoServiceProvider" => "DES",
            "RC2" or "RC2CryptoServiceProvider" => "RC2",
            "MD5" or "MD5CryptoServiceProvider" or "MD5Cng" => "MD5",
            "SHA1" or "SHA1Managed" or "SHA1CryptoServiceProvider" or "SHA1Cng" => "SHA-1",
            "SHA256" or "SHA256Managed" or "SHA256CryptoServiceProvider" or "SHA256Cng" => "SHA-256",
            "SHA384" or "SHA384Managed" or "SHA384CryptoServiceProvider" or "SHA384Cng" => "SHA-384",
            "SHA512" or "SHA512Managed" or "SHA512CryptoServiceProvider" or "SHA512Cng" => "SHA-512",
            "RSA" or "RSACryptoServiceProvider" or "RSACng" or "RSAOpenSsl" => "RSA",
            "ECDsa" or "ECDsaCng" or "ECDsaOpenSsl" => "ECDSA",
            "ECDiffieHellman" or "ECDiffieHellmanCng" or "ECDiffieHellmanOpenSsl" => "ECDH",
            "DSA" or "DSACryptoServiceProvider" or "DSACng" => "DSA",
            _ => null,
        };
    }
}
