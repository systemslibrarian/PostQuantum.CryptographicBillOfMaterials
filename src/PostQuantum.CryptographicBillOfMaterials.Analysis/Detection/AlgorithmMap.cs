namespace PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;

/// <summary>Maps .NET BCL cryptographic type names to canonical knowledge-base algorithm names.</summary>
internal static class AlgorithmMap
{
    public static string? FromTypeName(string fullName)
    {
        int dot = fullName.LastIndexOf('.');
        string simple = dot >= 0 ? fullName[(dot + 1)..] : fullName;

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
