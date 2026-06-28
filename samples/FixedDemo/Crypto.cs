// The remediated counterpart to VulnerableDemo, used to demonstrate `dotnet-cbom diff`.
using System.Security.Cryptography;

namespace FixedDemo;

public static class Crypto
{
    public static byte[] Hash(byte[] data) => SHA384.HashData(data);   // quantum-safe hash

    public static (byte[] ciphertext, byte[] tag) Encrypt(byte[] key, byte[] nonce, byte[] data)
    {
        using var gcm = new AesGcm(key, 16);                            // AES-GCM, authenticated
        var ciphertext = new byte[data.Length];
        var tag = new byte[16];
        gcm.Encrypt(nonce, data, ciphertext, tag);
        return (ciphertext, tag);
    }
}
