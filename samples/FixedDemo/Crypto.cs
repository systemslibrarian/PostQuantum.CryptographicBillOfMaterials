// The remediated counterpart to VulnerableDemo, used to demonstrate `dotnet-cbom diff`: the
// quantum-vulnerable RSA key exchange becomes post-quantum ML-KEM (readiness rises, CBOM0002 clears,
// CBOM0090 appears), and the broken symmetric/hash/TLS usage is replaced with authenticated, modern crypto.
using System.Security.Cryptography;

namespace FixedDemo;

public static class Crypto
{
    // Was: RSA.Create(2048) — Shor-vulnerable key transport (CBOM0002). Now: ML-KEM-768 post-quantum key
    // establishment (FIPS 203, CBOM0090). Real code must gate on MLKem.IsSupported; ML-KEM needs .NET 10+
    // on a PQC-capable OS (OpenSSL 3.5+ / Windows 11 / Server 2025). See the key-establishment playbook.
    public static byte[] EstablishSharedKey(out byte[] ciphertext)
    {
        using MLKem kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        // kem.ExportEncapsulationKey() is published to peers; a peer encapsulates and returns the ciphertext.
        kem.Encapsulate(out ciphertext, out byte[] sharedSecret);
        byte[] recovered = kem.Decapsulate(ciphertext);   // == sharedSecret

        // Never use the KEM secret directly as a key: derive it with a KDF before use.
        return HKDF.DeriveKey(HashAlgorithmName.SHA384, recovered, outputLength: 32,
            info: "FixedDemo: AES-256-GCM data key v1"u8.ToArray());
    }

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
