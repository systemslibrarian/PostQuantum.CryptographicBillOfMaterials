// Intentionally insecure sample used to demonstrate dotnet-cbom. DO NOT copy into real code.
using System.Net.Http;
using System.Security.Authentication;
using System.Security.Cryptography;

namespace VulnerableDemo;

public static class Crypto
{
    public static byte[] EncryptBadly(byte[] data)
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;                                  // CBOM0007 (High)
        aes.Key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8,
                               9, 10, 11, 12, 13, 14, 15, 16 };     // CBOM0030 (Critical)
        using var enc = aes.CreateEncryptor();
        return enc.TransformFinalBlock(data, 0, data.Length);
    }

    public static RSA MakeKeyExchangeKey() => RSA.Create(2048);     // CBOM0002 (High, Shor / HNDL)

    public static byte[] LegacyHash(byte[] data) => MD5.HashData(data);   // CBOM0010 (High, broken)

    public static byte[] GoodHash(byte[] data) => SHA384.HashData(data);  // clean (Informational)

    public static HttpClient InsecureClient()
    {
        var handler = new HttpClientHandler
        {
            // CBOM0041 (Critical): accept any server certificate
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
            SslProtocols = SslProtocols.Ssl3,                       // CBOM0040 (High)
        };
        return new HttpClient(handler);
    }
}
