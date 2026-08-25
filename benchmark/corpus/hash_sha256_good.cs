// EXPECT: CBOM0010@Informational
// Intent: SHA-256 is a sound modern hash. It is inventoried (Informational), not flagged as a risk.
using System.Security.Cryptography;

public class Sha256Usage
{
    public byte[] Hash(byte[] data) => SHA256.HashData(data);
}
