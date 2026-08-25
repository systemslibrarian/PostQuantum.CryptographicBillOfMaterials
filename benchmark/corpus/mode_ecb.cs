// EXPECT: CBOM0001, CBOM0007
// Intent: ECB mode leaks plaintext structure (Broken). The Aes.Create() is also inventoried (CBOM0001).
using System.Security.Cryptography;

public class EcbUsage
{
    public Aes Create()
    {
        Aes aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        return aes;
    }
}
