// EXPECT: CBOM0001, CBOM0030
// Intent: a hardcoded symmetric key is recoverable from the binary (CWE-321/798). The Aes.Create() is
// inventoried (CBOM0001); the literal key assignment is the hardcoded-secret finding (CBOM0030).
using System.Security.Cryptography;

public class HardcodedKey
{
    public Aes Create()
    {
        Aes aes = Aes.Create();
        aes.Key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        return aes;
    }
}
