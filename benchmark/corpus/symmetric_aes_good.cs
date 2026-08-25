// EXPECT: CBOM0001@Informational
// Intent: AES (default 256) is a correct, quantum-resistant choice. It should appear as a positive
// inventory entry (Informational), NOT as a risk. This guards against over-flagging good crypto.
using System.Security.Cryptography;

public class AesUsage
{
    public Aes Create() => Aes.Create();
}
