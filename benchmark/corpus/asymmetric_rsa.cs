// EXPECT: CBOM0002
// Intent: an RSA key pair is quantum-vulnerable (Shor). Should be flagged High/Vulnerable.
using System.Security.Cryptography;

public class RsaUsage
{
    public RSA Create() => RSA.Create(2048);
}
