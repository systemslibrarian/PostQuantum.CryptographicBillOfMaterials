// EXPECT: CBOM0001@High
// Intent: DES is a broken legacy cipher (56-bit key). Should be flagged.
using System.Security.Cryptography;

public class DesUsage
{
#pragma warning disable SYSLIB0021
    public DES Create() => new DESCryptoServiceProvider();
#pragma warning restore SYSLIB0021
}
