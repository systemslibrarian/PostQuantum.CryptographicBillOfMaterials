// EXPECT: CBOM0002
// Intent: ECDSA signing is quantum-vulnerable (Shor on ECDLP). Should be flagged Vulnerable.
using System.Security.Cryptography;

public class EcdsaUsage
{
    public ECDsa Create() => ECDsa.Create(ECCurve.NamedCurves.nistP256);
}
