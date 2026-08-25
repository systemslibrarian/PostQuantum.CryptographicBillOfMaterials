// EXPECT: CBOM0001, CBOM0050@High
// Intent: System.Random output flows into an AES key. Taint analysis should ELEVATE CBOM0050 (key material
// from a non-CSPRNG). The Aes.Create() is also inventoried (CBOM0001). The flow uses a neutral variable
// name ("buffer") to prove detection is by dataflow, not by identifier name.
using System;
using System.Security.Cryptography;

public class WeakRngKey
{
    public Aes Create()
    {
        Aes aes = Aes.Create();
        byte[] buffer = new byte[16];
        new Random().NextBytes(buffer);
        aes.Key = buffer;
        return aes;
    }
}
