// EXPECT: CBOM0060
// Intent: PBKDF2 with only 1000 iterations is below modern guidance (Suboptimal). Should be flagged.
using System.Security.Cryptography;

public class WeakKdf
{
    public byte[] Derive(byte[] pw, byte[] salt)
    {
        var d = new Rfc2898DeriveBytes(pw, salt, 1000);
        return d.GetBytes(16);
    }
}
