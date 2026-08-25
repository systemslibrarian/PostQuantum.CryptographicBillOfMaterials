// EXPECT-CLEAN
// Intent: PBKDF2 with 600,000 iterations meets current OWASP guidance. It must NOT be flagged — FP guard.
using System.Security.Cryptography;

public class StrongKdf
{
    public byte[] Derive(byte[] pw, byte[] salt)
    {
        var d = new Rfc2898DeriveBytes(pw, salt, 600000);
        return d.GetBytes(16);
    }
}
