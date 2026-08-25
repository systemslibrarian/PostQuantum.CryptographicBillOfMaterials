// EXPECT: CBOM0010@High
// Intent: MD5 is collision-broken. Should be flagged.
using System.Security.Cryptography;

public class Md5Usage
{
    public byte[] Hash(byte[] data) => MD5.HashData(data);
}
