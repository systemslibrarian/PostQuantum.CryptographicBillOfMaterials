// EXPECT: CBOM0090
// Intent: ML-KEM is a post-quantum KEM (FIPS 203). It should be detected as a POSITIVE signal that raises
// readiness, not a risk. The net8.0 benchmark compilation predates the in-box type, so a stub in the real
// namespace stands in; on .NET 10 the same call resolves to System.Security.Cryptography.MLKem. The stub is
// kept to a single MLKem member-access usage so the expected count is unambiguous.
namespace System.Security.Cryptography
{
    public static class MLKem
    {
        public static object GenerateKey() => new object();
    }
}

namespace App
{
    public class PqcUsage
    {
        public object Create() => System.Security.Cryptography.MLKem.GenerateKey();
    }
}
