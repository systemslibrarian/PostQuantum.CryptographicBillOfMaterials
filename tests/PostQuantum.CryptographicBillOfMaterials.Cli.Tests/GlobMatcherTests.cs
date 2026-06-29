using PostQuantum.CryptographicBillOfMaterials.Cli;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Cli.Tests;

/// <summary>
/// Boundary correctness for the glob matcher used by include/exclude and data-sensitivity hints. The
/// regression of record is <c>**/Crypto.cs</c> erroneously matching <c>src/NotCrypto.cs</c>, which would
/// silently over-suppress findings.
/// </summary>
public class GlobMatcherTests
{
    [Theory]
    // '**/' = zero or more whole segments, boundary-anchored.
    [InlineData("**/Crypto.cs", "Crypto.cs", true)]
    [InlineData("**/Crypto.cs", "src/Crypto.cs", true)]
    [InlineData("**/Crypto.cs", "a/b/Crypto.cs", true)]
    [InlineData("**/Crypto.cs", "src/NotCrypto.cs", false)]   // the bug: must NOT match
    [InlineData("**/Crypto.cs", "NotCrypto.cs", false)]
    // single '*' stays within one segment.
    [InlineData("src/*.cs", "src/A.cs", true)]
    [InlineData("src/*.cs", "src/sub/A.cs", false)]
    // trailing '**' crosses segments.
    [InlineData("src/**", "src/a/b/C.cs", true)]
    [InlineData("src/**", "other/a.cs", false)]
    // '**' in the middle matches zero or more segments.
    [InlineData("a/**/b.cs", "a/b.cs", true)]
    [InlineData("a/**/b.cs", "a/x/y/b.cs", true)]
    [InlineData("a/**/b.cs", "a/x/yb.cs", false)]
    // backslashes normalize to forward slashes.
    [InlineData("**/Crypto.cs", "src\\Crypto.cs", true)]
    public void Matches(string pattern, string path, bool expected) =>
        Assert.Equal(expected, GlobMatcher.IsMatch(path, pattern));
}
