using PostQuantum.CryptographicBillOfMaterials.Model;
using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Cli.Tests;

/// <summary>
/// The package-manifest fallback (used when project.assets.json is absent, e.g. --no-restore) must capture
/// the package version whether it is declared as an attribute or a child element — both are valid MSBuild.
/// Regression of record (chat.md #1): the child-element form lost the version, recording "unspecified".
/// </summary>
public class PackageCryptoInventoryTests
{
    [Theory]
    [InlineData("<PackageReference Include=\"NSec.Cryptography\" Version=\"23.0.0\" />")]
    [InlineData("<PackageReference Include=\"NSec.Cryptography\"><Version>23.0.0</Version></PackageReference>")]
    public void CapturesPackageVersion_AsAttributeOrChildElement(string packageRef)
    {
        string dir = Path.Combine(Path.GetTempPath(), "cbom-pkg-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(
                Path.Combine(dir, "Repro.csproj"),
                $"<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup>{packageRef}</ItemGroup></Project>");

            var diagnostics = new List<string>();
            IReadOnlyList<CryptoFinding> findings = PackageCryptoInventory.Inventory(dir, dir, diagnostics);

            CryptoFinding f = Assert.Single(findings);
            Assert.Contains("NSec.Cryptography", f.AlgorithmName);
            Assert.Contains("23.0.0", f.AlgorithmName);
            Assert.DoesNotContain("unspecified", f.AlgorithmName);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
