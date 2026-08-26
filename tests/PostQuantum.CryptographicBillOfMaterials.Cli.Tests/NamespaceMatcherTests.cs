using Xunit;

namespace PostQuantum.CryptographicBillOfMaterials.Cli.Tests;

/// <summary>
/// `ns:` data-sensitivity hints are matched as namespaces, not paths. Glob translation alone turned
/// `Contoso.Billing.*` into `^Contoso\.Billing\.[^/]*$`, which misses the namespace named in the hint — so
/// the config shipped verbatim in samples/cbom.config.example.json silently skipped the harvest-now-
/// decrypt-later uplift for code sitting directly in `Contoso.Billing`.
/// </summary>
public class NamespaceMatcherTests
{
    [Theory]
    // The bug: the pattern must cover the namespace it names, not only its descendants.
    [InlineData("Contoso.Billing.*", "Contoso.Billing", true)]
    [InlineData("Contoso.Billing.*", "Contoso.Billing.Vault", true)]
    // Guards against "just replace dots with slashes", which regresses deeper namespaces to false.
    [InlineData("Contoso.Billing.*", "Contoso.Billing.Vault.Keys", true)]
    // Prefix matching is on whole segments: a sibling namespace sharing a text prefix must not match.
    [InlineData("Contoso.Billing.*", "Contoso.BillingOther", false)]
    [InlineData("Contoso.Billing.*", "Contoso.Bill", false)]
    [InlineData("Contoso.Billing.**", "Contoso.Billing", true)]
    [InlineData("Contoso.Billing.**", "Contoso.Billing.Vault", true)]
    // An exact pattern stays exact.
    [InlineData("Contoso.Billing", "Contoso.Billing", true)]
    [InlineData("Contoso.Billing", "Contoso.Billing.Vault", false)]
    // An inner wildcard keeps plain glob behaviour, unchanged.
    [InlineData("Contoso.*.Vault", "Contoso.Billing.Vault", true)]
    [InlineData("Contoso.*.Vault", "Contoso.Billing", false)]
    public void Matches(string pattern, string ns, bool expected) =>
        Assert.Equal(expected, NamespaceMatcher.IsMatch(ns, pattern));
}
