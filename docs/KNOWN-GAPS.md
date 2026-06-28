# Known Gaps

A clean scan means **"no detectable issues in the analyzed source,"** not "the system is quantum-safe."
This document is the honest list of what the tool cannot see. It is referenced by the executive summary
and the CLI footer so a clean result is never mistaken for a clean system.

## Inherent limits of static analysis

- **Runtime / config-driven algorithm selection.** Algorithm names read from `appsettings.json`,
  environment variables, a database, or a feature flag are invisible. (`CryptoConfig.CreateFromName(userInput)`.)
- **Crypto inside opaque dependencies.** Cryptography performed entirely within a third-party NuGet or
  native library whose source we never analyze. Partially mitigated by package/KMS detection, not fully.
- **Reflection / dynamic dispatch.** Late-bound algorithm construction.
- **Data sensitivity & lifetime.** The tool cannot know a key protects 30-year records — the dominant
  factor in harvest-now-decrypt-later risk. Supply hints via `cbom.config.json` `dataSensitivityHints`.
- **Actual deployment.** TLS may be terminated at a load balancer the code never references.

## Current implementation status (v0.4)

The full detector list and bases are in [RULES.md](RULES.md). Implemented: 12 detectors (symmetric,
asymmetric, ECB, hashes, JWT validation bypass, hardcoded keys/IVs, deprecated TLS, disabled cert
validation, weak RNG, KDF, cloud-KMS inventory, PQC positive). Reporting: CycloneDX 1.6, SARIF 2.1.0,
Markdown, HTML, executive summary, and CBOM **diff/baseline**. Plus `dotnet-cbom validate` (CycloneDX 1.6
+ profile structural validation), `cbom.config.json` (waivers, raise-only severity floors, globs,
`dataSensitivityHints`), and CI building with `-warnaserror`.

### Remaining gaps in *this build* (not inherent)

- **Full JSON-Schema validation.** `validate` checks CycloneDX 1.6 *structure* + the `cbom:` profile, not
  the complete official `bom-1.6.schema.json` JSON-Schema draft. Full schema validation in CI is planned.
- **AES key size via property.** `aes.KeySize = 128` is not yet tracked; only explicit constructor/factory
  sizes flag AES-128 as reduced-margin. Planned: intra-method flow for `KeySize`/`GenerateKey`.
- **JOSE/`alg=none` literals.** Detected via the validation-bypass flags, not raw `"none"` header strings;
  weak HMAC key detection is not yet implemented.
- **Cloud KMS depth.** Records *that* a managed KMS is used, not key specs / usages / rotation / region.
- **No Bouncy Castle / dependency-aware inventory**, and **no X.509 certificate inventory** beyond
  disabled validation / deprecated TLS.
- **Weak-RNG context.** `System.Random` is flagged low everywhere; it is not yet elevated specifically
  when random material flows into keys/tokens/IVs/nonces.
- **MSBuild loader is best-effort.** `.sln/.csproj` use `MSBuildWorkspace`; on failure the tool falls back
  to a no-MSBuild directory scan (BCL crypto resolves, but third-party symbols — Bouncy Castle,
  `Microsoft.IdentityModel` — do not, so those detectors may not fire). Per-project target-framework
  reporting is partial.
- **Rule granularity.** Config toggles are per rule id (disabling `CBOM0010` suppresses all hash findings,
  not just MD5). Per-algorithm tuning is not yet supported.
- **Supply chain.** Signed NuGet package, tool SBOM, and a compatibility matrix are not yet published.
