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

## Current implementation limitations (v0.2)

These are gaps in *this build*, scheduled for later turns; they are not inherent.

- **AES key size set via property.** `aes.KeySize = 128` is not yet tracked, so AES-128 is flagged
  reduced-margin only when the size is an explicit constructor/factory argument (rare in the BCL).
  Planned: lightweight intra-method flow to associate `KeySize`/`GenerateKey` with the instance.
- **Report paths are absolute.** Findings record the compilation's absolute file path; reports should
  emit repo-relative paths for portability and to avoid leaking local directory structure.
- **MSBuild loader is best-effort.** `.sln/.csproj` use `MSBuildWorkspace`; on failure the tool falls
  back to a no-MSBuild directory scan (BCL crypto still resolves, but project-reference/NuGet symbols —
  e.g., Bouncy Castle, `Microsoft.IdentityModel` JWT types — do not, so those detectors may not fire in
  fallback mode). Per-project target-framework reporting is partial.
- **Detector coverage is growing but incomplete.** Implemented: symmetric ciphers, ECB mode, hashes,
  RSA/ECDSA/ECDH/DSA, hardcoded keys/IVs, JWT signature-validation-disabled, deprecated TLS, disabled
  cert validation, PQC positive signals. Not yet: full JOSE/`alg=none` literal handling, KDFs (PBKDF2
  iteration thresholds), cloud KMS inventory, non-CSPRNG, Bouncy Castle.
- **Reporting:** CycloneDX 1.6, SARIF 2.1.0, Markdown, and an executive summary are implemented. Not yet:
  HTML report and the CBOM diff/baseline command.
- **No `cbom.config.json` yet.** Rule enable/disable, waivers, and `dataSensitivityHints` are designed
  (TDD §6.7) but not wired into the CLI.
- **CycloneDX schema validation** against the official `bom-1.6.schema.json` is not yet run in CI.
