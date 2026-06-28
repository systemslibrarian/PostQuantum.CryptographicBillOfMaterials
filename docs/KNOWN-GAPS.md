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

## Current implementation limitations (v0.1 — core engine slice)

These are gaps in *this build*, scheduled for later turns; they are not inherent.

- **AES key size set via property.** `aes.KeySize = 128` is not yet tracked, so AES-128 is flagged
  reduced-margin only when the size is an explicit constructor/factory argument (rare in the BCL).
  Planned: lightweight intra-method flow to associate `KeySize`/`GenerateKey` with the instance.
- **No MSBuild workspace loader yet.** The engine analyzes a `Compilation`; solution/project loading via
  `MSBuildWorkspace` (and the fail-closed "project failed to analyze" path) lands with the CLI turn.
- **Detector coverage is a vertical slice.** Implemented: symmetric ciphers, ECB mode, hashes,
  RSA/ECDSA/ECDH/DSA, hardcoded keys/IVs. Not yet: JWT/JOSE (`alg=none`), TLS/cert-validation, KDFs,
  cloud KMS, non-CSPRNG, Bouncy Castle, PQC positive-signal detection.
- **No reporters yet.** CycloneDX/SARIF/Markdown/HTML serialization and CBOM diff are the reporting turn.
- **Detector exceptions are not yet sandboxed per-node.** The design calls for isolating a throwing
  detector; the current engine does not wrap `Inspect` in a try/catch. Add before plugin support.
