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

## Current implementation status

The full detector list and bases are in [RULES.md](RULES.md). Implemented: **17 rules** (16 Roslyn detectors
+ the CBOM0081 package-manifest inventory) — symmetric,
asymmetric, AES-128-via-property, ECB, hashes, JWT validation bypass, **JWT alg=none / weak HMAC key**,
hardcoded keys/IVs, deprecated TLS, disabled cert validation, **X.509 certificate inventory**, weak RNG
(**context-elevated**), KDF, **cloud-KMS inventory + key-spec depth**, **Bouncy Castle inventory**,
**package-manifest dependency inventory**, and PQC positive. Each Shor-vulnerable finding also carries a
**PQC migration playbook** (worked .NET 10 `MLKem`/`MLDsa`/`SlhDsa` code, hybrid/TLS/BouncyCastle options,
caveats, steps). Reporting: CycloneDX 1.6, SARIF 2.1.0, Markdown, HTML, executive summary, and CBOM
**diff/baseline** — as **audit packets** (top migration actions, what-changed-since-baseline, waivers).
Plus `dotnet-cbom validate` against the **official
CycloneDX 1.6 JSON Schema** + the `cbom:` profile; **policy profiles** (general/federal/cnsa2/audit/
developer); `cbom.config.json` (waivers with justification/approver/expiry, raise-only severity floors,
**per-algorithm** tuning, globs, path + **namespace** `dataSensitivityHints`); deterministic SourceLinked
packaging; a **tool SBOM**; an official **GitHub Action** + Azure/GitLab examples; and CI that self-scans
and schema-validates on every run.

### Remaining gaps (not inherent)

- **Dataflow is intra-method only.** Weak-RNG → key/IV/nonce flow uses a real intra-procedural taint
  analysis (`CryptoTaintAnalysis`, see [ADR 0002](adr/0002-intra-method-taint-for-key-material.md)), not
  identifier names. It does **not** follow values across method boundaries or constructor injection, branch
  /loop semantics are approximated by a linear pass, and only `System.Random`/`Random.Shared` are sources.
- **Cloud KMS region/account/rotation.** Captured only when statically visible; usually runtime config.
- **No-MSBuild fallback.** Symbol-based third-party detectors may not fire without restored packages; the
  package-manifest inventory (CBOM0081) mitigates this but does not replace per-call-site detection.
- **NuGet publishing & signing are wired but not executed** — publishing to nuget.org and signing require a
  maintainer's API key and code-signing certificate (supplied as CI secrets); see `.github/workflows/release.yml`.
