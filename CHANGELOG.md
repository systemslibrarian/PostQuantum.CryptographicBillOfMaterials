# Changelog

All notable changes to `dotnet-cbom` are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versions follow SemVer.

## [1.0.0] — Initial release

The first public release of `dotnet-cbom`: a Roslyn-based Cryptographic Bill of Materials generator that
inventories cryptography, classifies quantum risk on two independent axes, tells you how to migrate, and
emits auditor-grade CycloneDX/SARIF/Markdown/HTML.

### PQC migration playbooks (the transition, not just the inventory)
- **Actionable .NET migration playbooks** for every Shor-vulnerable algorithm (RSA, ECDSA, ECDH, DSA). Each
  finding carries concrete *how-to-migrate* guidance, not just a one-line label: in-box .NET 10
  `System.Security.Cryptography` APIs (`MLKem`/`MLDsa`/`SlhDsa`) with worked, verified code; the
  often-no-code-change TLS path (`X25519MLKEM768`); BouncyCastle for older runtimes; hybrid-mode guidance;
  size/interop caveats; and ordered migration steps. Rendered in the Markdown and HTML reports, with a
  machine-readable `cbom:migration:playbooks` pointer in the CycloneDX output. Knowledge lives in
  `playbooks.json` (data, reviewable/citable independently of code) and is referenced from `algorithms.json`.
  See [ADR 0003](docs/adr/0003-pqc-migration-playbooks.md).

### Detection (17 rules — 16 Roslyn detectors + the CBOM0081 package-manifest inventory)
- **Symmetric**: AES (with AES-128 reduced-margin via `KeySize`), 3DES/DES/RC2, ECB mode (CBOM0001/0003/0007).
- **Asymmetric / Shor**: RSA, ECDSA, ECDH, DSA, including small key sizes (CBOM0002).
- **Hashing**: MD5/SHA-1 (broken) and SHA-2 inventory (CBOM0010).
- **JWT**: signature-validation bypass (CBOM0021); `alg=none` and hardcoded/sub-256-bit HMAC keys (CBOM0022).
- **Secrets**: hardcoded symmetric key / IV literals (CBOM0030).
- **TLS**: deprecated SSL/TLS versions (CBOM0040) and disabled certificate validation (CBOM0041).
- **Certificates**: X.509 inventory, classified by signing-key algorithm (CBOM0042).
- **Randomness**: non-cryptographic RNG, elevated to High when its output flows into key/token/IV/nonce/salt
  material via real intra-method taint analysis; gameplay/non-security use stays low-noise (CBOM0050). See
  [ADR 0002](docs/adr/0002-intra-method-taint-for-key-material.md).
- **KDF**: PBKDF1 and low-iteration PBKDF2 (CBOM0060).
- **Cloud KMS**: KMS usage, with classical asymmetric KMS keys (`CreateRsaKeyOptions`/`CreateEcKeyOptions`)
  flagged as Shor-vulnerable (CBOM0070).
- **Third-party**: Bouncy Castle primitives by type (CBOM0080) and crypto-bearing NuGet packages from the
  manifest / `project.assets.json` (CBOM0081).
- **Post-quantum (positive)**: ML-KEM / ML-DSA / SLH-DSA usage, which raises readiness (CBOM0090).

### Reporting & scoring
- Output as **CycloneDX 1.6** (a profiled CBOM, not a proprietary format), **SARIF 2.1.0**, Markdown, HTML,
  and an executive summary — as audit packets: Top Migration Actions, What-Changed-Since-Baseline
  (remediation status New/Unchanged/Regressed/Waived), and Waivers.
- Transparent 0–100 finding risk and a PQC Readiness Score whose arithmetic is shown.
- Baseline/diff workflow (`--baseline`, `diff`) stamps each finding's remediation status.

### Trust & validation
- **Official CycloneDX 1.6 JSON-Schema validation** in the `validate` command and CI, against the bundled
  `bom-1.6.schema.json` (+ spdx/jsf), offline (`--schema-only` / `--profile-only`). Internal
  primitive/mode/padding values are mapped onto the CycloneDX enums so output validates; the richer
  vocabulary is preserved in `cbom:crypto:primitive`.
- **Accuracy benchmark**: a labeled corpus measures precision/recall (including false-positive traps and
  severity discrimination) and fails CI on regression. See [benchmark/ACCURACY.md](benchmark/ACCURACY.md).
- Fail-closed by design: an unparseable `cbom.config.json` is fatal (exit 3) rather than silently reverting
  to defaults; a project that fails to load is reported as "not analyzed," never "clean" (exit 2). Waivers
  require a justification and an unexpired expiry to suppress. See
  [ADR 0001](docs/adr/0001-fail-closed-config-and-justified-waivers.md).

### Policy & workflow
- **Policy profiles**: `general | federal | cnsa2 | audit | developer` (`--profile`, recorded in metadata).
  Profiles may only raise severity or require more evidence — never silently lower risk.
- Waivers with justification/approver/expiry (the `audit` profile annotates instead of suppressing);
  per-algorithm rule tuning (`rules.<id>.algorithms.<name>`); namespace-scoped data-sensitivity hints
  (`ns:` keys); full applied-config recording in CBOM metadata.
- Scan options: `--profile`, `--changed-files` (PR-aware), `--restore` / `--no-restore`,
  `--msbuild-property`, with per-project load-failure reasons surfaced.

### Supply chain & CI
- Official composite **GitHub Action** (`action.yml`) with SARIF upload + artifact retention; example Azure
  DevOps and GitLab pipelines; a PR baseline-diff comment workflow.
- Deterministic, **SourceLink**ed, symbol-published packaging. The release workflow stamps the version from
  the git tag, signs the package (when a certificate is configured), and publishes a **GitHub Release** with
  the `.nupkg`, symbols, tool SBOM, and SHA-256 checksums attached. See [docs/RELEASING.md](docs/RELEASING.md).
- The CLI reports its version from the assembly (single source of truth in `Directory.Build.props`), so the
  installed package and `dotnet-cbom version` always agree.
- **Tool SBOM** (`sbom/tool.cdx.json`) with a regeneration script; compatibility matrix and accuracy page.

### Performance
- The Roslyn scan runs per-syntax-tree in parallel with a deterministic, order-preserving merge.
