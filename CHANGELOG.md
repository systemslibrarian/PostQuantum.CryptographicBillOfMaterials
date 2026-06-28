# Changelog

All notable changes to `dotnet-cbom` are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versions follow SemVer.

## [Unreleased]

### Added — detection coverage
- **CBOM0022** — unsigned/weak-keyed JWT algorithms: `alg=none` (raw literal and `SecurityAlgorithms.None`)
  and HMAC signing keys that are hardcoded or shorter than the 256-bit HS256 minimum (RFC 8725, RFC 7518).
- **CBOM0042** — X.509 certificate inventory: `CertificateRequest` classified by signing-key algorithm
  (RSA/ECDSA → Shor-vulnerable), and `X509Certificate2` loads recorded as certificate assets.
- **CBOM0080** — Bouncy Castle (`Org.BouncyCastle.*`) dependency-aware inventory by type, including PQC types.
- **CBOM0081** — package-manifest crypto inventory from `project.assets.json` / `<PackageReference>`
  (Bouncy Castle, Microsoft.IdentityModel, jose-jwt, NSec/libsodium, ASP.NET Data Protection, …).
- **CBOM0050** now elevates `System.Random` to High when its output flows into key/token/IV/nonce/salt
  material; gameplay/non-security usage stays low-noise.
- **CBOM0070** (Cloud KMS) now flags classical asymmetric keys minted in a managed KMS
  (`CreateRsaKeyOptions`/`CreateEcKeyOptions`) as Shor-vulnerable, not just "a KMS is used."

### Added — trust & validation
- **Full official CycloneDX 1.6 JSON-Schema validation.** The `validate` command and CI now check generated
  CBOMs against the bundled official `bom-1.6.schema.json` (+ spdx/jsf), offline. `--schema-only`/`--profile-only`.
- Generated CBOMs are mapped onto the CycloneDX `primitive`/`mode`/`padding` enums so output validates;
  the richer internal vocabulary is preserved in `cbom:crypto:primitive`.

### Added — policy & workflow
- **Policy profiles**: `general | federal | cnsa2 | audit | developer` (`--profile`, recorded in metadata).
  Profiles may only raise severity or require more evidence — never silently lower risk.
- **Audit-packet reporting**: Top Migration Actions, What-Changed-Since-Baseline (remediation status:
  New/Unchanged/Regressed/Waived), and Waivers in summary/Markdown/HTML.
- **Waivers** with justification/approver/expiry; the `audit` profile annotates instead of suppressing;
  expired waivers re-activate.
- **Per-algorithm rule tuning** (`rules.<id>.algorithms.<name>`), **namespace-scoped** data-sensitivity hints
  (`ns:` keys), and **full applied-config recording** in CBOM metadata.
- New scan options: `--profile`, `--changed-files` (PR-aware), `--restore`/`--no-restore`,
  `--msbuild-property`. Per-project load-failure reasons surfaced.

### Added — supply chain & CI
- Official composite **GitHub Action** (`action.yml`) with SARIF upload + artifact retention; example
  Azure DevOps and GitLab pipelines; PR baseline-diff comment workflow.
- Deterministic, **SourceLink**ed, symbol-published packaging; release workflow with NuGet signing wiring.
- **Tool SBOM** (`sbom/tool.cdx.json`) + regeneration script. Compatibility matrix and accuracy page.

### Performance
- The Roslyn scan now runs per-syntax-tree in parallel with deterministic, order-preserving merge.
