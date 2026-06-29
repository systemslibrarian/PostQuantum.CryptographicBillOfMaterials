# PostQuantum.CryptographicBillOfMaterials (`dotnet-cbom`)

A Cryptographic Bill of Materials (CBOM) generator for .NET. It uses Roslyn static analysis to
**inventory cryptographic usage, classify quantum risk, and demonstrate post-quantum (PQC) migration
progress** — in a form auditors trust and your existing tooling already consumes.

Built for ordinary .NET teams — county IT, libraries, SaaS vendors, defense subcontractors — who must
respond to federal PQC-migration timelines, often **without an in-house cryptographer**.

> **Honesty first.** A clean scan means *"no detectable issues in analyzed source,"* not *"the system is
> quantum-safe."* See [`docs/KNOWN-GAPS.md`](https://github.com/systemslibrarian/PostQuantum.CryptographicBillOfMaterials/blob/main/docs/KNOWN-GAPS.md) for exactly what static analysis cannot see.

## What it does

- **Discovers** crypto across `System.Security.Cryptography`, JWT validation, TLS/cert handling, and
  post-quantum APIs (ML-KEM/ML-DSA/SLH-DSA), with a **detection confidence** on every finding.
- **Classifies** each finding on **two independent axes** — classical weakness (e.g., ECB, MD5) and
  quantum vulnerability (Shor breaks RSA/ECC; Grover reduces AES-128's margin) — so advice is never
  conflated. Every verdict carries a **documented basis** (FIPS/NIST/CWE citation).
- **Scores** transparently: a 0–100 finding risk and a **PQC Readiness Score** whose arithmetic is shown,
  never a black box.
- **Reports** as **CycloneDX 1.6** (a profiled CBOM, not a proprietary format), **SARIF 2.1.0**,
  Markdown, HTML, and an executive summary — now as **audit packets**: top migration actions,
  what-changed-since-baseline, remediation status, and waivers.
- **Tracks progress** with `diff`/`--baseline`: "quantum-vulnerable findings 1 → 0, readiness 64 → 100,"
  stamping each finding New / Unchanged / Regressed / Waived.
- **Validates itself**: generated CBOMs are checked against the **official CycloneDX 1.6 JSON Schema**
  (bundled, offline) plus the `dotnet-cbom` profile — in the `validate` command and in CI.
- **Sees beyond source**: third-party crypto via Bouncy Castle detection and a **package-manifest
  inventory** (`project.assets.json` / `PackageReference`) so crypto in dependencies is visible too.

## Install

```bash
dotnet tool install -g PostQuantum.CryptographicBillOfMaterials.Cli
```

(Requires the .NET SDK present for `.sln`/`.csproj` scans; a directory scan works without it.)

## Quick start

```bash
# Scan a solution, project, directory, or single file
dotnet-cbom scan ./MyApp.sln

# Choose formats, a policy posture, and a CI gate
dotnet-cbom scan ./src --format cyclonedx,sarif,html --profile cnsa2 --fail-on critical

# Show migration progress against a previous run (stamps New/Regressed/Unchanged on findings)
dotnet-cbom scan ./src --baseline ./last.cbom.json
dotnet-cbom diff ./last.cbom.json ./cbom-out/cbom.cbom.json

# Verify a CBOM against the official CycloneDX 1.6 schema AND the dotnet-cbom profile
dotnet-cbom validate ./cbom-out/cbom.cbom.json
```

### Policy profiles

`--profile` selects a posture (recorded in the CBOM). Profiles may only **raise** severity or require more
evidence — never silently lower risk.

| Profile | Posture |
|---|---|
| `general` | Conservative commercial default (draft guidance labelled as draft) |
| `federal` | NIST-centered; Shor-vulnerable public-key crypto is at least High |
| `cnsa2` | CNSA 2.0 / NSS; AES-128 insufficient (AES-256 required); verbose basis |
| `audit` | Maximum evidence; waivers annotate rather than suppress |
| `developer` | Lower-noise local mode (risk classification unchanged) |

### Useful scan options

`--changed-files a.cs,b.cs` (PR-aware), `--config cbom.config.json`, `--restore`/`--no-restore`,
`--msbuild-property name=value`, `--allow-partial`, `-q`.

### Exit codes (CI-friendly, fail-closed)

| Code | Meaning |
|---|---|
| 0 | Completed; nothing at or above `--fail-on` |
| 1 | Findings at or above `--fail-on` (default `high`) |
| 2 | Partial analysis — a project failed to load (never reported as "clean") |
| 3 | Usage/config error · 4 internal error |

## CI / GitHub Actions

Use the official composite action (SARIF upload + artifact retention built in):

```yaml
- uses: actions/setup-dotnet@v4
  with: { dotnet-version: '8.0.x' }
- uses: systemslibrarian/PostQuantum.CryptographicBillOfMaterials@v1
  with:
    target: ./MyApp.sln
    formats: cyclonedx,sarif,markdown,summary
    profile: general
    fail-on: ${{ github.event_name == 'pull_request' && 'none' || 'high' }}
    baseline: baseline/cbom.cbom.json
```

Full copy-paste pipelines for **GitHub Actions** (with a PR baseline-diff comment), **Azure DevOps**, and
**GitLab CI** are in [`examples/ci/`](https://github.com/systemslibrarian/PostQuantum.CryptographicBillOfMaterials/tree/main/examples/ci). Start at `--fail-on critical` and ratchet down as the
inventory matures; SARIF lights up code scanning while the CBOM artifact feeds Dependency-Track or an auditor.

## How risk and readiness are computed (transparent)

- **Finding risk** = `0.45·Q + 0.35·C + 0.20·X` (quantum, classical-weakness, usage-exposure factors),
  with fail-closed floors (e.g., disabled cert validation and hardcoded keys are always ≥ Critical).
- **PQC Readiness** = `100 × safe-weight / total-weight` over quantum-relevant algorithms only; classical
  and config issues are reported separately so they don't distort the PQC picture.

Full methodology and the CycloneDX profile delta are in [`docs/TECHNICAL-DESIGN.md`](https://github.com/systemslibrarian/PostQuantum.CryptographicBillOfMaterials/blob/main/docs/TECHNICAL-DESIGN.md).

## Standards alignment

Output is a valid **CycloneDX 1.6** BOM (the version that upstreamed CBOM) — proven every run against the
official JSON Schema. PQC/risk fields live in the sanctioned `properties`/`evidence` extension points under
the `cbom:` namespace, so any CycloneDX-aware tool can ingest it. Verdicts cite FIPS 203/204/205, NIST SP
800-131A/800-52, NIST IR 8547 (⚠ draft), CNSA 2.0, and CWE — see the citation-status table in
[`docs/RULES.md`](https://github.com/systemslibrarian/PostQuantum.CryptographicBillOfMaterials/blob/main/docs/RULES.md).

Configuration (`cbom.config.json`): rule toggles recorded as **waivers** (justification/approver/expiry),
**per-algorithm** tuning, severity floors that only raise, path globs, and **data-sensitivity hints** by
path or namespace (`ns:`) that elevate harvest-now-decrypt-later risk. Everything applied is recorded back
into the CBOM. See [`samples/cbom.config.example.json`](https://github.com/systemslibrarian/PostQuantum.CryptographicBillOfMaterials/blob/main/samples/cbom.config.example.json).

## Project layout

```
src/  PostQuantum.CryptographicBillOfMaterials            core model · risk · scoring · knowledge base
      PostQuantum.CryptographicBillOfMaterials.Analysis   Roslyn detectors + scan engine
      PostQuantum.CryptographicBillOfMaterials.Reporting  CycloneDX / SARIF / Markdown / HTML / diff
      PostQuantum.CryptographicBillOfMaterials.Cli        dotnet-cbom
docs/  TECHNICAL-DESIGN.md · THREAT-MODEL.md · KNOWN-GAPS.md · RULES.md · ROADMAP.md
       RULE-CHANGELOG.md · COMPATIBILITY.md · ACCURACY-AND-LIMITATIONS.md
examples/ci/  github-actions.yml · azure-pipelines.yml · gitlab-ci.yml
```

## Status

Active development. Working today: scan (solution/project/directory), **16 rules**, all report formats as
audit packets, diff/baseline with remediation status, **policy profiles**, expressive config, **official
CycloneDX 1.6 schema validation**, a GitHub Action + CI examples, and a tool SBOM. See
[`docs/ACCURACY-AND-LIMITATIONS.md`](https://github.com/systemslibrarian/PostQuantum.CryptographicBillOfMaterials/blob/main/docs/ACCURACY-AND-LIMITATIONS.md) and
[`docs/KNOWN-GAPS.md`](https://github.com/systemslibrarian/PostQuantum.CryptographicBillOfMaterials/blob/main/docs/KNOWN-GAPS.md) for what static analysis can and cannot see.

## License

Apache-2.0.
