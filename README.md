# PostQuantum.CryptographicBillOfMaterials (`dotnet-cbom`)

A Cryptographic Bill of Materials (CBOM) generator for .NET. It uses Roslyn static analysis to
**inventory cryptographic usage, classify quantum risk, and demonstrate post-quantum (PQC) migration
progress** — in a form auditors trust and your existing tooling already consumes.

Built for ordinary .NET teams — county IT, libraries, SaaS vendors, defense subcontractors — who must
respond to federal PQC-migration timelines, often **without an in-house cryptographer**.

> **Honesty first.** A clean scan means *"no detectable issues in analyzed source,"* not *"the system is
> quantum-safe."* See [`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md) for exactly what static analysis cannot see.

## What it does

- **Discovers** crypto across `System.Security.Cryptography`, JWT validation, TLS/cert handling, and
  post-quantum APIs (ML-KEM/ML-DSA/SLH-DSA), with a **detection confidence** on every finding.
- **Classifies** each finding on **two independent axes** — classical weakness (e.g., ECB, MD5) and
  quantum vulnerability (Shor breaks RSA/ECC; Grover reduces AES-128's margin) — so advice is never
  conflated. Every verdict carries a **documented basis** (FIPS/NIST/CWE citation).
- **Scores** transparently: a 0–100 finding risk and a **PQC Readiness Score** whose arithmetic is shown,
  never a black box.
- **Reports** as **CycloneDX 1.6** (a profiled CBOM, not a proprietary format), **SARIF 2.1.0**,
  Markdown, HTML, and an executive summary.
- **Tracks progress** with `diff`/`--baseline`: "quantum-vulnerable findings 1 → 0, readiness 64 → 100."

## Install

```bash
dotnet tool install -g PostQuantum.CryptographicBillOfMaterials.Cli
```

(Requires the .NET SDK present for `.sln`/`.csproj` scans; a directory scan works without it.)

## Quick start

```bash
# Scan a solution, project, directory, or single file
dotnet-cbom scan ./MyApp.sln

# Choose formats and a CI gate
dotnet-cbom scan ./src --format cyclonedx,sarif,html --fail-on critical

# Show migration progress against a previous run
dotnet-cbom scan ./src --baseline ./last.cbom.json
dotnet-cbom diff ./last.cbom.json ./cbom-out/cbom.cbom.json
```

### Exit codes (CI-friendly, fail-closed)

| Code | Meaning |
|---|---|
| 0 | Completed; nothing at or above `--fail-on` |
| 1 | Findings at or above `--fail-on` (default `high`) |
| 2 | Partial analysis — a project failed to load (never reported as "clean") |
| 3 | Usage/config error · 4 internal error |

## How risk and readiness are computed (transparent)

- **Finding risk** = `0.45·Q + 0.35·C + 0.20·X` (quantum, classical-weakness, usage-exposure factors),
  with fail-closed floors (e.g., disabled cert validation and hardcoded keys are always ≥ Critical).
- **PQC Readiness** = `100 × safe-weight / total-weight` over quantum-relevant algorithms only; classical
  and config issues are reported separately so they don't distort the PQC picture.

Full methodology and the CycloneDX profile delta are in [`docs/TECHNICAL-DESIGN.md`](docs/TECHNICAL-DESIGN.md).

## Standards alignment

Output is a valid **CycloneDX 1.6** BOM (the version that upstreamed CBOM); PQC/risk fields live in the
sanctioned `properties`/`evidence` extension points under the `cbom:` namespace, so any CycloneDX-aware
tool can ingest it. Verdicts cite FIPS 203/204/205, NIST SP 800-131A/800-52, NIST IR 8547 (⚠ draft),
CNSA 2.0, and CWE. Configuration: an optional `cbom.config.json` (rule toggles recorded as waivers,
severity floors that only raise, path globs).

## Project layout

```
src/  PostQuantum.CryptographicBillOfMaterials            core model · risk · scoring · knowledge base
      PostQuantum.CryptographicBillOfMaterials.Analysis   Roslyn detectors + scan engine
      PostQuantum.CryptographicBillOfMaterials.Reporting  CycloneDX / SARIF / Markdown / HTML / diff
      PostQuantum.CryptographicBillOfMaterials.Cli        dotnet-cbom
docs/  TECHNICAL-DESIGN.md · THREAT-MODEL.md · KNOWN-GAPS.md
```

## Status

Active development. Working today: scan (solution/project/directory), 9 detectors, all report formats,
diff/baseline, config, CI. See [`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md) for current limitations.

## License

Apache-2.0.
