# PostQuantum CBOM Analyzer

In-editor cryptographic and post-quantum (PQC) risk diagnostics for .NET — the [`dotnet-cbom`](https://www.nuget.org/packages/PostQuantum.CryptographicBillOfMaterials.Cli) detection engine packaged as a Roslyn analyzer.

> **Find your crypto before quantum does.** Quantum-vulnerable and weak cryptography is underlined as you type — RSA, ECDSA/ECDH, MD5/SHA-1, ECB mode, deprecated TLS, disabled certificate validation, hardcoded keys, weak RNGs, and more — each with the risk level and a NIST/FIPS/CWE citation.

## Install

```bash
dotnet add package PostQuantum.CryptographicBillOfMaterials.Analyzer
```

Diagnostics appear in Visual Studio, VS Code (C# Dev Kit), Rider, and on `dotnet build` / CI.

## What you get

- **Squiggles + Problems entries** on risky cryptography, with the same rules that generate the full CBOM.
- **Per-finding severity**: weak usage (e.g. `MD5.Create()`) is a warning; clean usage (e.g. SHA-384) stays an informational hint.
- **Citations on hover**: every verdict links its standards basis (FIPS 203/204/205, NIST SP 800-131A/800-52, CWE).
- **Tunable**: set any `CBOM####` rule's severity in `.editorconfig`, e.g. `dotnet_diagnostic.CBOM0002.severity = error`.

## Local-first, by design

- Runs entirely on your machine as part of the C# compilation.
- **No source code uploaded. No cloud analysis. No telemetry.**

For full-solution inventory, CycloneDX/SARIF reports, PQC-readiness scoring, baselines, and policy profiles, use the [`dotnet-cbom` CLI](https://www.nuget.org/packages/PostQuantum.CryptographicBillOfMaterials.Cli). Rule reference: [docs/RULES.md](https://github.com/systemslibrarian/PostQuantum.CryptographicBillOfMaterials/blob/main/docs/RULES.md).

Apache-2.0.
