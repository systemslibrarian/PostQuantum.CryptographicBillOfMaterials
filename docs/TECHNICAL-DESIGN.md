# Technical Design Document — `PostQuantum.CryptographicBillOfMaterials` (`dotnet-cbom`)

**Status:** Draft for human review · **Version:** 0.1 (design) · **Date:** 2026-06-28
**Author role:** Senior .NET security architect / library designer
**Scope of this document:** Design only. No implementation. Short illustrative snippets are used where a snippet is the clearest way to convey a design decision.

> **How to read the security claims in this document.** Every "weak / deprecated / quantum-vulnerable" judgment carries an explicit *basis* (the standard or notice it derives from). Where a source is a **draft** or where guidance is **evolving or contested**, it is marked **⚠ NOT-SETTLED**. A wrong call in a security tool is worse than a hedge, so hedges are deliberate.

---

## 0. Executive framing

`dotnet-cbom` produces a **Cryptography Bill of Materials** for .NET solutions through Roslyn-based static analysis, classifies each finding for **quantum risk**, and emits output that auditors and existing security tooling already consume (CycloneDX, SARIF). The product is judged by three outcomes, not by cryptographic elegance:

1. An inventory an **auditor will trust** — standards-aligned, with documented bases and honest confidence.
2. Recommendations a **non-cryptographer can safely follow** — misuse-resistant, never downgrading safety.
3. Output that **plugs into the compliance/security tooling these teams already run**.

The single most important strategic decision in this design: **the CBOM is a CycloneDX 1.6 document, profiled — not a proprietary schema.** Everything else follows from that.

---

## 1. Architecture overview and layer breakdown

### 1.1 Layering (Clean Architecture; dependencies point inward)

```
                 ┌───────────────────────────────────────────────┐
                 │                   Cli  (dotnet-cbom)            │  System.CommandLine
                 │   commands · config binding · exit codes        │
                 └───────────────┬───────────────┬────────────────┘
                                 │               │
              ┌──────────────────▼───┐      ┌────▼───────────────────┐
              │      Reporting        │      │       Analysis          │  Microsoft.CodeAnalysis
              │  CycloneDX · SARIF ·  │      │  MSBuildWorkspace ·      │  (Roslyn)
              │  Markdown · HTML ·    │      │  detectors · rule engine │
              │  diff · exec summary  │      └────────────┬────────────┘
              └───────────┬──────────┘                   │
                          │                              │
                 ┌────────▼──────────────────────────────▼─────────┐
                 │                 Core / Domain                     │  no Roslyn, no IO
                 │  CBOM object model · risk model · scoring ·       │
                 │  rule & detector contracts · confidence model     │
                 └───────────────────────────────────────────────────┘
```

**Dependency rule.** `Core` depends on nothing but BCL. `Analysis` and `Reporting` depend on `Core`. `Cli` depends on all three. Roslyn lives **only** in `Analysis` (and in the optional `Analyzers` package). This keeps the domain model — the thing auditors and downstream tools care about — independent of how findings were produced, so the same model can be populated by Roslyn today and by an IL/binary scanner or config scanner later.

### 1.2 The five concerns

| Concern | Responsibility | Lives in |
|---|---|---|
| **Model** | Immutable CBOM object graph (solution→project→file→finding), risk classes, confidence levels | Core |
| **Detection** | Turn Roslyn symbols/operations into `CryptoFinding`s via a rule registry | Analysis |
| **Assessment** | Apply risk-scoring + readiness-scoring + recommendation lookup to findings | Core (engine) + rule-supplied data |
| **Reporting** | Serialize the model to CycloneDX JSON / SARIF / Markdown / HTML; diff two CBOMs | Reporting |
| **Orchestration** | Resolve targets, load config, run the pipeline, set exit codes | Cli |

### 1.3 Processing pipeline

```
targets ─► resolve (sln/csproj/dir) ─► MSBuildWorkspace load ─► per-Compilation:
   semantic walk (IOperation + symbols) ─► rule registry match ─► raw findings
   ─► dedupe/merge ─► risk engine (classify + score) ─► recommendation bind
   ─► readiness scoring (project, solution) ─► CBOM model
   ─► [optional] baseline merge/diff ─► renderers ─► outputs + exit code
```

**Fail-closed seam.** Two failure modes are distinguished and never collapsed:

- **Analysis failure** (project won't load, compilation errors, detector throws): emitted as a first-class `scan.diagnostics` entry **and** reflected in coverage metrics and (configurably) exit code. A project that failed to compile is reported as **"not analyzed,"** never as **"clean."**
- **Finding-level uncertainty:** carried as **detection confidence** on each finding (never dropped). See §4.4 and §5.

---

## 2. Proposed project / folder structure

```
CryptographicBillOfMaterials/                      (repo root)
├─ src/
│  ├─ PostQuantum.CryptographicBillOfMaterials/                 # Core package (the library)
│  │  ├─ Model/            # CbomDocument, Component, CryptoFinding, Location, Evidence…
│  │  ├─ Risk/             # RiskLevel, QuantumThreat, RiskEngine, scoring formulas
│  │  ├─ Scoring/          # ReadinessScore calculators (project/solution), formula constants
│  │  ├─ Rules/            # ICryptoDetector, IRule, RuleContext, RuleId, Severity contracts
│  │  ├─ Knowledge/        # Embedded algorithm knowledge base (JSON) + loader
│  │  └─ Recommendations/  # Recommendation model + standards-based recommendation catalog
│  ├─ PostQuantum.CryptographicBillOfMaterials.Analysis/        # Roslyn engine (Core dep)
│  │  ├─ Workspace/        # MSBuild loading, target resolution, framework discovery
│  │  ├─ Detectors/        # Built-in detectors grouped by surface (Bcl, Jwt, BouncyCastle, Kms, Tls…)
│  │  ├─ Operations/       # IOperation/symbol helpers, constant + literal analysis
│  │  └─ Engine/           # ScanEngine, finding dedupe/merge, coverage tracking
│  ├─ PostQuantum.CryptographicBillOfMaterials.Reporting/       # Renderers (Core dep)
│  │  ├─ CycloneDx/        # CBOM (CycloneDX 1.6) writer + reader, profile constants
│  │  ├─ Sarif/            # SARIF 2.1.0 writer
│  │  ├─ Markdown/  Html/  # human reports + exec summary
│  │  └─ Diff/             # CBOM diff model + renderer
│  ├─ PostQuantum.CryptographicBillOfMaterials.Cli/             # dotnet-cbom global tool
│  │  ├─ Commands/         # scan, diff, report, list-rules, validate-config, version
│  │  └─ Configuration/    # cbom.config.json binding, layering, validation
│  └─ PostQuantum.CryptographicBillOfMaterials.Analyzers/       # OPTIONAL Roslyn analyzers (IDE/build)
│     └─ (DiagnosticAnalyzers reusing the same rule metadata as the scanner)
├─ tests/
│  ├─ …Core.Tests/  …Analysis.Tests/  …Reporting.Tests/  …Cli.Tests/
│  └─ …Analysis.IntegrationTests/      # fixture solutions compiled in-memory + golden CBOMs
├─ samples/                            # tiny solutions exercising each detector (also test fixtures)
├─ docs/
│  ├─ TECHNICAL-DESIGN.md  (this file)
│  ├─ THREAT-MODEL.md      (house convention)
│  ├─ KNOWN-GAPS.md        (house convention — what static analysis cannot see)
│  ├─ schema/cbom-profile-1.0.md   # the CycloneDX profile spec + JSON Schema overlay
│  └─ rules/               # one page per rule (basis, examples, remediation)
└─ Directory.Build.props / .editorconfig / global.json   # .NET 10 SDK pin, analyzers, nullable on
```

**Packaging.** Three shipped packages: `…CryptographicBillOfMaterials` (core library, usable standalone), `…Cli` (the `dotnet-cbom` tool), and the optional `…Analyzers`. `Analysis` and `Reporting` are separate assemblies but **may** ship inside the Core NuGet to keep the public dependency surface small — open question §8.

---

## 3. CBOM schema v1 — a CycloneDX profile

### 3.1 Decision: profile, do not fork

**Adopt** CycloneDX **1.6** as the base format (this is the version that upstreamed CBOM; *basis:* CycloneDX release notes / OWASP CBOM guide). **Track** 1.7's Cryptography Registry for canonical algorithm identifiers as a future enrichment. Output is a **valid CycloneDX 1.6 BOM** — any CycloneDX-aware tool (Dependency-Track, vendor scanners, GitHub) can ingest it without knowing about our profile. Our additions live in the schema's *sanctioned* extension points (`properties`, `evidence`) so they never break base-schema validation.

> ⚠ **NOT-SETTLED / verify before freeze:** the precise field set of `cryptoProperties` differs between the *original IBM CBOM proposal* and the *upstreamed CycloneDX 1.6 schema*. Notably, the IBM draft carried locations/confidence inside `cryptoProperties.detectionContext` / `confidenceLevels`; upstream CycloneDX represents source locations via the standard `component.evidence.occurrences` and identity confidence via `component.evidence.identity[].confidence`. **This design targets the upstream CycloneDX 1.6 schema.** The implementation's first task is to validate every emitted field against the official `bom-1.6.schema.json`; any field below that fails validation moves into `properties` (§3.5).

### 3.2 What we REUSE from base CycloneDX (unchanged)

| Base element | How we use it |
|---|---|
| `metadata` (timestamp, tools, component) | scan timestamp, tool name/version, root component = solution |
| `component` (type `application`/`library`) | one per project; the analyzed NuGet deps |
| `component` (type `cryptographic-asset`) | **one per distinct crypto finding** |
| `cryptoProperties.assetType` = `algorithm` \| `certificate` \| `protocol` \| `related-crypto-material` | primary classification of each finding |
| `cryptoProperties.algorithmProperties` (primitive, parameterSetIdentifier/variant, curve, mode, padding, cryptoFunctions, classicalSecurityLevel, nistQuantumSecurityLevel, executionEnvironment, implementationPlatform, certificationLevel) | algorithm parameters |
| `cryptoProperties.certificateProperties` / `protocolProperties` / `relatedCryptoMaterialProperties` | certs, TLS, keys/secrets |
| `cryptoProperties.oid` | algorithm OID where known (from Cryptography Registry) |
| `component.evidence.occurrences[]` (`location`, `line`, `offset`, `symbol`) | **finding source location** (file/line) |
| `component.evidence.identity[].confidence` (0.0–1.0) | numeric detection confidence |
| `dependencies[]` | finding→component→project hierarchy and algorithm→algorithm relationships (e.g., a protocol depends on its cipher suite) |

> ⚠ **NOT-SETTLED:** the documented numeric range of `nistQuantumSecurityLevel`. NIST defines **security categories 1–5**; some tooling encodes `0` as "unknown/none." Treat NIST category as 1–5 and represent "unknown" by **omitting** the field rather than writing `0`, unless schema validation requires otherwise. Verify against `bom-1.6.schema.json`.

### 3.3 What we ADD (the profile) — all via `properties`, namespace-qualified

To stay schema-valid, every PQC/risk concept the base schema lacks is expressed as a `name`/`value` pair under the reverse-DNS namespace **`io.github.systemslibrarian.cbom`** (shortened below to `cbom:` for readability). These attach to each `cryptographic-asset` component, to project components, and to `metadata`.

| Property name | Where | Value | Why it's an extension |
|---|---|---|---|
| `cbom:risk:level` | finding | `Critical`\|`High`\|`Medium`\|`Low`\|`Informational` | base schema has no risk verdict |
| `cbom:risk:score` | finding | `0–100` numeric | transparent score (§5) |
| `cbom:risk:basis` | finding | citation string (e.g., `NIST IR 8547 IPD §3; FIPS 197`) | auditor traceability |
| `cbom:quantum:vulnerable` | finding | `true`\|`false`\|`reduced-margin` | the central PQC verdict |
| `cbom:quantum:threat` | finding | `Shor`\|`Grover`\|`None`\|`HarvestNowDecryptLater` | mechanism of break |
| `cbom:detection:confidence` | finding | `Confirmed`\|`High`\|`Medium`\|`Low` | qualitative band paired with the numeric `evidence.identity.confidence` |
| `cbom:detection:method` | finding | `symbol`\|`constant`\|`heuristic`\|`config` | how it was found |
| `cbom:rule:id` | finding | e.g. `CBOM0007` | links to rule doc/SARIF |
| `cbom:recommendation:summary` | finding | one-line action | non-expert remediation |
| `cbom:recommendation:options` | finding | JSON array of standards-based options w/ tradeoffs | never single-vendor (§5.4) |
| `cbom:usage:context` | finding | `AtRest`\|`InTransit`\|`Signing`\|`Auth`\|`KeyExchange`\|`Hashing`\|`Unknown` | exposure weighting |
| `cbom:readiness:score` | project / metadata | `0–100` | PQC Readiness Score |
| `cbom:readiness:formulaVersion` | metadata | e.g. `1.0` | reproducibility |
| `cbom:coverage:projectsAnalyzed` / `…projectsFailed` | metadata | counts | fail-closed honesty |
| `cbom:baseline:ref` / `cbom:baseline:delta` | metadata / finding | prior CBOM id; `new`\|`unchanged`\|`resolved` | baselining |
| `cbom:profile:version` | metadata | `1.0` | our profile version, distinct from CycloneDX specVersion |

### 3.4 What we OVERRIDE / constrain

We override **nothing** in the base schema (overriding would break interop). We **constrain** it via the profile spec (`docs/schema/cbom-profile-1.0.md`): e.g., "a `dotnet-cbom` CBOM MUST set `metadata.component.type=application`; every `cryptographic-asset` MUST carry `evidence.occurrences` OR a `cbom:detection:method=config` property; every finding MUST carry `cbom:risk:level` and `cbom:detection:confidence`." A profile validator (ships in Reporting) enforces these on read/write.

### 3.5 Versioning

Two independent version axes, both recorded in `metadata`:
- **CycloneDX specVersion** — the base format (`1.6`).
- **`cbom:profile:version`** — our property semantics (`1.0`). Profile changes that add properties are minor; renaming/removing a property or changing a risk-score formula is **major** and also bumps `cbom:readiness:formulaVersion` so historical scores remain interpretable.

### 3.6 Illustrative fragment (one finding)

```jsonc
{
  "type": "cryptographic-asset",
  "bom-ref": "crypto/aes-ecb/PaymentService/Crypto.cs#42",
  "name": "AES-128-ECB",
  "cryptoProperties": {
    "assetType": "algorithm",
    "algorithmProperties": {
      "primitive": "block-cipher",
      "parameterSetIdentifier": "128",
      "mode": "ecb",
      "cryptoFunctions": ["encrypt"],
      "classicalSecurityLevel": 128,
      "nistQuantumSecurityLevel": 1
    },
    "oid": "2.16.840.1.101.3.4.1.1"
  },
  "evidence": {
    "occurrences": [{ "location": "src/PaymentService/Crypto.cs", "line": 42 }],
    "identity": [{ "field": "name", "confidence": 0.95 }]
  },
  "properties": [
    { "name": "cbom:risk:level", "value": "High" },
    { "name": "cbom:risk:score", "value": "78" },
    { "name": "cbom:risk:basis", "value": "ECB confidentiality failure (FIPS SP 800-38A); not quantum-related" },
    { "name": "cbom:quantum:vulnerable", "value": "reduced-margin" },
    { "name": "cbom:quantum:threat", "value": "Grover" },
    { "name": "cbom:detection:confidence", "value": "Confirmed" },
    { "name": "cbom:rule:id", "value": "CBOM0007" },
    { "name": "cbom:usage:context", "value": "AtRest" },
    { "name": "cbom:recommendation:summary",
      "value": "Replace ECB with AES-GCM (authenticated). Re-key from a KDF, not a hardcoded key." }
  ]
}
```

Note this finding is **High for a classical reason** (ECB) while only **reduced-margin** for quantum (AES-128/Grover). The tool keeps those two axes separate — see §4 and §5.

---

## 4. Core detection categories and rules

### 4.1 Two orthogonal axes (this is the core mental model)

Findings are scored on **two independent axes**, because conflating them produces wrong advice:

1. **Classical weakness** — is the primitive/usage broken or risky *today*, regardless of quantum? (ECB, MD5, RSA-512, hardcoded key.) *Basis:* FIPS/NIST SP 800-series, CWE.
2. **Quantum vulnerability** — does a cryptographically-relevant quantum computer break or weaken it? *Basis:* Shor's algorithm (asymmetric), Grover's algorithm (symmetric/hash, ~halving effective strength); NIST IR 8547 (IPD); CNSA 2.0.

A primitive can be strong on one axis and weak on the other. AES-256 is classically strong **and** quantum-strong; RSA-3072 is classically strong but quantum-**broken**; AES-128 is classically strong but quantum-**reduced-margin**.

### 4.2 The quantum verdict rules (the heart of the tool)

| Family | Quantum verdict | Basis (stated) |
|---|---|---|
| RSA, ECDSA, ECDH, DH, DSA, ElGamal, ECIES (any key size) | **Vulnerable** (Shor — fully broken) | NIST IR 8547 IPD; CNSA 2.0; well-established Shor result |
| AES-128, ChaCha20 (128-bit), symmetric ≤128-bit | **Reduced-margin** (Grover ~halves to ~64-bit) | NIST guidance that AES-128 has reduced PQ margin; Grover. ⚠ *NOT-SETTLED:* whether AES-128 is "acceptable" or "to-migrate" varies by program; CNSA 2.0 mandates AES-256 for NSS. We report reduced-margin + cite, do not declare "broken." |
| AES-192/256, ChaCha20-256 | **Not vulnerable** | Grover leaves ≥128-bit effective; CNSA 2.0 selects AES-256 |
| SHA-1, MD5 | **Vulnerable classically** (collisions) — separate from quantum | NIST SP 800-131A (SHA-1 disallowed); MD5 long broken |
| SHA-256 / SHA-384 / SHA-512 / SHA-3 | **Not vulnerable** (Grover halves preimage; still ≥128-bit) | NIST; CNSA 2.0 selects SHA-384/512 |
| ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205) | **PQC — positive signal** | FIPS 203/204/205 (finalized Aug 2024) |
| Hybrid (e.g., X25519+ML-KEM, ECDSA+ML-DSA) | **PQC hybrid — strongest positive signal** | NIST/IETF hybrid guidance; CNSA-aligned transition |

> ⚠ **NOT-SETTLED, surfaced prominently:** NIST IR 8547 is an **Initial Public Draft (Nov 2024)**. Its dates (RSA/ECC ~112-bit **deprecated 2030, disallowed 2035**) are authoritative-but-draft. CNSA 2.0 timelines (PQC code/firmware signing **preferred 2025 → mandatory 2030**; NSS broadly by ~2030–2033; NSM-10 federal target **2035**) apply firmly to **National Security Systems** and are **guidance, not law, for general industry.** The tool states which regime a date comes from and never implies a single universal deadline. *Basis to embed in the knowledge base, with citation strings.*

### 4.3 Detection categories (Roslyn surfaces)

Each detector matches on **fully-qualified symbols** via the semantic model (resilient to `using` aliases and partial names), inspects `IOperation` trees for arguments/constants, and emits findings with a category, rule id, and confidence.

| # | Category | Surfaces (examples) | Example weak/positive patterns |
|---|---|---|---|
| 1 | **Symmetric encryption** | `System.Security.Cryptography.Aes/TripleDES/DES/RC2`, `ChaCha20Poly1305`, BouncyCastle ciphers | ECB mode; DES/3DES/RC2 (deprecated, *SP 800-131A*); AES-128 (reduced PQ margin); **+** AES-256-GCM (good) |
| 2 | **Asymmetric / key exchange** | `RSA`, `ECDsa`, `ECDiffieHellman`, `DSA`, BouncyCastle | RSA < 2048 (disallowed, *SP 800-131A*); RSA/ECC all quantum-vulnerable (*IR 8547*); weak curves (P-192, secp*k1 where unexpected) |
| 3 | **Hashing / MAC** | `SHA1/MD5/SHA256/SHA512`, `HMAC*`, `KMAC` | MD5/SHA-1 (collision-broken); HMAC-MD5; **+** SHA-384/512 |
| 4 | **KDF / password hashing** | `Rfc2898DeriveBytes` (PBKDF2), `Argon2`(BC), `PasswordDeriveBytes` | `PasswordDeriveBytes` (legacy PBKDF1); low PBKDF2 iteration counts (heuristic, *OWASP*); MD5-based KDFs |
| 5 | **Digital signatures** | `RSA.SignData`, `ECDsa.SignData`, JWT signing, X.509 signing | RSA/ECDSA signing (quantum-vulnerable, esp. long-lived/code-signing per CNSA 2.0); **+** ML-DSA/SLH-DSA |
| 6 | **JWT / JOSE** | `System.IdentityModel.Tokens.Jwt`, `Microsoft.IdentityModel.*`, `SigningCredentials`, `EncryptingCredentials` | `alg=none`; HS256 with weak/sample key; RS256/ES256 (quantum-vulnerable signing); validation with `ValidateIssuerSigningKey=false` (heuristic) |
| 7 | **TLS / HTTPS / cert handling** | `SslProtocols`, `HttpClientHandler`/`SocketsHttpHandler` callbacks, `ServicePointManager`, `X509Certificate2` | `SslProtocols.Ssl3/Tls/Tls11`; `ServerCertificateCustomValidationCallback` returning `true` (cert validation disabled, *CWE-295*); SHA-1 signed certs |
| 8 | **Cloud KMS** | `Azure.Security.KeyVault.Keys/Certificates`, `Amazon.KeyManagementService`, GCP KMS | inventory of which KMS-managed keys/alg specs are used (often *positive* — managed rotation); RSA/EC key specs flagged quantum-vulnerable |
| 9 | **Randomness** | `System.Random`, `Guid.NewGuid` used as secret | non-CSPRNG used for keys/tokens/IVs (*CWE-338*) → recommend `RandomNumberGenerator` |
| 10 | **Hardcoded keys / secrets** | byte[]/string literals flowing into key/IV/password params; base64 constants | hardcoded symmetric keys, IVs, JWT signing keys (*CWE-321/798*) — constant-flow analysis |
| 11 | **PQC usage (positive)** | `PostQuantum.*` packages, ML-KEM/ML-DSA/SLH-DSA APIs, OQS bindings, hybrid constructions | recorded as positive signals that *raise* the readiness score |

Each rule gets a one-page doc in `docs/rules/CBOMxxxx.md`: trigger, **basis with citation**, example code, confidence rationale, and remediation options.

### 4.4 Detection confidence (never dropped, always shown)

| Band | Numeric (`evidence.identity.confidence`) | Meaning |
|---|---|---|
| **Confirmed** | 0.95–1.0 | resolved symbol + concrete constant (e.g., `CipherMode.ECB` literal; `new DESCryptoServiceProvider()`) |
| **High** | 0.8–0.94 | resolved symbol, parameter not statically known (e.g., `Aes.Create()` with key size from variable) |
| **Medium** | 0.5–0.79 | symbol resolved but behavior depends on runtime/config; or matched via a known wrapper |
| **Low** | 0.2–0.49 | heuristic/name-based match (custom wrapper named `*Crypto*`, string `"SHA1"`) |

Confidence affects presentation and (slightly) score, **but a high-risk finding is never suppressed for low confidence** — see §5.5 tension resolution.

### 4.5 What static analysis cannot see (stated up front; expanded in `KNOWN-GAPS.md`)

- **Runtime/config-driven algorithm selection** (alg name from `appsettings.json`, env var, DB, feature flag).
- **Crypto inside opaque dependencies** (a NuGet/native lib that does crypto we never see source for — partially mitigated by KMS/package detection, not fully).
- **Reflection / dynamic dispatch** (`CryptoConfig.CreateFromName(userInput)`).
- **Data sensitivity & lifetime** — the tool can't know a key protects 30-year records (which dominates harvest-now-decrypt-later risk). It asks via config hints (§6) and otherwise flags conservatively.
- **Actual deployment** (TLS may be terminated at a load balancer the code never references).

**Consequence, stated everywhere it matters:** *a clean scan means "no detectable issues in analyzed source," not "the system is quantum-safe."* This sentence appears in the executive summary, the CLI footer, and the report header. This is a deliberate anti-false-confidence measure.

---

## 5. Risk-scoring methodology (fully transparent)

All formulas are versioned (`cbom:readiness:formulaVersion`), deterministic, and documented so any number can be recomputed by hand from the CBOM.

### 5.1 Finding-level risk

Each finding gets a 0–100 **risk score** and a **risk level**. The score is a transparent weighted combination of four factors, each on 0–1:

```
RiskScore = round(100 * clamp(
      0.45 * Q        // quantum factor
    + 0.35 * C        // classical-weakness factor
    + 0.20 * X        // usage-exposure factor
  ) * Conf_adj )      // confidence adjustment (presentation only; see 5.5)
```

**Q — quantum factor** (basis: §4.2 table)

| Verdict | Q |
|---|---|
| Vulnerable (Shor — RSA/ECC/DH) | 1.0 |
| Vulnerable classically only is **not** counted here (goes to C) | — |
| Reduced-margin (AES-128/Grover) | 0.4 |
| Not vulnerable / PQC | 0.0 |

**C — classical-weakness factor** (basis: SP 800-131A, FIPS, CWE)

| Condition | C |
|---|---|
| Broken (MD5, SHA-1 collisions, DES, ECB, `alg=none`, hardcoded key, disabled cert validation) | 1.0 |
| Disallowed/deprecated by NIST (RSA<2048, 3DES, P-192) | 0.7 |
| Suboptimal (low PBKDF2 iterations, non-CSPRNG) | 0.4 |
| None | 0.0 |

**X — usage-exposure factor** (from `cbom:usage:context`; reflects blast radius + HNDL)

| Context | X | Rationale |
|---|---|---|
| KeyExchange / InTransit / AtRest (long-lived) | 1.0 | harvest-now-decrypt-later applies to confidentiality of recorded traffic/data |
| Signing / Auth | 0.7 | forgery risk; code-signing especially (CNSA 2.0) |
| Hashing / general | 0.4 | |
| Unknown | 0.6 | conservative midpoint (fail toward attention) |

**Risk level banding** (after scoring):

| Score | Level |
|---|---|
| ≥ 80 | Critical |
| 60–79 | High |
| 40–59 | Medium |
| 20–39 | Low |
| < 20 | Informational |

**Override floors (fail-closed).** Certain conditions set a **minimum** level regardless of formula: `alg=none`, hardcoded private/signing key, and disabled TLS cert validation are **≥ Critical**; any Shor-vulnerable algorithm protecting AtRest/InTransit long-lived data is **≥ High**. Floors are listed in the rule docs with their basis.

### 5.2 PQC Readiness Score (project and solution)

A 0–100 score answering: *"of the cryptography we can see that quantum matters for, how much is already quantum-safe?"* Only **quantum-relevant** assets count (a hardcoded key is a serious classical finding but is **not** in the readiness denominator — it's reported separately so the two stories don't contaminate each other).

```
Let assets = all findings where quantum verdict ∈ {Vulnerable, Reduced-margin, NotVulnerable-but-PQ-relevant, PQC}

weight(asset) = base_weight[quantum verdict] * exposure_weight[usage]   // both from tables below

safe_weight   = Σ weight(asset) for asset that is PQC or quantum-not-vulnerable
total_weight  = Σ weight(asset) for all quantum-relevant assets

ReadinessScore = round(100 * safe_weight / total_weight)     // 100 if no quantum-relevant assets, see note
```

`base_weight` by verdict: Vulnerable = 1.0, Reduced-margin = 0.5, NotVulnerable = 1.0 (counts in numerator and denominator), PQC = 1.0, **PQC-hybrid = 1.1** (small bonus rewarding the recommended end-state). `exposure_weight` reuses the X table (×1.0/0.7/0.4/0.6).

**Worked transparency.** Every report shows the arithmetic: e.g., *"Readiness 62 = 100 × (safe 18.4 / total 29.7). 3 RSA key-exchange sites (weight 3.0) and 1 ECDSA signing site (0.7) are the largest gaps."* No black box.

> **Edge case (stated):** a project with **zero** quantum-relevant crypto scores **100 but is flagged `coverage:trivial`** so "100" is never mistaken for "audited & migrated." A project that **failed to analyze** scores **N/A**, never 100.

### 5.3 Baselining / trend

A scan can take `--baseline previous.cbom.json`. Findings are matched by stable `bom-ref` (algorithm + normalized location + rule id). Each finding gets `cbom:baseline:delta` = `new` | `unchanged` | `resolved`. Metadata records score deltas, enabling *"quantum-vulnerable findings down 47% since 2026-03-01; readiness 51 → 62."* The diff is also a standalone command (§6).

### 5.4 Recommendations — standards-first, never single-vendor

Each rule supplies an **ordered list of options**, every one tied to a standard, with tradeoffs. `PostQuantum.*` packages may appear **as one option among standards-based alternatives, never as the only path** (a crypto-inventory tool that only recommends its author's packages is an auditor trust liability — explicit product rule). Example for an RSA key-exchange finding:

```
1. Hybrid KEM: X25519 + ML-KEM-768  (NIST FIPS 203; CNSA 2.0 transition posture)
     + safe today even if one half breaks; - newer, library support varies.
2. Pure ML-KEM-768 once peers support it (FIPS 203).
     + simplest end state; - no classical fallback during transition.
3. If migration must wait: ensure RSA ≥ 3072 AND record in migration plan (IR 8547).
     + buys time; - still quantum-vulnerable; interim only.
   (Implementation aids, optional: BouncyCastle, Open Quantum Safe, PostQuantum.Hybrid.)
```

**Misuse-resistance invariant:** the recommendation engine asserts that no recommended option is *weaker* than the detected state on either axis. A recommendation that would lower security is a bug caught by a unit test (`Recommendations_NeverDowngrade`).

### 5.5 Named tension: fail-closed vs. low-noise

These pull against each other. Resolution:

- **High-risk axis → fail-closed wins.** Critical/High findings are always emitted, even at Low confidence; confidence is shown so the user can triage, but nothing high-risk is hidden. Override floors (§5.1) cannot be suppressed by config.
- **Low-risk / informational axis → low-noise wins.** Informational and Low findings are collapsed/summarized by default and can be filtered by config; positive PQC signals are aggregated. Confidence *lowers ordering and the score slightly* (`Conf_adj` ∈ [0.9, 1.0]) but **cannot move a Critical/High below its floor.**
- **Net effect:** noise reduction happens at the bottom of the risk stack, never at the top. This is the only safe way to reconcile the two principles, and it's encoded so config can't violate it.

---

## 6. CLI command design

`dotnet-cbom` (built on `System.CommandLine`). Non-interactive by default; every command supports `--output`, `--format`, `--quiet`, `--verbosity`. Configuration layering: CLI args > `cbom.config.json` (nearest to target) > built-in defaults.

### 6.1 Command surface

| Command | Purpose |
|---|---|
| `scan` | Analyze a solution/project/directory → CBOM (+ other formats) |
| `diff` | Compare two CBOMs → progress/regression report |
| `report` | Re-render an existing CBOM to md/html/sarif/exec-summary (no re-scan) |
| `list-rules` | List detectors/rules with id, category, basis |
| `validate-config` | Validate a `cbom.config.json` against schema |
| `version` | Tool + profile + CycloneDX spec versions |

### 6.2 Exit codes (CI-friendly, fail-closed)

| Code | Meaning |
|---|---|
| 0 | Completed; no findings at/above `--fail-on` threshold |
| 1 | Completed; findings at/above threshold (default `--fail-on High`) |
| 2 | Partial analysis — one or more targets failed to load/compile (fail-closed signal) |
| 3 | Usage/config error |
| 4 | Internal error |

`--fail-on none` decouples the gate (always exit 0 on findings) for inventory-only CI stages; partial-analysis still returns 2 unless `--allow-partial`.

### 6.3 `scan` help (excerpt)

```
dotnet-cbom scan — Generate a Cryptographic Bill of Materials for .NET code.

USAGE
  dotnet-cbom scan <target> [options]

ARGUMENTS
  <target>   Path to a .sln, .csproj, or directory. Defaults to current directory.

OPTIONS
  -o, --output <dir>        Output directory (default: ./cbom-out)
  -f, --format <list>       cyclonedx,sarif,markdown,html,summary  (default: cyclonedx,summary)
      --baseline <file>     Prior CBOM to compute deltas against
      --fail-on <level>     Min level that sets exit 1: critical|high|medium|low|none (default: high)
      --allow-partial       Don't return exit 2 when some targets fail to analyze
      --config <file>       Path to cbom.config.json (default: discovered near target)
      --include / --exclude <glob>   Path filters
      --min-confidence <band>        Hide findings below band in HUMAN reports only
                                     (machine outputs always include all; default: low)
  -v, --verbosity <level>   quiet|normal|detailed   (default: normal)

EXAMPLES
  dotnet-cbom scan ./MyApp.sln
  dotnet-cbom scan . --format cyclonedx,sarif --fail-on critical
  dotnet-cbom scan ./MyApp.sln --baseline ./last.cbom.json -o ./artifacts
```

### 6.4 Example `scan` run (console summary)

```
$ dotnet-cbom scan ./PaymentPlatform.sln --baseline ./baseline.cbom.json

dotnet-cbom 1.0.0  ·  CycloneDX 1.6  ·  profile 1.0
Loading PaymentPlatform.sln … 7 projects, target frameworks: net8.0, net10.0

Analyzed 6/7 projects.   ⚠ 1 project failed to load (see diagnostics) — reported as NOT analyzed.

Cryptographic findings: 23   (Critical 2 · High 5 · Medium 9 · Low 4 · Info 3)
PQC positive signals:   2    (1 hybrid X25519+ML-KEM in Gateway)

Top findings
  CRIT  CBOM0021  JWT 'alg=none' accepted in token validation   Auth/JwtValidator.cs:58   [Confirmed]
  CRIT  CBOM0010  Hardcoded AES key                             Payments/Crypto.cs:42     [Confirmed]
  HIGH  CBOM0002  RSA-2048 key exchange (quantum-vulnerable)    Gateway/Tls.cs:91         [High]
  HIGH  CBOM0007  AES-128-ECB (no confidentiality, ECB)         Payments/Crypto.cs:42     [Confirmed]
  …

PQC Readiness:  Gateway 71 · Payments 38 · Identity 55  →  Solution 54
  Solution 54 = 100 × (safe 21.6 / total 40.0). Largest gaps: 3 RSA KEX, 4 RSA/ECDSA signing.

Baseline (2026-03-01): quantum-vulnerable findings 19 → 14  (−26%).  Readiness 47 → 54.

Wrote: cbom-out/cbom.json, cbom-out/summary.md
Note: a clean scan means "no detectable issues in analyzed source," not "the system is quantum-safe."
Exit code: 1  (findings ≥ High)
```

### 6.5 Example `diff` run

```
$ dotnet-cbom diff baseline.cbom.json current.cbom.json --format markdown -o diff.md

CBOM diff  baseline(2026-03-01) → current(2026-06-28)

Resolved (7):
  + RSA-2048 KEX in Gateway/Tls.cs       → now hybrid X25519+ML-KEM   ✔
  + AES-128-ECB in Reporting/Export.cs   → now AES-256-GCM            ✔
New (2):
  - SHA-1 signature in Vendor/Legacy.cs:12   (High)
Unchanged (12)

Quantum-vulnerable findings: 19 → 14 (−26%)   ·   Readiness 47 → 54 (+7)
Regression check: 0 findings moved to a higher risk level.   PASS
```

### 6.6 Example CI invocation (GitHub Actions)

```yaml
- name: Cryptographic Bill of Materials
  run: |
    dotnet tool install -g PostQuantum.CryptographicBillOfMaterials.Cli
    dotnet-cbom scan ./src --format cyclonedx,sarif --fail-on critical --baseline ./.cbom/baseline.json -o ./.cbom/out
- name: Upload SARIF to code scanning
  uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: ./.cbom/out/cbom.sarif }
- name: Publish CBOM artifact
  uses: actions/upload-artifact@v4
  with: { name: cbom, path: ./.cbom/out/cbom.json }
```

`--fail-on critical` keeps the pipeline green while inventory matures, while SARIF lights up GitHub code scanning and the CBOM artifact feeds Dependency-Track or an auditor.

### 6.7 `cbom.config.json` (shape)

```jsonc
{
  "$schema": "https://.../cbom.config.schema.json",
  "include": ["src/**"],
  "exclude": ["**/*.Tests/**", "**/Generated/**"],
  "failOn": "high",
  "formats": ["cyclonedx", "sarif", "summary"],
  "rules": {
    "CBOM0019": { "enabled": false },           // suppress a rule (recorded in CBOM as a waiver)
    "CBOM0007": { "severityFloor": "critical" } // can RAISE, never silently lower a floor
  },
  "dataSensitivityHints": {                      // optional, improves exposure scoring (§4.5)
    "src/Payments/**": { "dataLifetimeYears": 25 }   // long-lived → stronger HNDL weighting
  },
  "baseline": ".cbom/baseline.json"
}
```

Suppressions are **recorded in the CBOM as explicit waivers** (with who/why if provided) — never an invisible deletion. This preserves "never silently drop a finding" even when a team chooses to mute one.

---

## 7. Extensibility model

### 7.1 The detector contract

A detector is a small, focused unit keyed to the symbols it cares about. Sketch (illustrative, not final API):

```csharp
public interface ICryptoDetector
{
    string RuleId { get; }                 // "CBOM0007"
    DetectorMetadata Metadata { get; }     // category, default severity, basis citation, doc URL
    // Symbols this detector subscribes to; the engine indexes by these so each
    // syntax node is dispatched only to interested detectors (performance).
    IEnumerable<SymbolSelector> Triggers { get; }

    void Inspect(DetectionContext ctx);    // ctx exposes IOperation, SemanticModel,
                                           //  constant-flow helpers, and ctx.Report(finding)
}
```

- **`SymbolSelector`** matches fully-qualified type/member names (e.g., `System.Security.Cryptography.Aes.Create`) so the engine can build an index and dispatch efficiently rather than every detector walking every node.
- **`DetectionContext`** offers high-level helpers: `TryGetConstant(arg, out value)`, `GetEnumArgument(...)`, `TracesToLiteral(...)` for hardcoded-key analysis — so rule authors don't reimplement constant flow.
- **Findings carry the rule's `basis` citation by construction** — you cannot register a "weak" verdict without a basis string. This enforces the accuracy-over-confidence principle at the type level.

### 7.2 Knowledge base (data, not code)

Algorithm facts (quantum verdict, classical status, OIDs, NIST levels, citations, recommendation options) live in an **embedded JSON knowledge base**, separate from detector code. Adding "P-192 is disallowed, here's the basis" is a data edit reviewed like a security change, not a code change. The knowledge base is also exposed via `list-rules --json` for auditor inspection and is versioned with the profile.

### 7.3 Plugin discovery

Three extension tiers, lowest-friction first:

1. **Config-only:** enable/disable/retune existing rules and add `dataSensitivityHints` via `cbom.config.json`. (Most users.)
2. **External detector assemblies:** `dotnet-cbom scan … --plugin ./MyRules.dll` (and a `plugins[]` config key). The engine loads via a dedicated `AssemblyLoadContext`, discovers `ICryptoDetector` implementations, validates each has a unique `RuleId` + basis, and merges them into the registry. Untrusted-plugin caveat documented in THREAT-MODEL.md (plugins run as code).
3. **Custom reporters:** `IReportRenderer { string Format; Task RenderAsync(CbomDocument doc, Stream output); }` discovered the same way, so a team can emit, e.g., their internal GRC format without forking.

### 7.4 Roslyn analyzers package (optional, build/IDE-time)

The optional `…Analyzers` package reuses the **same rule metadata** to surface the highest-confidence, highest-value findings (e.g., `alg=none`, ECB, hardcoded key, SHA-1) as live diagnostics in the IDE and build. It is a *subset* of the scanner (only Confirmed/High-confidence, low-false-positive rules) — it is **not** a replacement for `scan`, and the doc says so to avoid teams assuming the analyzer covers everything the CBOM does.

---

## 8. Assumptions, known limitations, and open questions

### 8.1 Assumptions

- Targets are buildable/restoreable .NET 8+ projects; `MSBuildWorkspace` (via the .NET 10 SDK) can load them. Non-restorable projects degrade to lower-confidence syntactic analysis (and are marked partial).
- Auditors/consumers value **CycloneDX + SARIF interop** over a bespoke format — the whole schema strategy rests on this.
- Teams want a **CI gate they can tune** (start at `critical`, ratchet down) rather than an all-or-nothing fail.
- A finding's `bom-ref` (algorithm + normalized location + rule id) is **stable enough** across scans for baselining; minor churn is acceptable and surfaced as new/resolved pairs.

### 8.2 Known limitations (also → `KNOWN-GAPS.md`)

- Cannot see runtime/config-selected algorithms, crypto in opaque binaries, reflection-based selection, or real deployment/TLS termination (§4.5).
- Cannot assess data sensitivity/lifetime without hints — central to harvest-now-decrypt-later risk, which the tool can therefore only approximate.
- Static key-size/curve detection is best-effort when values come from variables/config (reported as High, not Confirmed).
- The Analyzers package covers only a high-confidence subset (§7.4).
- NIST IR 8547 dates are **draft**; CNSA 2.0 dates apply firmly only to NSS. The tool cites regimes precisely but cannot tell a given org which regime binds it.

### 8.3 Open questions for the human (RULED 2026-06-28 — all recommendations accepted)

> **Decision of record (2026-06-28):** the human accepted every recommendation below. Implementation proceeds on these settings: (1) fold `Analysis`+`Reporting` into Core for v1; (2) require .NET SDK present for `scan`; (3) AES-128 = `reduced-margin` by default with opt-in `cnsa2` profile; (4) `bom-ref` = normalized location + symbol-path hash; (5) ship `nist-general` default + `cnsa2` opt-in; (6) emit CycloneDX 1.6 with registry-aligned OIDs, hold 1.7 output; (7) crypto-key/IV/JWT-key literals only, defer general secret scanning.

1. **Packaging granularity.** Ship `Analysis` + `Reporting` *inside* the Core NuGet (smaller surface, simpler) or as separate packages (cleaner deps, more to version)? *Recommendation: fold into Core for v1; split later if demand appears.*
2. **MSBuild dependency in the global tool.** `MSBuildWorkspace` needs an MSBuild/SDK resolution path. Acceptable to **require the .NET SDK present** (not just runtime) for `scan`, and document it? *Recommendation: yes — SDK-present is the norm for the target users and avoids shipping a buildless analyzer that silently under-reports.*
3. **AES-128 verdict wording.** Report as `reduced-margin` (this design) or harden to `to-migrate` for CNSA-aligned orgs? Affects score and noise. *Recommendation: `reduced-margin` by default, with a `--profile cnsa2` switch that promotes it — see Q5.*
4. **`bom-ref` stability vs. file churn.** Is location-based ref acceptable, or do we need a content/AST-hash component to survive reformatting? *Recommendation: include a normalized symbol-path hash alongside location to reduce false "resolved/new" churn.*
5. **Compliance "profiles."** Should v1 ship selectable regimes (`--profile cnsa2 | nist-ir8547 | nist-general`) that adjust verdict floors and deadline language, or is one default enough? *Recommendation: ship `nist-general` as default and `cnsa2` as an opt-in profile; defer others.*
6. **Cryptography Registry adoption (CycloneDX 1.7).** Pull in 1.7's registry OIDs/identifiers now (richer, but 1.7 is newer/less widely ingested) or stay on 1.6 and enrich later? *Recommendation: emit 1.6, populate registry-aligned OIDs where known, hold 1.7 output until downstream support is common.*
7. **Secret detection depth.** How far should hardcoded-secret constant-flow analysis go before it overlaps/duplicates dedicated secret scanners (e.g., should we defer deep secret hunting to those and only flag the obvious crypto-key cases)? *Recommendation: cover crypto-key/IV/JWT-key literals only; explicitly defer general secret scanning and say so.*

---

### Appendix A — Sources consulted (for the bases cited above)

- CycloneDX CBOM capability & guide; CBOM upstreamed in **CycloneDX 1.6**, Cryptography Registry in **1.7** — cyclonedx.org, OWASP.
- IBM/CBOM reference (cryptoProperties field structure) — github.com/IBM/CBOM.
- **NIST IR 8547 (Initial Public Draft, Nov 2024)**, *Transition to Post-Quantum Cryptography Standards* — nvlpubs.nist.gov. ⚠ draft.
- **FIPS 203 / 204 / 205** (ML-KEM / ML-DSA / SLH-DSA, finalized Aug 2024) — NIST CSRC.
- **CNSA 2.0** suite & timeline (NSA); **NSM-10** (federal migration target 2035).
- **NIST SP 800-131A / 800-38A**, **FIPS 197** (algorithm transitions, modes, AES).
- **SARIF 2.1.0** (OASIS) for tooling interop.

*These ground the design's claims; the implementation must re-verify each citation string embedded in the knowledge base against the primary source at build time.*
