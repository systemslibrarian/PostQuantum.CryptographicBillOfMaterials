# Accuracy and limitations

This page is updated every release. It states, plainly, what `dotnet-cbom` is good at, where it is weak, and
how to read its output. The honest framing is deliberate: **a clean scan means "no detectable issues in the
analyzed source," not "the system is quantum-safe."**

## What it is reliable at

- Finding **BCL cryptography** by symbol: AES/3DES/DES/RC2, RSA/ECDSA/ECDH/DSA, MD5/SHA-family, ECB mode,
  hardcoded keys/IVs, deprecated TLS, disabled certificate validation, weak KDFs, `System.Random`.
- Separating **classical weakness** (MD5, ECB) from **quantum vulnerability** (RSA, ECC) — two different axes,
  never collapsed into one number.
- Producing a **standards-cited basis** for every verdict and a **recommendation that is never less safe**
  than what it found (enforced by tests).
- **Deterministic, schema-valid CycloneDX 1.6** output suitable for diffing and audit.

## Where it is weak (by design or by current build)

| Limitation | Kind | Mitigation |
|---|---|---|
| Crypto inside third-party packages | Inherent (static analysis) | CBOM0080 (Bouncy Castle), CBOM0081 (package manifest), KMS depth |
| Runtime/config-driven algorithm selection | Inherent | Stated in every report; supply `dataSensitivityHints` |
| Reflection / dynamic dispatch | Inherent | — |
| Data sensitivity & lifetime | Inherent (not in code) | `dataSensitivityHints` (path + namespace) drive HNDL elevation |
| TLS terminated at a load balancer | Inherent (not in code) | — |
| Full intra-method dataflow (IV/nonce/key tracking) | Current build | `aes.KeySize` is tracked; broader flow is heuristic |
| Third-party symbols in no-MSBuild fallback | Current build | Use `--restore`; manifest inventory still fires |

See [KNOWN-GAPS.md](KNOWN-GAPS.md) for the complete, maintained list.

## False positives / false negatives

- **False positives** are kept low by requiring symbol/semantic confirmation where possible and by gating
  heuristics (e.g., weak-RNG elevation only fires on security-sensitive identifiers). Every rule ships with
  positive **and** negative fixtures.
- **False negatives** are expected for the inherent limits above. The tool never claims completeness; the
  coverage statement and `KNOWN-GAPS` are emitted alongside results so a clean scan is not mistaken for proof.

## How to read a verdict

Every finding carries: rule id, source location, detection confidence, **classical** verdict, **quantum**
verdict, transparent 0–100 score (recomputable by hand from the CBOM), standards basis (with draft/final
status), policy profile, and a recommendation. "Why is this High?" is answerable from those fields alone.

## Citation status

Draft vs. final guidance is labelled in-line. Notably, **NIST IR 8547 is a DRAFT** (initial public draft,
Nov 2024) and is cited as such; **CNSA 2.0** binds national-security systems firmly and is offered to
industry as guidance via the `cnsa2` profile. See [RULES.md](RULES.md) for the per-rule citation table.
