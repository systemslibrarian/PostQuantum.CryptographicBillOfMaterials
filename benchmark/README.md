# Accuracy benchmark

This benchmark turns "we think the detectors are accurate" into **reproducible, auditable evidence**. It
runs the real detector pipeline over a labeled corpus and measures precision and recall against
independently-authored ground truth. The generated results live in [`ACCURACY.md`](ACCURACY.md).

## How it works

- [`corpus/`](corpus/) holds small, single-purpose C# files. Each declares the findings it **should**
  produce as a comment, written from the rule's intent (not from the tool's output):
  - `// EXPECT: CBOM0002` — this file must produce that finding.
  - `// EXPECT: CBOM0050@High` — and at that severity (used to prove context discrimination).
  - `// EXPECT-CLEAN` — this file must produce **no** findings (a false-positive trap).
- The `AccuracyBenchmark` test compiles each file in-memory and runs the same `ScanEngine` /
  `DetectorRegistry` the CLI uses, then compares detected findings to the labels:
  - a labeled finding not detected → **false negative** (hurts recall),
  - a detected finding not labeled → **false positive** (hurts precision),
  - a severity-pinned label whose level isn't met → **severity mismatch**.
- The test **fails CI** on any false negative, false positive, or severity mismatch, and rewrites
  `ACCURACY.md`. The corpus is therefore the detection contract: changing detector behavior must update it.

## What the corpus deliberately covers

- **True positives** across the source-detectable rules (asymmetric/Shor, symmetric, ECB, hashes, hardcoded
  keys, weak KDF, deprecated TLS, disabled cert validation, JWT, weak RNG, PQC-positive).
- **False-positive traps**: good crypto that must *not* be flagged — strong PBKDF2 iterations, and ordinary
  business code whose identifiers (`key`, `token`) would fool a name-only scanner.
- **Context discrimination** via severity pins: `System.Random` for a dice roll stays **Low**, but
  `System.Random` flowing into an AES key is **High**; AES-256 is **Informational**, DES is **High**.

## Honest scope

This measures the tool **against its own claimed coverage on curated cases**. It is *not* a claim about
arbitrary real-world code — the inherent limits of static analysis still apply (see
[`../docs/KNOWN-GAPS.md`](../docs/KNOWN-GAPS.md)). Out of corpus scope: **CBOM0081** (package-manifest
inventory) is evaluated from `project.assets.json` rather than source, so it is exercised by CLI tests.
Symbol-based third-party rules (KMS, Bouncy Castle) rely on resolvable packages in practice; here they use
in-file stubs to stay SDK-only and reproducible.

## Regenerating

```bash
dotnet test tests/PostQuantum.CryptographicBillOfMaterials.Tests --filter FullyQualifiedName~AccuracyBenchmark
```
