# ADR 0002 — Intra-method taint analysis for weak-RNG key material

- Status: Accepted
- Date: 2026-06-28

## Context

CBOM0050 (non-cryptographic RNG) was either uniformly low-severity or, in a later iteration, elevated by
**identifier-name matching** (a variable/method named `key`, `token`, …). That heuristic both:

- **missed** real flows with neutral names — `rnd.NextBytes(buf); aes.Key = buf;`, and
- **false-positived** on innocent names — `var keyboardLayout = new Random();`.

For a tool whose value is trustworthy verdicts, "looks like a secret by its name" is not good enough.

## Decision

Introduce `CryptoTaintAnalysis`: a bounded, **intra-procedural forward dataflow** that tracks weak randomness
(`System.Random` / `Random.Shared`) through local assignments and buffer fills into key/IV/nonce sinks:

- **Sources**: `new Random()`, `Random.Shared`, and locals assigned from them.
- **Taint**: buffers passed to `NextBytes`, and values from `Next*()`, propagated across local def-use.
- **Sinks**: assignment to `.Key`/`.IV`/`.Nonce`; `SymmetricSecurityKey`/`HMAC*` constructors; and *escapes*
  (return / field-property assignment) **only when the member name is sensitive** — names disambiguate
  escapes but are never the sole signal.

CBOM0050 now elevates to Broken/High only when taint reaches a sink; otherwise it stays low-noise.

## Consequences

- Catches name-independent flows and removes the keyboard-style false positive (both unit-tested).
- **Honest limits** (documented in KNOWN-GAPS): single-method only — cross-method/constructor-injected key
  flows are not tracked; branch/loop semantics are approximated by a linear pass; only `System.Random` /
  `Random.Shared` are sources. These are acceptable trade-offs for a sound-enough, low-FP local analysis, and
  are stated rather than hidden.
- The analysis is reusable: the same sink model can later back stronger CBOM0022/CBOM0030 provenance.
