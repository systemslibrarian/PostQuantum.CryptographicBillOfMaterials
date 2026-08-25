# ADR 0003 — PQC migration playbooks

- Status: Accepted
- Date: 2026-06-29

## Context

The tool inventoried crypto, classified quantum risk, and emitted a one-line, standards-based
recommendation per finding (e.g. *"Migrate to a hybrid KEM (X25519+ML-KEM) or ML-DSA for signatures"*).
That answers *what* to migrate to, but the audience — .NET teams with no in-house cryptographer — is left
with the hard part: *how, in .NET, today.* Which API? Is it in-box yet? What does the code look like? What
breaks (key/signature sizes, platform support, peer interop)? Without that, the inventory is a to-do list
nobody knows how to action, and the mission ("help thousands of programmers transition to PQC") is unmet.

## Decision

Add **migration playbooks**: concrete, .NET-specific, standards-cited transition guides, keyed by the class
of vulnerable primitive.

- **Knowledge as data.** Playbooks live in `Knowledge/playbooks.json` (embedded), reviewable and citable
  independently of detector code — the same discipline as `algorithms.json`. Each algorithm in
  `algorithms.json` references its applicable playbooks via `migrationPlaybookIds`; a knowledge-base test
  enforces referential integrity and that every Shor-vulnerable algorithm has at least one playbook.
- **Two playbooks, mapped by use.** `pqc-key-establishment` (RSA key transport, ECDH, DH) and
  `pqc-signatures` (RSA signing, ECDSA, DSA). RSA references both because it is used for both.
- **Each playbook is actionable.** Applicability + harvest-now-decrypt-later framing, a one-line target end
  state, ordered implementation **approaches** (in-box .NET 10 `System.Security.Cryptography`
  `MLKem`/`MLDsa`/`SlhDsa` with worked code; the often-no-code-change TLS path via `X25519MLKEM768`;
  hybrid mode; BouncyCastle for pre-.NET-10/unsupported OS), per-approach caveats, ordered migration
  **steps**, and authoritative **references** (FIPS 203/204/205, NIST IR 8547, .NET docs).
- **Baked, then rendered.** Applicable playbook IDs are resolved from the canonical algorithm at scan time
  and stored on each `CryptoFinding`, so the CBOM is self-contained and the IDs survive serialization. The
  Markdown and HTML reports render the full playbook (deduplicated across findings); the CycloneDX output
  carries a machine-readable `cbom:migration:playbooks` pointer. Full content stays in the knowledge base —
  `cbom:knowledgeBase:version` records which version produced the BOM — keeping the artifact small but
  traceable.

## Consequences

- A non-cryptographer can go from a finding to working PQC code without leaving the report.
- Code examples were authored against **verified** current .NET 10 APIs (`MLKem.GenerateKey` /
  `Encapsulate` / `Decapsulate`, `MLDsa.GenerateKey` / `SignData` / `VerifyData`, `IsSupported`), not memory.
  They must be re-reviewed when the .NET PQC surface changes — the playbook content version (`PlaybooksVersion`)
  and a drift-guard test on the playbook ID set make changes deliberate.
- Guidance is honest about cost: PQC key/signature sizes, OpenSSL 3.5 / Windows 11 platform requirements, and
  peer-interop caveats are stated, not hidden.
- New output is additive and namespaced; the CBOM still validates against the official CycloneDX 1.6 schema.
