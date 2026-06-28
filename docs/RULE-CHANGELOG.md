# Rule changelog

Deliberate changes to the rule set — additions, severity/basis changes, detector-behavior changes. A drift
guard test (`DriftGuardTests`) fails the build if the rule-id set changes without updating its snapshot, so
every entry here corresponds to an intentional change.

## Unreleased

### Added
- **CBOM0022** — Unsigned/weak-keyed JWT algorithm. Basis: RFC 8725, RFC 7518. Default floor: Critical for
  `alg=none`/hardcoded key, High for sub-256-bit HMAC key.
- **CBOM0042** — X.509 certificate. Basis: NIST IR 8547 (DRAFT), CNSA 2.0. `CertificateRequest` with an
  RSA/ECDSA/DSA key → Vulnerable (Signing); certificate loads → Informational inventory.
- **CBOM0080** — Bouncy Castle cryptography. Basis: per primitive. RSA/EC/DSA/EdDSA/DH → Vulnerable;
  MD5/SHA-1/DES/RC4 → Broken; ML-KEM/ML-DSA/SLH-DSA types → PostQuantum (positive).
- **CBOM0081** — Crypto-bearing dependency (package manifest). Inventory signal, Medium confidence.

### Changed
- **CBOM0050** (weak RNG) — added context elevation: `System.Random` flowing into key/token/IV/nonce/salt
  material is now Broken/High (was uniformly Low). Non-security usage remains Low.
- **CBOM0070** (Cloud KMS) — added depth: classical asymmetric key-creation options
  (`CreateRsaKeyOptions`/`CreateEcKeyOptions`) are now reported as Shor-vulnerable managed keys.

## Baseline (v0.4)
- Initial 13-rule set: CBOM0001, 0002, 0003, 0007, 0010, 0021, 0030, 0040, 0041, 0050, 0060, 0070, 0090.
  Formula version 1.0; readiness formula version 1.0.

## Review cadence
- Rule bases are reviewed each release. Draft citations (e.g., NIST IR 8547) are re-checked for status
  changes; if a draft is finalized or withdrawn, the basis string and this changelog are updated.
