# Rule changelog

Deliberate changes to the rule set — additions, severity/basis changes, detector-behavior changes. A drift
guard test (`DriftGuardTests`) fails the build if the rule-id set changes without updating its snapshot, so
every entry here corresponds to an intentional change.

## 1.0.0 — Initial rule set

16 Roslyn source detectors plus the CBOM0081 package-manifest inventory. Formula version 1.0; readiness
formula version 1.0.

- **CBOM0001** — Symmetric cipher inventory (AES safe; 3DES/DES/RC2 broken/deprecated). FIPS 197; SP 800-131A.
- **CBOM0002** — Asymmetric / Shor-vulnerable public key (RSA/ECDSA/ECDH/DSA) and small key sizes.
  NIST IR 8547 (DRAFT); CNSA 2.0; SP 800-131A.
- **CBOM0003** — Reduced-margin key size via `KeySize` property (e.g. AES-128). FIPS 197; CNSA 2.0.
- **CBOM0007** — ECB cipher mode (Broken). SP 800-38A.
- **CBOM0010** — Hash inventory; MD5/SHA-1 broken. FIPS 180-4; SP 800-131A; RFC 6151.
- **CBOM0021** — JWT signature validation disabled. RFC 8725; OWASP.
- **CBOM0022** — Unsigned/weak-keyed JWT algorithm. RFC 8725, RFC 7518. Floor: Critical for
  `alg=none`/hardcoded key, High for sub-256-bit HMAC key.
- **CBOM0030** — Hardcoded symmetric key / IV literal. CWE-321, CWE-798.
- **CBOM0040** — Deprecated SSL/TLS protocol version. SP 800-52r2; RFC 8996.
- **CBOM0041** — Disabled certificate validation. CWE-295.
- **CBOM0042** — X.509 certificate. NIST IR 8547 (DRAFT), CNSA 2.0. `CertificateRequest` with an
  RSA/ECDSA/DSA key → Vulnerable (Signing); certificate loads → Informational inventory.
- **CBOM0050** — Non-cryptographic RNG, with context elevation: `System.Random` flowing into
  key/token/IV/nonce/salt material is Broken/High; non-security usage stays Low. CWE-338, CWE-330.
- **CBOM0060** — Weak KDF (PBKDF1; low-iteration PBKDF2). OWASP Password Storage.
- **CBOM0070** — Cloud KMS inventory, with classical asymmetric key-creation options
  (`CreateRsaKeyOptions`/`CreateEcKeyOptions`) reported as Shor-vulnerable managed keys. NIST IR 8547 (DRAFT); CNSA 2.0.
- **CBOM0080** — Bouncy Castle cryptography, per primitive. RSA/EC/DSA/EdDSA/DH → Vulnerable;
  MD5/SHA-1/DES/RC4 → Broken; ML-KEM/ML-DSA/SLH-DSA → PostQuantum (positive).
- **CBOM0081** — Crypto-bearing dependency (package manifest). Inventory signal, Medium confidence.
- **CBOM0090** — Post-quantum algorithm usage (ML-KEM/ML-DSA/SLH-DSA), positive signal. FIPS 203/204/205.

## Review cadence
- Rule bases are reviewed each release. Draft citations (e.g., NIST IR 8547) are re-checked for status
  changes; if a draft is finalized or withdrawn, the basis string and this changelog are updated.
