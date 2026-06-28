# Detector coverage matrix

This is the authoritative list of what `dotnet-cbom` detects, with the basis for each verdict and where it
is covered by tests. "Confidence" is the typical detection confidence for the rule. A clean scan means
*"no detectable issues in analyzed source,"* not *"the system is quantum-safe"* — see
[KNOWN-GAPS.md](KNOWN-GAPS.md) for blind spots and [ACCURACY-AND-LIMITATIONS.md](ACCURACY-AND-LIMITATIONS.md)
for how to read verdicts. Rule changes are tracked in [RULE-CHANGELOG.md](RULE-CHANGELOG.md).

| Rule | Category | Detects | Example detected | Quantum verdict | Confidence | Basis |
|---|---|---|---|---|---|---|
| **CBOM0001** | Symmetric | AES / 3DES / DES / RC2 usage | `Aes.Create()`, `new DESCryptoServiceProvider()` | AES-256 safe; AES-128 reduced; DES/3DES/RC2 broken/deprecated | Confirmed | FIPS 197; SP 800-131A |
| **CBOM0002** | Asymmetric | RSA / ECDSA / ECDH / DSA (Shor); small key sizes | `RSA.Create(2048)` | Vulnerable (Shor / HNDL) | Confirmed | NIST IR 8547 (DRAFT); CNSA 2.0; SP 800-131A |
| **CBOM0003** | Symmetric | Reduced-margin key size via `KeySize` property | `aes.KeySize = 128` | Reduced margin (Grover) | Confirmed | FIPS 197; CNSA 2.0 |
| **CBOM0007** | Symmetric | ECB cipher mode | `aes.Mode = CipherMode.ECB` | Not quantum (Broken) | Confirmed | SP 800-38A |
| **CBOM0010** | Hashing | MD5 / SHA-1 (broken) and SHA-2 inventory | `MD5.Create()` | Not quantum; MD5/SHA-1 broken | Confirmed | FIPS 180-4; SP 800-131A; RFC 6151 |
| **CBOM0021** | JWT | Signature validation disabled | `RequireSignedTokens = false` | Not quantum (Broken) | High | RFC 8725; OWASP |
| **CBOM0022** | JWT | `alg=none`; hardcoded / sub-256-bit HMAC key | `SecurityAlgorithms.None`, `new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secret"))` | Not quantum (Broken) | High | RFC 8725; RFC 7518 |
| **CBOM0030** | Hardcoded secret | Hardcoded symmetric key / IV literals | `aes.Key = new byte[]{…}` | Not quantum (Broken) | Confirmed | CWE-321, CWE-798 |
| **CBOM0040** | TLS | Deprecated SSL/TLS protocol versions | `SslProtocols.Ssl3` | Not quantum (Deprecated/Broken) | Confirmed | SP 800-52r2; RFC 8996 |
| **CBOM0041** | TLS | Disabled certificate validation | `ServerCertificateCustomValidationCallback = (…) => true` | Not quantum (Broken) | High | CWE-295 |
| **CBOM0042** | Certificate | X.509 inventory; cert minted with RSA/ECDSA key | `new CertificateRequest("CN=x", rsa, …)` | Vulnerable when RSA/ECDSA; else inventory | High / Medium | NIST IR 8547 (DRAFT); CNSA 2.0 |
| **CBOM0050** | Randomness | Non-cryptographic RNG; elevated for secret material | `new Random().NextBytes(key)` | Not quantum (Suboptimal→Broken) | Medium / High | CWE-338, CWE-330 |
| **CBOM0060** | KDF | PBKDF1; low PBKDF2 iterations | `new Rfc2898DeriveBytes(pw, salt, 1000)` | Not quantum (Deprecated/Suboptimal) | High | OWASP Password Storage |
| **CBOM0070** | Cloud KMS | KMS client usage; classical asymmetric KMS keys | `new KeyClient(…)`, `new CreateRsaKeyOptions(…)` | Inventory; Vulnerable for RSA/EC keys | High | NIST IR 8547 (DRAFT); CNSA 2.0 |
| **CBOM0080** | Third-party | Bouncy Castle primitives by type | `new RsaEngine()` under `Org.BouncyCastle` | Per primitive (RSA/EC → Vulnerable) | High | NIST IR 8547 (DRAFT); FIPS 203/204/205 |
| **CBOM0081** | Dependency | Crypto-bearing NuGet packages (manifest) | `BouncyCastle.Cryptography` in `project.assets.json` | Inventory; Vulnerable for EC-only libs | Medium | Package manifest |
| **CBOM0090** | Post-quantum | PQC algorithm usage (positive) | `MLKem`, `MLDsa`, `SlhDsa` | Post-quantum (raises readiness) | Confirmed | FIPS 203/204/205 |

## Citation status & review cadence

| Source | Status | Used by | Notes |
|---|---|---|---|
| FIPS 197 / 180-4 / 203 / 204 / 205 | Final | CBOM0001/0003/0010/0090/0080 | Stable standards |
| NIST SP 800-131A Rev. 2, 800-38A, 800-52 Rev. 2 | Final | CBOM0001/0002/0007/0010/0040 | Stable |
| **NIST IR 8547** | **DRAFT (IPD, Nov 2024)** | CBOM0002/0042/0070/0080 | Labelled "DRAFT" in every basis; re-checked each release |
| CNSA 2.0 | Policy (binds NSS; industry guidance) | CBOM0002/0003/0042/0070 | Applied firmly only under the `cnsa2` profile |
| RFC 8725 / 7518 / 8996 / 6151 / 7465 | Final | CBOM0021/0022/0040/0010/0080 | Stable |
| CWE-295/321/330/338/798 | Reference | CBOM0030/0041/0050 | Stable |

Last reviewed: 2026-06-28.

## Notes on limits

- Third-party detectors (JWT, KMS, Bouncy Castle) need their packages to resolve for symbol-based rules; the
  package-manifest inventory (**CBOM0081**) covers them even when symbols don't resolve.
- CBOM0050 elevation is heuristic (identifier names: key/token/iv/nonce/salt/secret/…); non-security use of
  `System.Random` stays low-noise.
- CBOM0070/0080 cannot see region/account/rotation set at runtime — that remains an inherent limit.
