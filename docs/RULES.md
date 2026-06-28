# Detector coverage matrix

This is the authoritative list of what `dotnet-cbom` detects, with the basis for each verdict and where
it is covered by tests. "Confidence" is the typical detection confidence for the rule. A clean scan means
*"no detectable issues in analyzed source,"* not *"the system is quantum-safe"* — see
[KNOWN-GAPS.md](KNOWN-GAPS.md) for blind spots.

| Rule | Category | Detects | Example detected | Quantum verdict | Confidence | Basis |
|---|---|---|---|---|---|---|
| **CBOM0001** | Symmetric | AES / 3DES / DES / RC2 usage | `Aes.Create()`, `new DESCryptoServiceProvider()` | AES-256 safe; AES-128 reduced; DES/3DES/RC2 reduced+broken/deprecated | Confirmed | FIPS 197; NIST SP 800-131A |
| **CBOM0002** | Asymmetric | RSA / ECDSA / ECDH / DSA (Shor-broken); small RSA/DSA key sizes | `RSA.Create(2048)`, `ECDsa.Create()` | Vulnerable (Shor / HNDL) | Confirmed | NIST IR 8547 (draft); CNSA 2.0; SP 800-131A |
| **CBOM0003** | Symmetric | Reduced-margin key size set via `KeySize` property | `aes.KeySize = 128` | Reduced margin (Grover) | Confirmed | FIPS 197; CNSA 2.0 |
| **CBOM0007** | Symmetric | ECB cipher mode | `aes.Mode = CipherMode.ECB` | Not quantum (classical Broken) | Confirmed | NIST SP 800-38A |
| **CBOM0010** | Hashing | MD5 / SHA-1 (broken) and SHA-2 inventory | `MD5.Create()`, `SHA384.HashData(..)` | Not quantum; MD5/SHA-1 classically broken | Confirmed | FIPS 180-4; SP 800-131A; RFC 6151 |
| **CBOM0021** | JWT | Signature validation disabled (`alg=none` equivalent) | `RequireSignedTokens = false` | Not quantum (Broken) | High | RFC 8725; OWASP |
| **CBOM0030** | Hardcoded secret | Hardcoded symmetric key / IV literals | `aes.Key = new byte[]{…}` | Not quantum (Broken) | Confirmed | CWE-321, CWE-798 |
| **CBOM0040** | TLS | Deprecated SSL/TLS protocol versions | `SslProtocols.Ssl3`, `Tls11` | Not quantum (Deprecated/Broken) | Confirmed | NIST SP 800-52 Rev. 2; RFC 8996 |
| **CBOM0041** | TLS | Disabled certificate validation | `ServerCertificateCustomValidationCallback = (…) => true` | Not quantum (Broken) | High | CWE-295 |
| **CBOM0050** | Randomness | Non-cryptographic RNG | `new System.Random()` | Not quantum (Suboptimal) | Medium | CWE-338 |
| **CBOM0060** | KDF | PBKDF1 (`PasswordDeriveBytes`); low PBKDF2 iterations | `new Rfc2898DeriveBytes(pw, salt, 1000)` | Not quantum (Deprecated/Suboptimal) | High | OWASP Password Storage |
| **CBOM0070** | Cloud KMS | Managed KMS client usage (positive inventory) | `new KeyClient(…)`, `AmazonKeyManagementServiceClient` | Not quantum (inventory) | High | Inventory signal |
| **CBOM0090** | Post-quantum | PQC algorithm usage (positive signal) | `MLKem`, `MLDsa`, `SlhDsa` types | Post-quantum (raises readiness) | Confirmed | FIPS 203/204/205 |

## Notes on limits

- `alg=none` is detected via the `RequireSignedTokens`/`ValidateIssuerSigningKey` bypass; raw `"none"`
  string literals in JOSE headers are not yet matched.
- AES key size set via the `KeySize` property (`aes.KeySize = 128`) is not yet flagged as reduced-margin;
  only explicit constructor/factory sizes are. (Tracked in KNOWN-GAPS.)
- KMS detection currently records *that* a managed KMS is used, not key specs / rotation / region.
- Detectors that rely on third-party symbols (JWT, KMS, Bouncy Castle) require those packages to resolve;
  in the no-MSBuild fallback directory scan they may not fire.
