# Threat Model — `dotnet-cbom`

This is a security tool; a wrong answer is worse than no answer. The threats below are about the tool's
own trustworthiness, not the crypto it inventories.

## Assets to protect
- **Integrity of findings** — an auditor relies on them. A missed high-risk item (false negative) is the
  worst outcome.
- **Truthfulness of coverage** — "analyzed N of M projects" must be accurate so a partial scan is never
  read as complete.

## Adversaries / failure modes & mitigations

| Threat | Mitigation |
|---|---|
| **False negative on high-risk crypto** | Fail-closed: prefer false positives on high-risk; floors that config cannot lower; every detected weakness emitted with confidence rather than suppressed. |
| **Silent under-reporting from load/compile failure** | A project that fails to analyze is reported "not analyzed," never "clean"; reflected in coverage counts and (configurably) exit code 2. |
| **Misleading remediation** | Misuse-resistance invariant (unit-tested): no recommendation may yield a less-safe configuration; standards-based options only. |
| **Author-bias toward own packages** | `PostQuantum.*` packages appear only as one option among standards-based alternatives, never the sole path. |
| **Malicious / buggy plugin** | Plugins run as in-process code and are explicitly trusted; documented as such. Future: load in a restricted `AssemblyLoadContext`, validate unique rule ids + mandatory basis, isolate exceptions. |
| **Knowledge-base drift / stale citations** | Verdicts live in reviewed `algorithms.json` with mandatory `basis`; CI re-verifies citation strings against primary sources. DRAFT sources (NIST IR 8547) are labeled as such. |
| **Tampered tool supply chain** | Standard NuGet signing / reproducible build expectations (matches the PostQuantum.* family). |

## Explicitly out of scope
- Detecting crypto the static analyzer cannot see (see [KNOWN-GAPS.md](KNOWN-GAPS.md)).
- General secret scanning beyond crypto key/IV/JWT-key literals (defer to dedicated scanners).
- Asserting real-world deployment posture (e.g., TLS termination topology).
