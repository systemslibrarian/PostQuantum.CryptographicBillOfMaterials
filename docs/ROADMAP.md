# What would make `dotnet-cbom` a 10/10 for people who need it

## Delivered (status as of 2026-06-28)

The 10 bars below have been substantially implemented. See [CHANGELOG.md](../CHANGELOG.md) for specifics.

| Bar | Status | Evidence |
|---|---|---|
| 01. Trust mechanically verifiable | ✅ | Official CycloneDX 1.6 schema validation in `validate` + CI; profile validator; golden test |
| 02. Coverage matrix + high-value gaps | ✅ | 16 rules incl. JWT alg=none/weak-HMAC, X.509, Bouncy Castle, package manifest, KMS depth, AES KeySize, weak-RNG context; [RULES.md](RULES.md) |
| 03. Reports as audit packets | ✅ | Top migration actions, what-changed-since-baseline, remediation status, waivers |
| 04. Policy profiles | ✅ | general/federal/cnsa2/audit/developer; recorded in metadata; raise-only |
| 05. CI/PR first-class | ✅ | GitHub Action, Azure/GitLab examples, PR baseline-diff comment, `--changed-files`, exit codes |
| 06. Config + data sensitivity | ✅ | `dataSensitivityHints` (path + `ns:` namespace) wired to scorer; per-algorithm rules; applied-config recorded |
| 07. MSBuild/workspace hardening | ◑ | Per-project failure reasons, `--restore`/`--no-restore`/`--msbuild-property`; full dataflow still heuristic |
| 08. Govern the knowledge base | ✅ | Per-rule matrix, citation-status table, [RULE-CHANGELOG.md](RULE-CHANGELOG.md), drift-guard tests |
| 09. Determinism & portability | ✅ | Relative paths, deterministic serial/ordering, stable bom-refs, refreshed samples |
| 10. Ship like audits depend on it | ◑ | Tool SBOM, compat matrix, accuracy page, deterministic/SourceLinked pack, signing **wired** (needs maintainer cert/key to execute) |

The two ◑ items are limited only by things that need a maintainer secret (signing/publishing) or are an
inherent static-analysis limit (full dataflow) — see [KNOWN-GAPS.md](KNOWN-GAPS.md).

## Short verdict

This is already aimed at the right problem. The strongest parts are the honest framing, CycloneDX/SARIF orientation, fail-closed scan behavior, separate classical-vs-quantum risk model, and baseline/diff workflow. For early technical evaluators, I would put the current repo around a strong 7/10.

To become a 10/10 for the people who actually need it, the project should become less like "a promising scanner" and more like "an auditable PQC migration system for .NET teams that do not have a cryptographer on staff." The winning move is not random feature breadth. It is trust evidence, coverage depth, workflow fit, and claim hygiene.

## Who the real users are

- Security and compliance leads who must answer PQC-readiness questions with evidence.
- .NET application owners who need to find cryptography they did not know they had.
- Auditors who need traceable claims, standards bases, coverage limits, and repeatable output.
- DevSecOps/platform teams who need CI gates, SARIF upload, baseline diffs, and low-noise triage.
- Public sector, library, SaaS, defense subcontractor, and regulated teams that may not have an in-house cryptographer.

## Evidence snapshot from this repo

01. The README has a strong user promise: inventory crypto, classify quantum risk, demonstrate PQC migration progress, and emit auditor-friendly formats. See `README.md:1`, `README.md:8`, `README.md:14`, and `README.md:22`.

02. The CLI already has useful adoption primitives: `scan`, `diff`, `version`, selectable formats, baselines, config, quiet mode, and CI exit codes. See `src/PostQuantum.CryptographicBillOfMaterials.Cli/Program.cs:25`, `src/PostQuantum.CryptographicBillOfMaterials.Cli/Program.cs:30`, and `src/PostQuantum.CryptographicBillOfMaterials.Cli/Program.cs:196`.

03. The scan runner records project coverage and fails closed on partial analysis unless explicitly allowed. See `src/PostQuantum.CryptographicBillOfMaterials.Cli/ScanRunner.cs:96`, `src/PostQuantum.CryptographicBillOfMaterials.Cli/ScanRunner.cs:176`, and `src/PostQuantum.CryptographicBillOfMaterials.Cli/ScanRunner.cs:178`.

04. The default detector registry is no longer just the initial narrow set. It includes KDF, weak random, cloud KMS, and PQC-positive detectors. See `src/PostQuantum.CryptographicBillOfMaterials.Analysis/Engine/DetectorRegistry.cs:17`, `src/PostQuantum.CryptographicBillOfMaterials.Analysis/Engine/DetectorRegistry.cs:27`, `src/PostQuantum.CryptographicBillOfMaterials.Analysis/Engine/DetectorRegistry.cs:28`, `src/PostQuantum.CryptographicBillOfMaterials.Analysis/Engine/DetectorRegistry.cs:29`, and `src/PostQuantum.CryptographicBillOfMaterials.Analysis/Engine/DetectorRegistry.cs:30`.

05. Reporting is stronger than the gap doc says. The gap doc still says HTML is not yet implemented, but `ScanRunner` wires an `HtmlReporter` and reporting tests cover self-contained HTML. See `docs/KNOWN-GAPS.md:37`, `src/PostQuantum.CryptographicBillOfMaterials.Cli/ScanRunner.cs:150`, and `tests/PostQuantum.CryptographicBillOfMaterials.Reporting.Tests/HtmlReporterTests.cs:47`.

06. The docs also say KDF, cloud KMS, and non-CSPRNG detection are not yet implemented, but tests and the detector registry show current implementation for at least some of those areas. See `docs/KNOWN-GAPS.md:31`, `docs/KNOWN-GAPS.md:32`, `tests/PostQuantum.CryptographicBillOfMaterials.Tests/BreadthDetectorTests.cs:38`, and `tests/PostQuantum.CryptographicBillOfMaterials.Tests/BreadthDetectorTests.cs:81`.

07. CycloneDX output has structural tests, but the known gaps still say official `bom-1.6.schema.json` validation is not run in CI. That is a major trust gap for a tool whose strategic claim is standards-compatible CBOM. See `tests/PostQuantum.CryptographicBillOfMaterials.Reporting.Tests/ReporterTests.cs:21`, `tests/PostQuantum.CryptographicBillOfMaterials.Reporting.Tests/ReporterTests.cs:27`, `tests/PostQuantum.CryptographicBillOfMaterials.Reporting.Tests/ReporterTests.cs:28`, and `docs/KNOWN-GAPS.md:38`.

08. The sample markdown currently contains absolute local developer paths, which weakens polish, reproducibility, and shareability. See `samples/VulnerableDemo/cbom-out/cbom.md:32` through `samples/VulnerableDemo/cbom-out/cbom.md:39`.

09. The docs mention `dataSensitivityHints`, and also say they are not yet honored by the scorer. That matters because data lifetime is central to harvest-now-decrypt-later risk. See `docs/KNOWN-GAPS.md:15` and `docs/KNOWN-GAPS.md:40`.

## The 10/10 bar

### 01. Make trust mechanically verifiable

For this audience, trust is the product. A 10/10 version should prove its claims every time CI runs.

Definition of done:

- Validate generated CBOMs against the official CycloneDX 1.6 schema in CI.
- Add a project-specific profile validator for required `cbom:*` properties, coverage metadata, evidence locations, confidence, rule IDs, risk basis, and recommendation fields.
- Validate SARIF against a SARIF schema or a known SARIF validator.
- Keep golden fixture outputs for representative projects and diff them intentionally.
- Refresh generated samples as part of release checks.
- Add a `dotnet-cbom validate <cbom.cbom.json>` command that users and auditors can run.

Why this matters: the README says the CBOM is standards-friendly and auditor-trustworthy. That claim becomes much stronger when the repo can prove schema validity, profile conformance, and repeatability without hand inspection.

### 02. Publish a detector coverage matrix and close the highest-value gaps

The current detector set is useful, but a 10/10 tool needs an explicit coverage matrix so users know what is detected, what is partially detected, and what is invisible.

Highest-value next coverage work:

- Track AES key size set through properties, especially `aes.KeySize = 128`.
- Improve constant and local flow for algorithm names, key sizes, cipher modes, IVs, and signing options.
- Add or deepen Bouncy Castle coverage.
- Add full JOSE/JWT literal handling, including `alg=none`, weak HMAC keys, signing credential choices, and validation bypasses.
- Deepen cloud KMS inventory from "KMS client used" toward key specs, key usages, RSA/EC/PQC posture, rotation hints, and region/account metadata when visible.
- Add dependency-aware crypto inventory for NuGet packages known to wrap crypto.
- Add X.509 and certificate inventory beyond disabled validation and deprecated TLS.
- Make weak-random findings context-sensitive: using `System.Random` for gameplay should not feel equivalent to random material flowing into secrets, tokens, IVs, nonces, or keys.

Definition of done:

- A public table lists every rule, supported APIs, examples detected, examples not detected, confidence level, and tests.
- Every rule has positive and negative fixtures.
- Each known gap has a test that demonstrates the current behavior, even before it is fixed.

### 03. Turn reports into audit packets, not just findings lists

The reports already give severity, rule, algorithm, location, quantum posture, and recommendations. For a 10/10 user, reports should also answer: "What do I tell leadership? What do I fix first? What changed since last month? Can an auditor reproduce this?"

Add:

- A "top migration actions" section grouped by service/project and owner.
- A "why this is risky" section per finding with the standards basis, draft/non-draft status, and confidence.
- A "what changed since baseline" section in HTML and executive summaries, not only in `cbom.diff.md`.
- A remediation status model: new, unchanged, accepted risk, waived, fixed, regressed.
- Waiver metadata with justification, approver, expiry, and whether the waiver suppresses output or only changes gate behavior.
- Relative, portable paths in reports and samples by default.
- Machine-readable remediation fields in CycloneDX properties, not only prose.

Definition of done:

- A non-cryptographer can open the HTML or markdown report and decide the next three actions without reading source code.
- An auditor can trace each claim to a source location, rule page, standard, formula version, and scan coverage statement.

### 04. Add policy profiles instead of one universal posture

Different teams need different answers. Federal/NSS users, general commercial users, healthcare, public sector, and library teams will not share one exact migration deadline or severity appetite.

Add built-in profiles such as:

- `general`: conservative commercial default, clear draft labels.
- `federal`: NIST-centered posture.
- `cnsa2`: stricter CNSA 2.0/NSS posture.
- `audit`: maximum evidence, minimal suppression, verbose basis.
- `developer`: lower-noise local mode, focused on actionable fixes.

Definition of done:

- The selected policy profile is recorded in CBOM metadata and reports.
- Every date-sensitive recommendation states its source and whether the source is final, draft, policy-specific, or general guidance.
- Profiles can raise severity or require more evidence, but cannot silently make risky findings disappear.

### 05. Make CI and PR workflows first-class

The CLI already has the right foundation: exit codes, SARIF, baseline diff, and fail-on thresholds. A 10/10 version should make the common workflows copy-paste simple.

Add:

- Official GitHub Action with SARIF upload and artifact retention.
- Azure DevOps pipeline example.
- GitLab CI example.
- PR baseline mode that comments only on new/regressed findings.
- A `--changed-files` or PR-aware mode for faster incremental feedback, while preserving full-scan CI for release gates.
- Exit-code examples for "warn only," "fail on new high," and "fail on any critical."

Definition of done:

- A team can add the tool to CI in under 10 minutes and get a useful first result without reading the implementation.
- PRs do not drown teams in old findings; they highlight new and regressed risk.

### 06. Finish enterprise configuration and data-sensitivity modeling

Harvest-now-decrypt-later risk depends heavily on data lifetime and sensitivity. The project already acknowledges this, but a 10/10 version should make it a core workflow.

Add:

- Implement `dataSensitivityHints` in the scorer.
- Allow path, namespace, project, and symbol-based sensitivity hints.
- Support asset ownership tags: team, service, system, data class, environment.
- Add config validation with clear diagnostics for unknown rules, invalid severities, invalid globs, and unused settings.
- Record all applied config, suppressions, and waivers into CBOM metadata.

Definition of done:

- Users can express "this code protects 30-year records" and watch that change prioritization.
- The report makes clear which risks are intrinsic crypto risks and which are elevated by data sensitivity or policy.

### 07. Harden MSBuild and workspace loading

For real .NET estates, project loading failures are common. The current fail-closed behavior is good; a 10/10 version also needs excellent diagnostics and recovery.

Add:

- Per-project and per-target-framework coverage details.
- Clear reasons for failed loads: missing SDK, restore failure, unsupported target framework, generated code issue, analyzer load issue.
- `--no-restore`, `--restore`, and `--msbuild-property` options if not already present.
- Binlog capture guidance for debugging load failures.
- Performance benchmarks on large multi-project solutions.

Definition of done:

- A partial scan is never mistaken for clean, and the user knows exactly how to fix the partial scan.

### 08. Govern the rule knowledge base like a security product

The knowledge base and rule logic are the heart of credibility.

Add:

- One docs page per rule: purpose, examples, false positives, false negatives, basis, last-reviewed date, and remediation.
- Citation hygiene: each standard citation should have a source, status, and review cadence.
- A rule changelog: severity changes, basis changes, detector behavior changes.
- Versioned knowledge-base releases independent from code where practical.
- Tests that fail when rule IDs, severity floors, formula versions, or required basis fields drift accidentally.

Definition of done:

- An auditor can ask "why is this High?" and the answer is stable, sourced, and versioned.

### 09. Polish output determinism and portability

Security artifacts get copied into tickets, audit folders, CI logs, and vendor portals. Small rough edges become trust friction.

Fix or verify:

- Reports should prefer repository-relative paths when possible.
- Generated samples should not contain local machine paths.
- Timestamps, serial numbers, and ordering should be deterministic where the mode requires reproducibility.
- Findings should have stable IDs across runs when source location and semantic meaning do not change.
- Markdown tables should remain readable with long paths and long recommendations.

Definition of done:

- Running the same scan in two checkouts produces comparable artifacts without local path noise.

### 10. Ship like teams are betting audits on it

A 10/10 tool for this audience needs release trust, not just code quality.

Add:

- Signed NuGet package and documented provenance.
- Tool SBOM.
- Compatibility matrix for SDK versions, target frameworks, and operating systems.
- Release notes that call out detector additions, severity changes, schema/profile changes, and known false-negative risks.
- A public "accuracy and limitations" page that is updated with every release.

Definition of done:

- A regulated team can justify installing and running the tool in CI without inventing its own supply-chain story.

## The five highest-impact immediate moves

01. Sync `docs/KNOWN-GAPS.md` with current implementation and make docs drift part of release review.

02. Add official CycloneDX schema validation plus a `cbom` profile validator in tests and CLI.

03. Refresh generated sample artifacts so they use current outputs and relative paths.

04. Implement `dataSensitivityHints` and AES `KeySize` property flow, because those directly affect PQC prioritization.

05. Ship a GitHub Action example with SARIF upload, baseline diff, artifact retention, and documented exit-code behavior.

## What not to change

- Do not stop saying a clean scan is not proof of quantum safety. That honesty is a differentiator.
- Do not replace CycloneDX with a proprietary schema. The profile approach is the right strategic decision.
- Do not collapse classical weakness and quantum vulnerability into one vague severity story. Keeping those axes separate is valuable.
- Do not pretend draft guidance is settled law. Marking draft or policy-specific bases is exactly the right instinct.
- Do not let config lower severity silently. The current "floors can only raise" approach is the right safety posture.

## 10/10 acceptance test

A team should be able to do this:

```bash
dotnet tool install -g PostQuantum.CryptographicBillOfMaterials.Cli
dotnet-cbom scan ./MyOrg.sln --format cyclonedx,sarif,html,summary --baseline ./last.cbom.json --fail-on high
dotnet-cbom validate ./cbom-out/cbom.cbom.json
```

And get all of this:

- The CBOM validates against CycloneDX 1.6 and the `dotnet-cbom` profile.
- SARIF uploads cleanly to code scanning.
- Partial project loads are obvious and fail closed unless explicitly allowed.
- Every finding has a rule ID, source location, confidence, standards basis, quantum verdict, classical verdict, score, recommendation, and policy profile.
- The report identifies the highest-priority migration work and what changed since the baseline.
- Waivers are visible, justified, expiring, and audit-friendly.
- Known blind spots are stated in the output and docs, not hidden in implementation details.
- Sample outputs are portable and match the current code.

That is the 10/10 version: not just a scanner that finds crypto, but a repeatable evidence system for PQC migration.

## Validation note from this assessment

I attempted `dotnet test`. One run produced an SDK resolver cancellation after an interrupted build. A subsequent `dotnet test -v minimal` restored and built the projects, and the output showed the test assemblies reaching finished/succeeded lines for the visible net8.0 test run, but I stopped the terminal before a clean final summary. I would not cite this as clean CI evidence until a fresh uninterrupted test run completes and reports a final pass.