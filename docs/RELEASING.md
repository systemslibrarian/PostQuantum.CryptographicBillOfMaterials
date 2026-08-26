# Releasing `dotnet-cbom`

Releases are fully automated by [`.github/workflows/release.yml`](../.github/workflows/release.yml). Cutting
a release is one tag push. Everything else — version stamping, build, test, pack, SBOM, checksums, signing,
GitHub Release, and NuGet publish — happens in CI.

## One-time maintainer setup

Publishing uses **NuGet Trusted Publishing** (OIDC) — no long-lived API key is stored. This is now the only
durable path: nuget.org [capped new API keys at 30 days on 2026-08-17 and expires all pre-existing keys on
2026-11-01](https://devblogs.microsoft.com/dotnet/strengthening-nuget-supply-chain-security-reducing-api-key-lifetime/).
Without a matching trust policy a tagged run **fails at the NuGet login step**, so complete step 1 before your
first tag.

**1. Create a Trusted Publishing policy on nuget.org** (Account → Trusted Publishing → add):

| Field | Value |
|---|---|
| Policy name | e.g. `cbom-release` |
| Package owner | your nuget.org account / org |
| Repository owner | `systemslibrarian` |
| Repository | `PostQuantum.CryptographicBillOfMaterials` |
| Workflow file | `release.yml` (filename only — not the `.github/workflows/` path) |
| Environment | leave empty |

Choose the scope **"Push new packages and package versions"** (`package:push`) — *not* "Push only new package
versions" — and set the package glob to `PostQuantum.CryptographicBillOfMaterials.*`. `package:pushversion`
cannot create a package ID that has never been published, which is the single most likely first-release
failure here.

A policy may start out **"temporarily active" for 7 days**: nuget.org needs GitHub's numeric repository and
owner IDs to lock the policy against resurrection attacks, and looks them up anonymously at creation time.
This repo is public, so that lookup normally succeeds and the policy is permanently active immediately — but a
GitHub API rate-limit at creation silently leaves it temporary, so check the page for a "days left" badge.
Every edit to the policy resets the 7-day clock; the first successful publish makes it permanent.

**2. Nothing else to configure.** The workflow already requests the `id-token: write` permission for OIDC and
signs in to nuget.org as `systemslibrarian`, the account that owns the trust policy above. Publishing runs on
every `vX.Y.Z` tag push; there is no opt-in switch.

**In a fork,** set the repository variable `NUGET_USER` (**Settings → Secrets and variables → Actions →
Variables**) to your own nuget.org **profile name** — the workflow uses `${{ vars.NUGET_USER || 'systemslibrarian' }}`.
It must be an individual profile name, not an organization name and not an email address; an organization
returns *"Generating fetching tokens directly for organizations is not supported."*

**Optional — package signing** (independent of publishing). Add these secrets to sign the `.nupkg`:

| Secret | Purpose | How to get it |
|---|---|---|
| `CODE_SIGNING_PFX_BASE64` | Sign the `.nupkg` | `base64 -w0 cert.pfx` from your code-signing certificate |
| `CODE_SIGNING_PFX_PASSWORD` | Password for the PFX above | — |

Add them under **Settings → Secrets and variables → Actions → Secrets**.

## Cut a release

The version is derived from the tag — there is no version string to edit by hand. The tag `vX.Y.Z` becomes
package version `X.Y.Z`, and `dotnet-cbom version` reports that same value at runtime (read from the assembly),
so the installed package and the tool's self-reported version can never disagree.

```bash
# 1. Update CHANGELOG.md, commit, and make sure main is green.
# 2. Tag and push. Pick an UNUSED vX.Y.Z — v1.0.0 through v1.1.2 are taken and already published:
git tag vX.Y.Z
git push origin vX.Y.Z
```

That triggers the release job, which:

1. Stamps the build with `-p:Version=X.Y.Z` (from the tag). A tag that is not `vX.Y.Z` fails fast.
2. Builds with `-warnaserror` and runs the full test suite.
3. Packs the global tool (`.nupkg` + `.snupkg`) **and the Roslyn analyzer package**
   (`PostQuantum.CryptographicBillOfMaterials.Analyzer`). Both ship on every tag.
4. Generates the tool SBOM (`tool.cdx.json`), stamped with the release version.
5. Signs **both packages** **if** signing secrets are present.
6. Writes `SHA256SUMS.txt` — after signing, so the hashes match the published bytes.
7. Publishes **both packages** to nuget.org via Trusted Publishing (OIDC) on any `vX.Y.Z` tag
   (`--skip-duplicate`, so re-running a partially-completed release is safe).
8. Creates a GitHub Release with the packages, symbols, SBOM and checksums attached, and uploads the same
   files as a workflow-run artifact named `release`.

## Dry run before tagging

Reproduce the CI pack locally and prove the tool installs and runs from the resulting package. Use a version
that is *not* on nuget.org, or `--add-source` cannot prove the bits you installed are the ones you just built:

```bash
OUT=$(mktemp -d)
dotnet pack src/PostQuantum.CryptographicBillOfMaterials.Cli -c Release -o "$OUT" -p:Version=0.0.0-dev
dotnet tool install -g PostQuantum.CryptographicBillOfMaterials.Cli --add-source "$OUT" --version 0.0.0-dev
dotnet-cbom version          # must print: dotnet-cbom 0.0.0-dev (...)
dotnet-cbom scan ./samples/VulnerableDemo/Crypto.cs --format summary   # exits 1 by design: the sample is
                                                                       # seeded with Critical/High findings
dotnet tool uninstall -g PostQuantum.CryptographicBillOfMaterials.Cli
```

`workflow_dispatch` also runs the job without a tag (using the `Directory.Build.props` version) so you can
exercise the pipeline against a branch before the real tag.

## First-release failure decoder

The exact strings nuget.org returns, and what each one actually means:

| You see | Cause |
|---|---|
| `No matching trust policy owned by user '<name>' was found.` | `user:` is wrong, **or** Repository Owner / Repository is wrong. Those two are deliberately not disclosed in the error, so you get no hint — re-check all three character by character. |
| `Workflow mismatch for policy '<n>': expected 'X', actual 'Y'` | Workflow File field is wrong. It wants `release.yml`, the file name only. |
| `Environment mismatch for policy '<n>': ...` | The Environment field is non-empty. `release.yml` declares no `environment:`; clear it. |
| `Claim 'job_workflow_ref' has value '...' which does not start with <owner>/<repo>/.github/workflows/.` | A reusable workflow was called; the policy must name the **called** workflow's file in **its** repo. |
| `The policy '<n>' has expired.` | A temporary policy lapsed past 7 days. Re-save it on the Trusted Publishing page. |
| `The scopes on the generated API key are not valid...` | The package owner no longer grants you push rights. |
| `GitHub OIDC is not available. Ensure your workflow has ... id-token: write` | The `permissions:` block was lost. |

## Post-release verification

```bash
# Once nuget.org has indexed the package (a few minutes):
dotnet tool install -g PostQuantum.CryptographicBillOfMaterials.Cli
dotnet-cbom version
# Verify the GitHub Release asset checksum:
sha256sum -c SHA256SUMS.txt
```
