# Releasing `dotnet-cbom`

Releases are fully automated by [`.github/workflows/release.yml`](../.github/workflows/release.yml). Cutting
a release is one tag push. Everything else — version stamping, build, test, pack, SBOM, checksums, signing,
GitHub Release, and NuGet publish — happens in CI.

## One-time maintainer setup

Publishing uses **NuGet Trusted Publishing** (OIDC) — no long-lived API key is stored. Without the setup
below the workflow still builds, packs, checksums, and creates a GitHub Release with downloadable assets — it
just skips signing/nuget.org.

**1. Create a Trusted Publishing policy on nuget.org** (Account → Trusted Publishing → add):

| Field | Value |
|---|---|
| Policy name | e.g. `cbom-release` |
| Package owner | your nuget.org account / org |
| Repository owner | `systemslibrarian` |
| Repository | `PostQuantum.CryptographicBillOfMaterials` |
| Workflow file | `release.yml` (filename only — not the `.github/workflows/` path) |
| Environment | leave empty |

The policy is "temporarily active" for 7 days; the first successful publish locks it permanently to this repo.

**2. Set the GitHub Actions variable** `NUGET_USER` to your nuget.org account username
(**Settings → Secrets and variables → Actions → Variables → New repository variable**). The publish steps are
skipped if it is unset. The workflow already requests the `id-token: write` permission for OIDC.

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
# 2. Tag and push:
git tag v1.0.0
git push origin v1.0.0
```

That triggers the release job, which:

1. Stamps the build with `-p:Version=1.0.0` (from the tag).
2. Builds with `-warnaserror` and runs the full test suite.
3. Packs the global tool (`.nupkg` + `.snupkg`).
4. Generates the tool SBOM (`tool.cdx.json`).
5. Signs the package **if** signing secrets are present.
6. Writes `SHA256SUMS.txt`.
7. Publishes to nuget.org via Trusted Publishing (OIDC) **if** the `NUGET_USER` variable is set (`--skip-duplicate`).
8. Creates a GitHub Release with the package, symbols, SBOM, and checksums attached.

## Dry run before tagging

Reproduce the CI pack locally and prove the tool installs and runs from the resulting package:

```bash
dotnet pack src/PostQuantum.CryptographicBillOfMaterials.Cli -c Release -o artifacts -p:Version=1.0.0
dotnet tool install -g PostQuantum.CryptographicBillOfMaterials.Cli --add-source ./artifacts --version 1.0.0
dotnet-cbom version          # must print: dotnet-cbom 1.0.0 (...)
dotnet-cbom scan ./samples/VulnerableDemo/Crypto.cs --format summary
```

`workflow_dispatch` also runs the job without a tag (using the `Directory.Build.props` version) so you can
exercise the pipeline against a branch before the real tag.

## Post-release verification

```bash
# Once nuget.org has indexed the package (a few minutes):
dotnet tool install -g PostQuantum.CryptographicBillOfMaterials.Cli
dotnet-cbom version
# Verify the GitHub Release asset checksum:
sha256sum -c SHA256SUMS.txt
```
