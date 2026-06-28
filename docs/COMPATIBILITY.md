# Compatibility matrix

`dotnet-cbom` is a .NET global tool. It needs the .NET SDK present at scan time because solution/project
loading uses MSBuild (`MSBuildWorkspace`).

## Tool runtime

| Component | Supported |
|---|---|
| Tool target framework | net8.0 |
| Runs on SDK | .NET SDK 8.0+ (10.0 tested in CI) |
| Operating systems | Windows, Linux, macOS (CI builds on ubuntu-latest; developed on Windows 11) |
| Architectures | x64, arm64 (any RID the .NET SDK supports) |

## What it can analyze

| Target type | Loader | Notes |
|---|---|---|
| `.sln` / `.slnx` | MSBuild workspace | One project per target framework; per-TFM coverage recorded |
| `.csproj` | MSBuild workspace | `--restore`/`--no-restore`, `--msbuild-property name=value` |
| Directory | Directory scan | Parses `*.cs` against the running framework's reference assemblies |
| Single `.cs` file | Directory scan | BCL crypto resolves; third-party symbols may not |

Analyzed source can target any TFM (net48 → net10.0); detectors match the BCL crypto surface, which is
stable across these. Third-party detectors (JWT, Bouncy Castle, KMS) need those packages to resolve — see
[KNOWN-GAPS.md](KNOWN-GAPS.md). The package-manifest inventory (CBOM0081) covers them even when symbols
don't resolve, as long as `project.assets.json` or `<PackageReference>` is present.

## Output compatibility

| Format | Version | Consumers |
|---|---|---|
| CycloneDX JSON | 1.6 (validated against the official schema) | Dependency-Track, OWASP tooling, auditors |
| SARIF | 2.1.0 | GitHub code scanning, Azure DevOps, GitLab SAST |
| Markdown / HTML / executive summary | — | humans, tickets, audit folders |

## Determinism

With a fixed input and timestamp, CycloneDX output is byte-identical (deterministic serial number, ordered
properties, repository-relative paths, stable bom-refs). This is what makes baseline diffing reliable.
