# PostQuantum CBOM for .NET

**Cryptographic inventory and PQC readiness, inside VS Code.** Find RSA, ECC, weak crypto, and quantum-migration risk in your .NET solution — with a live readiness score and prioritized actions.

> **Find your crypto before quantum does.**

![PQC readiness dashboard](media/icon.png)

## What it does

- **PQC Readiness dashboard** — a single panel showing your `0–100` readiness score, critical/high/medium counts, quantum-vulnerable vs. classical-weakness split, baseline delta, and the top migration actions.
- **Crypto inventory sidebar** — the highest-priority findings at a glance, each linking to its rule documentation.
- **Status-bar score** — `PQC: 64/100`, coloured by posture, one click to the dashboard.
- **One-click HTML report** and **`CBOM: Add GitHub Action`** to scaffold a CI gate.

It drives the [`dotnet-cbom`](https://www.nuget.org/packages/PostQuantum.CryptographicBillOfMaterials.Cli) CLI and reads its versioned JSON contract — so the editor view always matches what your CI produces.

### Want squiggles as you type?

This extension is the **dashboard and inventory** layer. For inline diagnostics on weak crypto *as you type* (in every IDE and on `dotnet build`), add the companion Roslyn analyzer:

```bash
dotnet add package PostQuantum.CryptographicBillOfMaterials.Analyzer
```

## Requirements

Install the CLI once (the extension calls it):

```bash
dotnet tool install -g PostQuantum.CryptographicBillOfMaterials.Cli
```

If `dotnet-cbom` isn't on your PATH, set **`cbom.cliPath`** in settings.

## Local-first, by design

- **Runs entirely on your machine.** No source code is uploaded.
- **No cloud analysis. No telemetry.**
- Uses the `dotnet-cbom` CLI you installed — nothing else phones home.

## Settings

| Setting | Default | Description |
|---|---|---|
| `cbom.cliPath` | `dotnet-cbom` | Path to the CLI executable. |
| `cbom.target` | _(workspace)_ | Solution/project/directory to scan, relative to the workspace. |
| `cbom.profile` | `general` | Policy profile (`general`, `federal`, `cnsa2`, `audit`, `developer`). Profiles only raise severity. |
| `cbom.scanOnSave` | `false` | Re-scan when a C# file is saved. |

## Honesty note

A clean scan means *“no detectable issues in analyzed source,”* not *“the system is quantum-safe.”* Static analysis cannot see runtime- or config-driven crypto. See the [project docs](https://github.com/systemslibrarian/PostQuantum.CryptographicBillOfMaterials/blob/main/docs/ACCURACY-AND-LIMITATIONS.md).

Apache-2.0 · [Source & issues](https://github.com/systemslibrarian/PostQuantum.CryptographicBillOfMaterials)
