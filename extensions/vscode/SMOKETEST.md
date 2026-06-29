# Smoke test — PostQuantum CBOM extension

A 2-minute manual pass to confirm the extension works end-to-end in a real editor. Run it before
publishing a new version, or after any change to the UI wiring.

The **data layer** (CLI invocation + json-summary contract → status bar / dashboard / tree fields) is
covered by automated tests and a headless check. What only a human can confirm is the **visual shell**:
that VS Code actually renders the webview, the activity-bar view, and the status-bar item. That's what
this checklist is for.

## Prerequisites

```bash
dotnet tool install -g PostQuantum.CryptographicBillOfMaterials.Cli   # the extension drives this CLI
```

## A. Installed build (what users get)

1. Install the extension: Extensions view → search **"PostQuantum CBOM"** → Install
   (or `code --install-extension systemslibrarian.postquantum-cbom`).
2. Open a .NET project that uses crypto (your own, or this repo's `samples/`).
3. Continue to **Checks** below.

## B. From source (for development / debugging)

1. `cd extensions/vscode && npm install`
2. Press **F5** ("Run Extension") → a second window opens: **[Extension Development Host]**.
3. In that window, open a .NET project, then continue to **Checks**.

## Checks

| # | Action | Expected |
|---|--------|----------|
| 1 | Command Palette → **CBOM: Scan workspace** | Progress notification, then a result toast: `PQC readiness NN/100 — N critical, N high`. |
| 2 | Look at the **status bar** (bottom-left) | `🛡 PQC: NN/100`, coloured red/yellow when critical/high findings exist. |
| 3 | Click the **PostQuantum CBOM** icon in the Activity Bar | "Crypto inventory" tree shows the readiness header + **Top migration actions**. |
| 4 | Click a tree action | Opens the rule docs (RULES.md) in the browser. |
| 5 | Click the status bar (or **CBOM: Show PQC readiness dashboard**) | Webview opens: score gauge, severity cards, top-actions table. |
| 6 | **CBOM: Generate HTML report** | The generated `cbom.html` opens. |
| 7 | **CBOM: Add GitHub Action** | Creates/opens `.github/workflows/cbom.yml`. |

**Pass:** all surfaces render with data; no error toasts.

## Common first-run issue

- *"Could not find 'dotnet-cbom'"* → the CLI isn't on the host's PATH. Set **`cbom.cliPath`** in Settings to
  the full path (`which dotnet-cbom` / `where dotnet-cbom`), or install the global tool (Prerequisites).
