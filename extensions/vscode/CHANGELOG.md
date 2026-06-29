# Changelog

All notable changes to the PostQuantum CBOM extension are documented here.

## [0.1.0] — Unreleased

Initial release.

- PQC Readiness dashboard (webview): score, severity counts, quantum/classical split, baseline delta, top actions.
- Crypto inventory sidebar (tree view) with prioritized migration actions.
- Status-bar readiness score, coloured by posture.
- Commands: `CBOM: Scan workspace`, `CBOM: Show PQC readiness dashboard`, `CBOM: Generate HTML report`, `CBOM: Add GitHub Action`.
- Opt-in scan-on-save for C# files.
- Reads the `dotnet-cbom --format json-summary` contract (schemaVersion 1). Fully local; no telemetry.
