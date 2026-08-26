#!/usr/bin/env bash
# Seed the remaining KNOWN-GAPS as labeled GitHub issues so the roadmap is visible and invites help.
# Requires the GitHub CLI authenticated against this repo: gh auth login
# Usage: scripts/seed-issues.sh [--dry-run]
set -euo pipefail
DRY="${1:-}"

ensure_label() {
  gh label create "$1" --color "$2" --description "$3" 2>/dev/null || true
}

create() {
  local title="$1" body="$2" labels="$3"
  if [ "$DRY" = "--dry-run" ]; then
    echo "ISSUE: $title   [$labels]"
  else
    gh issue create --title "$title" --body "$body" --label "$labels"
  fi
}

if [ "$DRY" != "--dry-run" ]; then
  ensure_label gap        "5319e7" "A documented coverage gap"
  ensure_label detector   "0e8a16" "New or improved detector"
  ensure_label enhancement "a2eeef" "Enhancement"
fi

create "Intra-method dataflow for IV/nonce/key tracking" \
  "Move CBOM0050/key-material detection from identifier heuristics to real intra-method dataflow (track random material and key bytes through assignments/locals). See docs/KNOWN-GAPS.md." \
  "gap,detector"

create "Cloud KMS region/account/rotation depth" \
  "Extend CBOM0070 to capture region/account/rotation when statically visible; document the runtime-config blind spot. See docs/KNOWN-GAPS.md." \
  "gap,detector"

create "Per-call-site third-party crypto beyond manifest inventory" \
  "CBOM0081 inventories crypto-bearing packages; add per-call-site detection for popular libraries (Microsoft.IdentityModel, jose-jwt, NSec) when symbols resolve." \
  "gap,detector"

create "Execute NuGet publish + code signing in release" \
  "release.yml wires deterministic pack, SBOM, signing, and publish, but needs a maintainer code-signing certificate and NuGet API key (CI secrets) to run end-to-end." \
  "enhancement"

create "Performance benchmarks on large multi-project solutions" \
  "Add benchmarks and document scaling behavior of the parallel Roslyn scan + MSBuildWorkspace on large monorepos; consider caching." \
  "enhancement"

echo "Done."
