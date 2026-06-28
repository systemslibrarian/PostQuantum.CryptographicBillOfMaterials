#!/usr/bin/env bash
# Generate a CycloneDX SBOM for dotnet-cbom itself (supply-chain provenance for the PostQuantum.* family).
# Requires the CycloneDX .NET tool: dotnet tool install --global CycloneDX
set -euo pipefail
cd "$(dirname "$0")/.."

dotnet CycloneDX \
  src/PostQuantum.CryptographicBillOfMaterials.Cli/PostQuantum.CryptographicBillOfMaterials.Cli.csproj \
  --output sbom \
  --filename tool.cdx.json \
  --output-format Json \
  --spec-version 1.6 \
  --recursive \
  --exclude-test-projects

# Round-trip: a CBOM tool should be able to validate its own SBOM against the official schema.
dotnet run --project src/PostQuantum.CryptographicBillOfMaterials.Cli -- validate sbom/tool.cdx.json --schema-only
echo "Wrote sbom/tool.cdx.json"
