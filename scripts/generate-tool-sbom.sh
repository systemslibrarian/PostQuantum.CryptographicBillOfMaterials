#!/usr/bin/env bash
# Generate a CycloneDX SBOM for dotnet-cbom itself (supply-chain provenance for the PostQuantum.* family).
# Requires the CycloneDX .NET tool: dotnet tool install --global CycloneDX
set -euo pipefail
cd "$(dirname "$0")/.."

# Without --set-version, CycloneDX stamps metadata.component.version (and the bom-ref) as "0.0.0" — it does
# not read the MSBuild Version property. Pass a version explicitly, or take it from the project.
VERSION="${1:-$(dotnet msbuild src/PostQuantum.CryptographicBillOfMaterials.Cli/PostQuantum.CryptographicBillOfMaterials.Cli.csproj -getProperty:Version -nologo)}"

dotnet CycloneDX \
  src/PostQuantum.CryptographicBillOfMaterials.Cli/PostQuantum.CryptographicBillOfMaterials.Cli.csproj \
  --output sbom \
  --filename tool.cdx.json \
  --output-format Json \
  --spec-version 1.6 \
  --recursive \
  --exclude-test-projects \
  --set-version "$VERSION"

# Round-trip: a CBOM tool should be able to validate its own SBOM against the official schema.
dotnet run -f net10.0 --project src/PostQuantum.CryptographicBillOfMaterials.Cli -- validate sbom/tool.cdx.json --schema-only
echo "Wrote sbom/tool.cdx.json"
