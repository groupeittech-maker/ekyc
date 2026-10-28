#!/usr/bin/env bash
# Build a versioned national release bundle:
#   bash package.sh [version]
# Produces dist/trusdy-national-<ver>.tar.gz + SHA256SUMS (signable by
# Central as manifest artifacts — contract §3.4).
set -euo pipefail

VER="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
OUT="dist/trusdy-national-$VER"
mkdir -p dist
git archive -o "$OUT.tar.gz" HEAD
( cd dist && sha256sum "trusdy-national-$VER.tar.gz" > "SHA256SUMS-$VER.txt" )
cat > "$OUT.release.json" <<EOF
{
  "name": "trusdy-national",
  "version": "$VER",
  "git": "$(git rev-parse HEAD)",
  "built_at": "$(date -u +%FT%TZ)",
  "contents": ["source tree", "deploy/national kit", "country-profiles", "models fetchers"],
  "artifacts": [{"name": "trusdy-national-$VER.tar.gz",
                  "sha256": "$(cd dist && sha256sum trusdy-national-$VER.tar.gz | cut -d' ' -f1)"}]
}
EOF
echo "Built: $OUT.tar.gz"
cat "$OUT.release.json"
