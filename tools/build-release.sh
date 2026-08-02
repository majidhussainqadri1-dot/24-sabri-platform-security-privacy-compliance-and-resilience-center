#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN_DIR="$ROOT/plugin/sabri-security-center"
VERSION="$(sed -n "s/.*define('SPCRC_VERSION', '\([^']*\)').*/\1/p" "$PLUGIN_DIR/sabri-security-center.php" | head -n1)"

if [[ -z "$VERSION" ]]; then
  echo "Unable to resolve SPCRC_VERSION" >&2
  exit 1
fi

BUILD_DIR="$ROOT/build"
STAGE="$BUILD_DIR/sabri-security-center"
ZIP="$BUILD_DIR/24-sabri-platform-security-privacy-compliance-and-resilience-center-${VERSION}.zip"
SOURCE_EPOCH="${SOURCE_DATE_EPOCH:-1767225600}"

rm -rf "$BUILD_DIR"
mkdir -p "$STAGE"
cp -R "$PLUGIN_DIR"/. "$STAGE"/
find "$STAGE" -exec touch -h -d "@${SOURCE_EPOCH}" {} +
(
  cd "$BUILD_DIR"
  LC_ALL=C find sabri-security-center -type f -print | sort | zip -X -q "$ZIP" -@
)
unzip -t "$ZIP" >/dev/null
unzip -l "$ZIP" | grep -q 'sabri-security-center/sabri-security-center.php'
(cd "$BUILD_DIR" && sha256sum "$(basename "$ZIP")" > "$(basename "$ZIP").sha256")
printf '%s\n' "$ZIP"
