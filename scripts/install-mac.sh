#!/usr/bin/env bash
# Rebuilds the macOS app from the current source and copies it to /Applications, replacing the old copy.
# Usage: npm run install:mac
set -euo pipefail
cd "$(dirname "$0")/.."

npm run pack
SRC="dist/mac-arm64/Trototita.app"
DEST="/Applications/Trototita.app"

if [ ! -d "$SRC" ]; then
  echo "Build did not produce $SRC" >&2
  exit 1
fi

# Close the running copy so it is not replaced while open.
osascript -e 'quit app "Trototita"' >/dev/null 2>&1 || true
sleep 1

rm -rf "$DEST" 2>/dev/null || { echo "Could not replace $DEST. Try: sudo npm run install:mac" >&2; exit 1; }
ditto "$SRC" "$DEST"
echo "Installed $(grep -o '"version": *"[^"]*"' package.json | head -1) to $DEST"
echo "Open it from Applications or Spotlight (Trototita)."
