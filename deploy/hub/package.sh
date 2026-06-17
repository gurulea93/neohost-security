#!/bin/bash
# Arhivă deploy HUB (Node.js) — rulează din repo: bash deploy/hub/package.sh
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT="$REPO_ROOT/dist/neohost-hub"
ARCHIVE="$REPO_ROOT/dist/neohost-hub.tar.gz"

cd "$REPO_ROOT/frontend"
npm install --silent && npm run build --silent
cd "$REPO_ROOT"

rm -rf "$OUT"
mkdir -p "$OUT/hub" "$OUT/frontend/dist" "$OUT/deploy/hub" "$OUT/deploy/agent"

rsync -a --exclude='node_modules' --exclude='data' \
  "$REPO_ROOT/hub/" "$OUT/hub/"
cp -r "$REPO_ROOT/frontend/dist/"* "$OUT/frontend/dist/"
cp "$SCRIPT_DIR/install.sh" "$SCRIPT_DIR/neohost-security.service" \
   "$SCRIPT_DIR/nginx-security.conf" "$SCRIPT_DIR/cloudpanel.md" "$OUT/deploy/hub/"
rsync -a "$REPO_ROOT/deploy/agent/" "$OUT/deploy/agent/"

mkdir -p "$REPO_ROOT/dist"
tar -czf "$ARCHIVE" -C "$REPO_ROOT/dist" neohost-hub
echo "Creat: $ARCHIVE"
echo "Pe server: tar -xzf neohost-hub.tar.gz && cd neohost-hub && bash deploy/hub/install.sh"
