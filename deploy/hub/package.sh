#!/bin/bash
# Arhivă deploy HUB — rulează din repo: bash deploy/hub/package.sh
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT="$REPO_ROOT/dist/neohost-hub"
ARCHIVE="$REPO_ROOT/dist/neohost-hub.tar.gz"

cd "$REPO_ROOT/frontend"
npm install --silent && npm run build --silent
cd "$REPO_ROOT"

rm -rf "$OUT"
mkdir -p "$OUT/backend" "$OUT/frontend/dist" "$OUT/deploy/hub"
rsync -a --exclude='.venv' --exclude='__pycache__' --exclude='*.db' \
  --exclude='agent.py' --exclude='collector.py' \
  "$REPO_ROOT/backend/" "$OUT/backend/"
cp -r "$REPO_ROOT/frontend/dist/"* "$OUT/frontend/dist/"
cp "$SCRIPT_DIR/install.sh" "$SCRIPT_DIR/neohost-security.service" "$SCRIPT_DIR/nginx-security.conf" "$OUT/deploy/hub/"

mkdir -p "$REPO_ROOT/dist"
tar -czf "$ARCHIVE" -C "$REPO_ROOT/dist" neohost-hub
echo "Creat: $ARCHIVE"
