#!/bin/bash
# Arhivă deploy AGENT — bash deploy/agent/package.sh
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT="$REPO_ROOT/dist/neohost-agent"
ARCHIVE="$REPO_ROOT/dist/neohost-agent.tar.gz"

rm -rf "$OUT"
mkdir -p "$OUT"
cp "$REPO_ROOT/backend/agent.py" "$REPO_ROOT/backend/collector.py" "$OUT/"
cp "$SCRIPT_DIR/install.sh" "$SCRIPT_DIR/check-remote.sh" "$SCRIPT_DIR/neohost-agent.service" "$OUT/"

mkdir -p "$REPO_ROOT/dist"
tar -czf "$ARCHIVE" -C "$REPO_ROOT/dist" neohost-agent
echo "Creat: $ARCHIVE"
