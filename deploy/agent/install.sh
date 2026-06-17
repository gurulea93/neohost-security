#!/bin/bash
# NeoHost AGENT — instalare pe server Linux controlat
# AGENT_KEY=xxx HUB_URL=https://... bash deploy/agent/install.sh

set -e
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INSTALL_DIR="/opt/neohost-agent"
HUB_URL="${HUB_URL:-https://security.neohost.md}"
AGENT_KEY="${AGENT_KEY:-}"

if [ -z "$AGENT_KEY" ]; then
  echo -e "${RED}AGENT_KEY lipsește! Dashboard → Servere → Key${NC}"
  exit 1
fi

echo -e "${GREEN}[1/4] Copiere agent...${NC}"
mkdir -p "$INSTALL_DIR"
cp "$REPO_ROOT/backend/agent.py" "$REPO_ROOT/backend/collector.py" "$INSTALL_DIR/"

echo -e "${GREEN}[2/4] venv Python...${NC}"
python3 -m venv "$INSTALL_DIR/venv" 2>/dev/null || true

echo -e "${GREEN}[3/4] systemd...${NC}"
cp "$SCRIPT_DIR/neohost-agent.service" /etc/systemd/system/
sed -i "s|https://security.neohost.md|$HUB_URL|g" /etc/systemd/system/neohost-agent.service
sed -i "s/INLOCUITI-CU-KEY-DIN-DASHBOARD/$AGENT_KEY/" /etc/systemd/system/neohost-agent.service

echo -e "${GREEN}[4/4] Pornire agent...${NC}"
systemctl daemon-reload
systemctl enable neohost-agent
systemctl restart neohost-agent

echo -e "${GREEN}✓ Agent instalat${NC}"
echo "Verificare: bash $SCRIPT_DIR/check-remote.sh"
