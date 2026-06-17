#!/bin/bash
# NeoHost HUB — instalare pe hosting central (dashboard + API + DB)
# Rulează din repo: bash deploy/hub/install.sh

set -e
RED='\033[0;31m'
GREEN='\033[0;32m'
AMBER='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INSTALL_DIR="/opt/neohost-security"
DOMAIN="${DOMAIN:-security.neohost.md}"
TOKEN=$(openssl rand -hex 32)

if [ -z "$DATABASE_URL" ]; then
  echo -e "${RED}DATABASE_URL lipsește!${NC}"
  echo "  export DATABASE_URL='postgresql://user:pass@localhost/neohost'"
  exit 1
fi

echo -e "${GREEN}[1/6] Copiere backend hub (fără agent)...${NC}"
mkdir -p "$INSTALL_DIR/backend" "$INSTALL_DIR/frontend"
rsync -a --exclude='.venv' --exclude='__pycache__' --exclude='*.db' \
  --exclude='agent.py' --exclude='collector.py' \
  "$REPO_ROOT/backend/" "$INSTALL_DIR/backend/"
cp -r "$REPO_ROOT/frontend/dist" "$INSTALL_DIR/frontend/dist" 2>/dev/null || true

echo -e "${GREEN}[2/6] Python venv...${NC}"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install -q -r "$INSTALL_DIR/backend/requirements.txt"

echo -e "${GREEN}[3/6] systemd...${NC}"
cp "$SCRIPT_DIR/neohost-security.service" /etc/systemd/system/
sed -i "s/schimba-acest-token-secret/$TOKEN/" /etc/systemd/system/neohost-security.service
grep -q "DATABASE_URL" /etc/systemd/system/neohost-security.service || \
  sed -i "/Environment=\"PORT/a Environment=\"DATABASE_URL=$DATABASE_URL\"" /etc/systemd/system/neohost-security.service

echo -e "${GREEN}[4/6] Build frontend (dacă lipsește dist)...${NC}"
if [ ! -d "$INSTALL_DIR/frontend/dist" ]; then
  cd "$REPO_ROOT/frontend"
  npm install --silent && npm run build --silent
  cp -r dist "$INSTALL_DIR/frontend/"
  cd - >/dev/null
fi

echo -e "${GREEN}[5/6] Pornire hub...${NC}"
systemctl daemon-reload
systemctl enable neohost-security
systemctl restart neohost-security

echo -e "${GREEN}[6/6] Nginx...${NC}"
cp "$SCRIPT_DIR/nginx-security.conf" /etc/nginx/sites-available/neohost-security
sed -i "s/security.neohost.md/$DOMAIN/g" /etc/nginx/sites-available/neohost-security
ln -sf /etc/nginx/sites-available/neohost-security /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx

echo ""
echo -e "${GREEN}✓ Hub instalat la $INSTALL_DIR${NC}"
echo -e "URL:   https://$DOMAIN"
echo -e "Token: ${AMBER}$TOKEN${NC} (SECURITY_API_TOKEN — salvați!)"
echo "Agent pe servere: bash deploy/agent/install.sh"
