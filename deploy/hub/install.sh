#!/bin/bash
# NeoHost HUB (Node.js) — instalare pe hosting central
# Rulează din repo: bash deploy/hub/install.sh

set -e
RED='\033[0;31m'
GREEN='\033[0;32m'
AMBER='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INSTALL_DIR="${INSTALL_DIR:-/opt/neohost-security}"
DOMAIN="${DOMAIN:-security.neohost.md}"
TOKEN=$(openssl rand -hex 32)

if ! command -v node >/dev/null 2>&1; then
  echo -e "${RED}Node.js lipsește! Instalați Node 18+ (nvm, nodesource sau din panel).${NC}"
  exit 1
fi

NODE_MAJOR=$(node -p "process.versions.node.split('.')[0]")
if [ "$NODE_MAJOR" -lt 18 ]; then
  echo -e "${RED}Necesită Node.js 18+. Versiune curentă: $(node -v)${NC}"
  exit 1
fi

if [ -z "$DATABASE_URL" ]; then
  echo -e "${AMBER}DATABASE_URL nesetat — folosesc SQLite local.${NC}"
  export DATABASE_URL="sqlite:///${INSTALL_DIR}/hub/data/neohost.db"
fi

echo -e "${GREEN}[1/5] Copiere hub Node.js + frontend...${NC}"
mkdir -p "$INSTALL_DIR/hub" "$INSTALL_DIR/frontend/dist"
rsync -a --exclude='node_modules' --exclude='data' \
  "$REPO_ROOT/hub/" "$INSTALL_DIR/hub/"
cp -r "$REPO_ROOT/frontend/dist/"* "$INSTALL_DIR/frontend/dist/" 2>/dev/null || true

echo -e "${GREEN}[2/5] npm install (producție)...${NC}"
cd "$INSTALL_DIR/hub"
npm install --omit=dev --silent

echo -e "${GREEN}[3/5] Build frontend (dacă lipsește dist)...${NC}"
if [ ! -f "$INSTALL_DIR/frontend/dist/index.html" ]; then
  cd "$REPO_ROOT/frontend"
  npm install --silent && npm run build --silent
  cp -r dist/* "$INSTALL_DIR/frontend/dist/"
fi

echo -e "${GREEN}[4/5] systemd...${NC}"
cp "$SCRIPT_DIR/neohost-security.service" /etc/systemd/system/
sed -i "s|schimba-acest-token-secret|${TOKEN}|g" /etc/systemd/system/neohost-security.service
sed -i "s|DATABASE_URL=.*|DATABASE_URL=${DATABASE_URL}|g" /etc/systemd/system/neohost-security.service
sed -i "s|WorkingDirectory=.*|WorkingDirectory=${INSTALL_DIR}/hub|g" /etc/systemd/system/neohost-security.service

systemctl daemon-reload
systemctl enable neohost-security
systemctl restart neohost-security

echo -e "${GREEN}[5/5] Nginx (opțional, dacă nu folosiți panel proxy)...${NC}"
if [ -d /etc/nginx/sites-available ]; then
  cp "$SCRIPT_DIR/nginx-security.conf" /etc/nginx/sites-available/neohost-security
  sed -i "s/security.neohost.md/$DOMAIN/g" /etc/nginx/sites-available/neohost-security
  sed -i "s|root /opt/neohost-security/frontend/dist|root ${INSTALL_DIR}/frontend/dist|g" /etc/nginx/sites-available/neohost-security
  ln -sf /etc/nginx/sites-available/neohost-security /etc/nginx/sites-enabled/ 2>/dev/null || true
  nginx -t && systemctl reload nginx 2>/dev/null || true
fi

echo ""
echo -e "${GREEN}✓ Hub Node.js instalat la ${INSTALL_DIR}/hub${NC}"
echo -e "URL:   https://${DOMAIN}"
echo -e "Login: admin / admin (schimbați din Profil)"
echo -e "Token: ${AMBER}${TOKEN}${NC} (SECURITY_API_TOKEN)"
echo ""
echo "Alternativă panel: PM2 → cd ${INSTALL_DIR}/hub && pm2 start ecosystem.config.cjs"
echo "Agent pe servere Linux: bash deploy/agent/install.sh"
