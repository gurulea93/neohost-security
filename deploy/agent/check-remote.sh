#!/bin/bash
# Verifică agentul și conectivitatea către hub
set -e
RED='\033[0;31m'
GREEN='\033[0;32m'
AMBER='\033[1;33m'
NC='\033[0m'

HUB_URL="${HUB_URL:-$(grep -oP 'HUB_URL=\K[^"]+' /etc/systemd/system/neohost-agent.service 2>/dev/null || echo '')}"
AGENT_KEY="${AGENT_KEY:-$(grep -oP 'AGENT_KEY=\K[^"]+' /etc/systemd/system/neohost-agent.service 2>/dev/null || echo '')}"

echo "=== NeoHost Agent — diagnostic ==="

if systemctl is-active --quiet neohost-agent; then
  echo -e "${GREEN}✓${NC} neohost-agent activ"
else
  echo -e "${RED}✗${NC} neohost-agent inactiv — systemctl status neohost-agent"
  exit 1
fi

if [ -z "$HUB_URL" ] || [ -z "$AGENT_KEY" ]; then
  echo -e "${RED}✗${NC} HUB_URL sau AGENT_KEY lipsesc din serviciu"
  exit 1
fi

echo "Hub: $HUB_URL"

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "X-Agent-Key: $AGENT_KEY" \
  "$HUB_URL/api/agent/commands" || echo "000")

if [ "$HTTP_CODE" = "200" ]; then
  echo -e "${GREEN}✓${NC} Hub accesibil (GET /api/agent/commands → 200)"
else
  echo -e "${RED}✗${NC} Hub răspunde HTTP $HTTP_CODE — verificați URL, firewall outbound, AGENT_KEY"
  exit 1
fi

echo -e "${AMBER}→${NC} Ultima activitate (journal, 5 linii):"
journalctl -u neohost-agent -n 5 --no-pager

for cmd in fail2ban-client csf nft ss python3; do
  if command -v "$cmd" >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} $cmd găsit"
  else
    echo -e "${AMBER}○${NC} $cmd absent (modul opțional)"
  fi
done

echo -e "${GREEN}Diagnostic complet.${NC}"
