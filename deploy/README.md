# Deploy — separare HOST vs SERVERE

## HOST (hub central)

**Unde:** hosting (VPS, cPanel, CloudPanel, FastPanel, BrainyCP, DirectAdmin…)

**Ce face:** dashboard web, API REST, WebSocket, baza de date, bot Telegram, autentificare panou.

**Tehnologie:** **Node.js 22.5+** (`hub/`) — fără Python pe hosting.

**Fișiere:** `deploy/hub/`

| Fișier | Descriere |
|--------|-----------|
| `install.sh` | Instalare Node + systemd în `/opt/neohost-security` |
| `package.sh` | Arhivă `dist/neohost-hub.tar.gz` |
| `panels.md` | Ghid generic panel hosting |
| `cloudpanel.md` | Ghid CloudPanel |
| `neohost-security.service` | systemd (node src/index.js) |
| `nginx-security.conf` | Reverse proxy HTTPS + SPA |

**Din repo:**
- `hub/` (fără `node_modules`, `data/`)
- `frontend/dist/` (build React)

**Instalare VPS:**
```bash
cd frontend && npm install && npm run build && cd ..
export DATABASE_URL='mysql://user:pass@127.0.0.1:3306/neohost'
export DOMAIN='security.domeniu.md'
bash deploy/hub/install.sh
```

**Panel (PM2):**
```bash
cd hub && npm install --omit=dev
cp .env.example .env   # editează DATABASE_URL
pm2 start ecosystem.config.cjs && pm2 save
```

---

## SERVERE controlate (agenți)

**Unde:** fiecare server Linux administrat

**Tehnologie:** **Python 3** (`agent.py`, `collector.py`)

**Fișiere:** `deploy/agent/`

| Fișier | Descriere |
|--------|-----------|
| `install.sh` | Instalare în `/opt/neohost-agent` |
| `package.sh` | Arhivă `dist/neohost-agent.tar.gz` |
| `check-remote.sh` | Diagnostic conectivitate |
| `neohost-agent.service` | systemd (root) |

**Instalare:**
```bash
export HUB_URL='https://security.domeniu.md'
export AGENT_KEY='cheia-din-dashboard'
bash deploy/agent/install.sh
bash deploy/agent/check-remote.sh
```

---

## Ce stă unde

| Componentă | HOST | SERVER |
|------------|:----:|:------:|
| `hub/` (Node.js API) | ✓ | |
| `frontend/dist` | ✓ | |
| MySQL / MariaDB / PostgreSQL | ✓ | |
| `agent.py`, `collector.py` | | ✓ |
| fail2ban, csf, nft | | ✓ |
| Port inbound 443 (HTTPS) | ✓ | ✗ (doar outbound) |
