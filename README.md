# NeoHost Security Monitor

**v3.0** — Dashboard central multi-server pentru **Fail2Ban**, **CSF** și **nftables**, cu control la distanță prin agenți pe fiecare server Linux.

| Componentă | Tehnologie | Unde rulează |
|------------|------------|--------------|
| **Hub** (panou + API) | **Node.js 22.5+** | Hosting (cPanel, CloudPanel, VPS…) |
| **Frontend** | React + Vite | Build static pe hosting |
| **Agent** | Python 3 | Servere Linux administrate |

---

## Arhitectură

```
┌──────────────────────────── HOST (hub) ────────────────────────────┐
│  Nginx / panel proxy  →  frontend/dist (React static)              │
│                       →  hub/ (Node.js API + WebSocket + Telegram) │
│                       →  MySQL / MariaDB / PostgreSQL / SQLite       │
└────────────────────────────▲─────────────────────────────────────┘
                             │ HTTPS outbound (agent inițiază)
         ┌───────────────────┼───────────────────┐
         │                   │                   │
┌────────┴────────┐ ┌────────┴────────┐ ┌───────┴─────────┐
│ SERVER 1        │ │ SERVER 2        │ │ SERVER N        │
│ agent.py        │ │ agent.py        │ │ agent.py        │
│ collector.py    │ │ collector.py    │ │ collector.py    │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

**Regulă:** pe **HOST** = Node.js (`hub/`) + fișiere statice. Pe **SERVERE** = agent **Python** (neschimbat).

**Ghiduri deploy:**
- [deploy/README.md](deploy/README.md) — separare HOST vs SERVERE
- [deploy/hub/panels.md](deploy/hub/panels.md) — cPanel, FastPanel, BrainyCP, DirectAdmin
- [deploy/hub/cloudpanel.md](deploy/hub/cloudpanel.md) — CloudPanel

---

## Instalare rapidă (HOST)

```bash
# 1. Build frontend
cd frontend && npm install && npm run build && cd ..

# 2. Hub Node.js
cd hub && npm install --omit=dev && cd ..

# 3. Configurare (copiază hub/.env.example → hub/.env)
# DATABASE_URL=mysql://user:pass@127.0.0.1:3306/neohost

# 4. Pornire (PM2 sau systemd)
cd hub && pm2 start ecosystem.config.cjs && pm2 save
```

**VPS cu root:** `bash deploy/hub/install.sh`  
**Arhivă:** `bash deploy/hub/package.sh` → `dist/neohost-hub.tar.gz`

---

## Instalare agent (SERVER Linux)

```bash
export HUB_URL='https://security.domeniul-tau.md'
export AGENT_KEY='cheia-din-panou-servere'
bash deploy/agent/install.sh
bash deploy/agent/check-remote.sh
```

Arhivă: `bash deploy/agent/package.sh` → `dist/neohost-agent.tar.gz`

---

## Dezvoltare locală (Windows)

**Cerințe:** Node.js **22.5+**, npm

```bat
run-local.bat
```

| Serviciu | URL |
|----------|-----|
| Hub (Node.js) | http://127.0.0.1:7654 |
| Frontend (Vite) | http://127.0.0.1:5173 |
| Login | `admin` / `admin` |

Baza locală: SQLite în `hub/data/neohost.db` (fără date demo).

Manual:
```bash
cd hub && npm install && npm run dev
cd frontend && npm install && npm run dev
```

---

## Variabile de mediu (hub)

| Variabilă | Descriere |
|-----------|-----------|
| `DATABASE_URL` | `mysql://…`, `postgresql://…` sau SQLite (implicit local) |
| `HOST`, `PORT` | Bind API (default `127.0.0.1:7654`) |
| `SERVE_STATIC=1` | Node servește și `frontend/dist` |
| `SECURITY_API_TOKEN` | Token API legacy (opțional) |
| `TELEGRAM_BOT_TOKEN` | Bot Telegram (opțional) |
| `TELEGRAM_WEBAPP_URL` | URL Mini App Telegram |
| `PANEL_ADMIN_USERNAME` | Admin inițial (default `admin`) |
| `PANEL_ADMIN_PASSWORD` | Parolă inițială (default `admin`) |

Agent (pe servere): `HUB_URL`, `AGENT_KEY`, `AGENT_INTERVAL` (default 5s).

Exemplu complet: [hub/.env.example](hub/.env.example)

---

## Funcționalități

### Module per server (`mod_*` / `cap_*`)

| Modul | Control la distanță |
|-------|---------------------|
| **Fail2Ban** | ban/unban, jailuri, reload, șabloane |
| **CSF** | deny/allow, toggles, porturi TCP_IN/OUT, preset |
| **nftables** | allow/deny, reguli, chain policy, preset |

### Panou

- Multi-server, hartă atacuri, threat intel, export CSV/JSON
- Centru securitate (audit, șabloane)
- Profil: 2FA (TOTP/Telegram), branding, whitelist IP, sesiuni
- i18n: RO / EN / RU
- WebSocket live

### Telegram

Bot + Mini App: `/ban`, `/unban`, CSF, nftables, conexiuni.

---

## Control la distanță

1. Acțiune în panou → coadă `agent_commands`
2. Agent poll `GET /api/agent/commands` (~5s)
3. Execuție locală (`fail2ban-client`, `csf`, `nft`)
4. Snapshot nou → WebSocket actualizează UI

**Cerințe:** agent root, `HUB_URL` accesibil outbound, `AGENT_KEY` valid, modul activ + tool instalat.

---

## Structura proiectului

```
neohost-security/
├── hub/                    ← HOST — API Node.js (Express + WebSocket)
│   ├── src/
│   ├── ecosystem.config.cjs   ← PM2
│   ├── package.json
│   └── .env.example
├── frontend/               ← HOST — React (build → dist/)
├── backend/
│   ├── agent.py            ← SERVER — agent Python
│   ├── collector.py        ← SERVER
│   └── app.py              ← legacy (înlocuit de hub/)
└── deploy/
    ├── hub/                ← install Node, nginx, systemd
    └── agent/              ← install agent Linux
```

---

## API

**Agent** (header `X-Agent-Key`):
- `POST /api/agent/report`
- `GET /api/agent/commands`
- `POST /api/agent/commands/{id}/done`

**Panou** (header `Authorization: Bearer <token>`):
- `?server_id=1` pe majoritatea rutelor
- `GET /api/status` — health check

---

## Securitate

- Hub pe `127.0.0.1`, expus prin Nginx HTTPS
- Cheie agent unică per server
- Sesiuni panou + 2FA + whitelist IP opțional

---

## Changelog

### v3.0.0
- **Hub rescris în Node.js** — fără Python/gunicorn pe hosting
- Deploy simplificat: PM2, systemd, compatibil cPanel / CloudPanel / FastPanel
- SQLite local via `node:sqlite` (fără module native)
- Module nftables, CSF, Fail2Ban independente
- Telegram bot + Mini App
- i18n RO / EN / RU

### v2.x (legacy)
- Hub Python Flask (`backend/app.py`) — păstrat pentru referință, înlocuit de `hub/`
