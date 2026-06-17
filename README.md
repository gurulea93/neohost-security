# NeoHost Security Monitor

Dashboard central multi-server pentru **Fail2Ban**, **CSF** și **nftables** — control la distanță prin agenți pe fiecare server Linux.

## Arhitectură

```
┌──────────────────────────── HOST (hub) ────────────────────────────┐
│  Nginx HTTPS  →  frontend/dist (React)                           │
│                →  backend/app.py (Flask API + WebSocket)           │
│                →  PostgreSQL / MySQL / MariaDB                     │
│                →  telegram_bot.py, panel_auth, notificări        │
└────────────────────────────▲─────────────────────────────────────┘
                             │ HTTPS outbound (agent inițiază)
         ┌───────────────────┼───────────────────┐
         │                   │                   │
┌────────┴────────┐ ┌────────┴────────┐ ┌───────┴─────────┐
│ SERVER 1        │ │ SERVER 2        │ │ SERVER N        │
│ agent.py        │ │ agent.py        │ │ agent.py        │
│ collector.py    │ │ collector.py    │ │ collector.py    │
│ fail2ban/csf/nft│ │ …               │ │ …               │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

**Regulă:** tot ce ține de interfață, DB și API stă pe **HOST**. Tot ce execută comenzi pe kernel/firewall stă pe **SERVERE**.

Detalii deploy: **[deploy/README.md](deploy/README.md)**

**CloudPanel:** ghid pas cu pas → **[deploy/hub/cloudpanel.md](deploy/hub/cloudpanel.md)**

---

## Separare fișiere: HOST vs SERVERE

### Pe HOST (`deploy/hub/`)

| Include | Exclude |
|---------|---------|
| `backend/app.py`, `models.py`, `db.py`, `intelligence.py` | `agent.py`, `collector.py` |
| `backend/panel_auth.py`, `telegram_bot.py`, `security_*.py` | Fail2Ban, CSF, nftables locale |
| `frontend/dist/` (build React) | |
| `nginx-security.conf`, `neohost-security.service` | |

**Instalare producție:**
```bash
cd frontend && npm install && npm run build && cd ..
export DATABASE_URL='postgresql://user:pass@localhost/neohost'
export DOMAIN='security.domeniu.md'
bash deploy/hub/install.sh
```

**Arhivă:**
```bash
bash deploy/hub/package.sh   # → dist/neohost-hub.tar.gz
```

### Pe fiecare SERVER (`deploy/agent/`)

| Include | Nu necesită |
|---------|-------------|
| `backend/agent.py` | Dashboard, frontend, DB |
| `backend/collector.py` | Nginx pe server |
| `neohost-agent.service` | Port inbound deschis |

**Instalare:**
```bash
export HUB_URL='https://security.domeniu.md'
export AGENT_KEY='cheia-din-panou-servere'
bash deploy/agent/install.sh
bash deploy/agent/check-remote.sh
```

**Arhivă:**
```bash
bash deploy/agent/package.sh   # → dist/neohost-agent.tar.gz
```

---

## Funcționalități

### Module independente (per server)

Fiecare modul are `mod_*` (activ în panou) și `cap_*` (detectat de agent):

| Modul | Pagină panou | Control la distanță |
|-------|--------------|---------------------|
| **Fail2Ban** | Jailuri | ban/unban, start/stop jail, reload, add/remove jail |
| **CSF** | CSF Firewall | deny/allow, toggles, porturi, restart, preset |
| **nftables** | nftables | allow/deny, reguli, chain policy, reload, preset |

### Panou web

- Multi-server, hartă atacuri, threat intel, istoric banuri
- Centru securitate (audit, șabloane F2B/CSF/nftables)
- Profil: 2FA, Telegram, branding, sesiuni active, notificări
- i18n: Română, English, Русский
- WebSocket live per server

### Telegram

- Bot cu meniu inline (F2B, CSF, nftables, conexiuni)
- Comenzi: `/ban`, `/unban`, `/csfdeny`, `/csfallow`, `/nftdeny`, `/nftallow`
- Mini App Web pentru acțiuni rapide

---

## Control la distanță — cum funcționează

1. Utilizatorul apasă o acțiune în panou (sau Telegram)
2. Hub-ul pune comanda în coada `agent_commands`
3. Agentul face poll la `GET /api/agent/commands` (~5s)
4. Agentul execută local (`fail2ban-client`, `csf`, `nft`)
5. Agentul raportează snapshot nou → WebSocket actualizează UI

**Cerințe pentru control complet:**
- Agent activ (`systemctl status neohost-agent`)
- Server **online** în panou (last_seen < 90s)
- `HUB_URL` accesibil **outbound** de pe server
- `AGENT_KEY` valid
- Modulul activ (`mod_*`) și tool instalat (`cap_*`)
- Agent rulează ca **root**

**Latență:** ~5–10 secunde (interval agent + poll comenzi).

---

## Dezvoltare locală (Windows/Linux)

```bat
run-local.bat
```

- Backend: http://127.0.0.1:7654
- Frontend: http://127.0.0.1:5173
- Login: `admin` / `admin` (schimbați din Profil)

SQLite local (`backend/neohost-dev.db`) — fără date demo; adăugați servere manual din panou.

---

## Bază de date (producție)

```sql
-- PostgreSQL
CREATE DATABASE neohost;
CREATE USER neohost WITH PASSWORD 'parola_sigura';
GRANT ALL PRIVILEGES ON DATABASE neohost TO neohost;
```

```bash
export DATABASE_URL='postgresql://neohost:parola@localhost:5432/neohost'
```

Tabelele se creează automat la prima pornire (`init_db`).

---

## Variabile de mediu

| Variabilă | Unde | Descriere |
|-----------|------|-----------|
| `DATABASE_URL` | HOST | PostgreSQL / MySQL / MariaDB |
| `SECURITY_API_TOKEN` | HOST | Token API legacy (opțional cu login panou) |
| `HOST`, `PORT` | HOST | Bind backend (default 127.0.0.1:7654) |
| `TELEGRAM_BOT_TOKEN` | HOST | Bot Telegram (opțional) |
| `HUB_URL` | SERVER | URL hub (`https://...`) |
| `AGENT_KEY` | SERVER | Cheie unică per server (din panou) |
| `AGENT_INTERVAL` | SERVER | Secunde între rapoarte (default 5) |

---

## Structura proiectului

```
neohost-security/
├── deploy/
│   ├── README.md          ← separare HOST vs SERVERE
│   ├── hub/               ← tot pentru hosting central
│   │   ├── install.sh
│   │   ├── package.sh
│   │   ├── neohost-security.service
│   │   └── nginx-security.conf
│   └── agent/             ← tot pentru servere controlate
│       ├── install.sh
│       ├── package.sh
│       ├── check-remote.sh
│       └── neohost-agent.service
├── backend/
│   ├── app.py             # HOST — API hub
│   ├── agent.py           # SERVER — agent
│   ├── collector.py       # SERVER — colectare locală
│   └── …
├── frontend/              # HOST — surse React (build → dist/)
├── install-hub.sh         # → deploy/hub/install.sh
├── install-agent.sh       # → deploy/agent/install.sh
└── run-local.bat          # dev local
```

---

## API agent (server → host)

| Method | Endpoint | Header |
|--------|----------|--------|
| POST | `/api/agent/report` | `X-Agent-Key` |
| GET | `/api/agent/commands` | `X-Agent-Key` |
| POST | `/api/agent/commands/{id}/done` | `X-Agent-Key` |

## API panou (utilizator → host)

Autentificare: `Authorization: Bearer <session_token>` (login panou)

Parametru: `?server_id=1` pe majoritatea rutelor.

---

## Securitate

- Hub pe `127.0.0.1`, expus doar prin Nginx HTTPS
- Cheie agent unică per server; regenerabilă din panou
- Comenzile destructive merg doar prin agent (root pe server)
- Sesiuni panou cu IP/user-agent; revocare din Profil
- 2FA: TOTP sau Telegram

---

## Changelog recent

- Module **nftables** independent (pagină, API, agent, Telegram, șabloane)
- Separare deploy `deploy/hub` vs `deploy/agent`
- Fix WebSocket reconnect, reset `liveNft`, erori API ban/unban
- Telegram `/unban` implementat
- systemd: hub fără dependență Fail2Ban; agent cu `Wants` opțional
- i18n: chei CSF/nftables, `login.2faTotpHint`
