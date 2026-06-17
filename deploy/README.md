# Deploy — separare HOST vs SERVERE

## HOST (hub central)

**Unde:** hosting-ul tău (VPS cu Nginx, PostgreSQL/MySQL, domeniu HTTPS)

**Ce face:** dashboard web, API REST, WebSocket live, baza de date, bot Telegram, autentificare panou.

**Fișiere:** vezi `deploy/hub/`

| Fișier | Descriere |
|--------|-----------|
| `install.sh` | Instalare în `/opt/neohost-security` |
| `package.sh` | Creează `dist/neohost-hub.tar.gz` |
| `neohost-security.service` | systemd backend (gunicorn) |
| `nginx-security.conf` | Reverse proxy HTTPS + SPA |

**Din repo (sursă):**
- `backend/*` **fără** `agent.py`, `collector.py`
- `frontend/dist/` (build React)

**Instalare:**
```bash
export DATABASE_URL='postgresql://user:pass@localhost/neohost'
export DOMAIN='security.domeniu.md'
bash deploy/hub/install.sh
```

---

## SERVERE controlate (agenți)

**Unde:** fiecare server Linux administrat (web, mail, VPS client)

**Ce face:** raportează starea la hub, execută comenzi Fail2Ban / CSF / nftables local.

**Fișiere:** vezi `deploy/agent/`

| Fișier | Descriere |
|--------|-----------|
| `install.sh` | Instalare în `/opt/neohost-agent` |
| `package.sh` | Creează `dist/neohost-agent.tar.gz` |
| `check-remote.sh` | Diagnostic conectivitate + serviciu |
| `neohost-agent.service` | systemd agent (root) |

**Din repo (sursă):**
- `backend/agent.py`
- `backend/collector.py`

**Instalare:**
```bash
export HUB_URL='https://security.domeniu.md'
export AGENT_KEY='cheia-din-dashboard'
bash deploy/agent/install.sh
bash deploy/agent/check-remote.sh
```

---

## Ce NU se amestecă

| Componentă | HOST | SERVER |
|------------|:----:|:------:|
| `app.py`, modele DB, Telegram | ✓ | |
| `frontend/dist` | ✓ | |
| PostgreSQL / MySQL | ✓ | |
| `agent.py`, `collector.py` | | ✓ |
| fail2ban-client, csf, nft | | ✓ (opțional) |
| Port inbound deschis | ✓ (443) | ✗ (doar outbound) |
