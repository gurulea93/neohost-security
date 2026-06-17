# NeoHost Hub pe orice panel (Node.js)

Hub-ul rulează **doar Node.js** — fără Python, fără gunicorn, fără venv.  
Funcționează similar pe **CloudPanel, cPanel, FastPanel, BrainyCP, DirectAdmin, Plesk** (cu Node sau SSH).

Agentul Python (`deploy/agent/`) merge **doar pe serverele Linux** pe care le controlezi.

---

## Ce instalezi pe hosting

| Componentă | Tehnologie |
|-----------|------------|
| Interfață | `frontend/dist/` — fișiere statice |
| API + WebSocket | `hub/` — `node src/index.js` |
| Bază de date | MySQL/MariaDB (recomandat) sau SQLite |

**Cerințe:** Node.js **18+**, npm, acces SSH (ideal).

---

## Pași rapizi (orice panel)

### 1. Build local sau pe server

```bash
cd frontend && npm install && npm run build
cd ../hub && npm install --omit=dev
```

### 2. Upload pe server

Încarcă (SFTP/Git):
- `hub/` (fără `node_modules` — rulezi `npm install` pe server)
- `frontend/dist/`

### 3. Variabile de mediu

Creează `hub/.env` (copiază din `hub/.env.example`):

```env
HOST=127.0.0.1
PORT=7654
NODE_ENV=production
SERVE_STATIC=1
DATABASE_URL=mysql://USER:PAROLA@127.0.0.1:3306/neohost
SECURITY_API_TOKEN=token-secret-lung
```

`SERVE_STATIC=1` — Node servește și React (util când panelul nu are document root separat).

### 4. Pornește procesul

**Variantă A — PM2** (cPanel Node, FastPanel, VPS):

```bash
cd hub
npm install --omit=dev
pm2 start ecosystem.config.cjs
pm2 save
```

**Variantă B — systemd** (VPS root):

```bash
bash deploy/hub/install.sh
```

**Variantă C — panel „Node.js app”:**

- App root: `hub/`
- Start file: `src/index.js`
- Port: `7654` (sau ce setezi în `.env`)

### 5. Proxy Nginx / Apache

Trimite `/api/` și `/ws` către `http://127.0.0.1:7654`:

```nginx
location /api/ {
    proxy_pass http://127.0.0.1:7654;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}

location /ws {
    proxy_pass http://127.0.0.1:7654;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_read_timeout 3600s;
}
```

Dacă `SERVE_STATIC=0`, pune `frontend/dist` în document root și proxy doar `/api` + `/ws`.

### 6. Verificare

```bash
curl http://127.0.0.1:7654/api/status
```

Browser: `https://domeniul-tau.md` → login **admin** / **admin**

---

## Panel-specific

| Panel | Recomandare |
|-------|-------------|
| **CloudPanel** | Site static + Node pe 7654 + custom nginx → [cloudpanel.md](cloudpanel.md) |
| **cPanel** | Setup Node.js App → `hub/`, sau PM2 via SSH |
| **FastPanel** | Site + reverse proxy la port 7654, PM2 pentru Node |
| **BrainyCP** | Similar FastPanel — nginx proxy + `pm2 start` |
| **DirectAdmin** | Custom HTTPD/Nginx include pentru `/api` și `/ws` |
| **VPS simplu** | `bash deploy/hub/install.sh` (systemd + nginx) |

---

## Bază de date

**MySQL/MariaDB** (din panel → Databases):

```env
DATABASE_URL=mysql://user:parola@127.0.0.1:3306/neohost
```

Tabelele se creează automat la prima pornire.

**SQLite** (test / un singur client):

```env
DATABASE_URL=sqlite:///opt/neohost-security/hub/data/neohost.db
```

---

## Agent pe servere Linux (neschimbat)

```bash
export HUB_URL='https://security.domeniul-tau.md'
export AGENT_KEY='cheia-din-panou'
bash deploy/agent/install.sh
```

Agentul rămâne **Python** — doar hub-ul e Node.js.

---

## Arhivă deploy

```bash
bash deploy/hub/package.sh
# → dist/neohost-hub.tar.gz
```

Pe server:

```bash
tar -xzf neohost-hub.tar.gz
cd neohost-hub
export DATABASE_URL='mysql://...'
bash deploy/hub/install.sh
```
