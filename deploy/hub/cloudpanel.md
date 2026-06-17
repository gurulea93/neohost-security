# NeoHost Hub pe CloudPanel

Pe CloudPanel pui **doar HUB-ul** (dashboard + API). **Nu** pui agentul aici — agentul merge pe serverele Linux pe care le controlezi.

---

## Ce ai nevoie

- VPS cu **CloudPanel** (acces SSH, ideal root sau sudo)
- Domeniu/subdomeniu, ex: `security.domeniu.md`
- **MariaDB** sau **MySQL** (din CloudPanel → Databases)
- Python **3.10+** pe server (`python3 --version`)

---

## Pas 1 — Site în CloudPanel

1. **Sites → Add Site**
2. Tip: **Create a PHP Site** (sau static — important e domeniul)
3. Domain: `security.domeniu.md`
4. Notează **Site User** (ex: `neohost-sec`)

SSL: **Sites → domeniu → SSL/TLS → Let's Encrypt** (Activează HTTPS)

---

## Pas 2 — Bază de date

1. **Databases → Add Database**
2. Nume DB: `neohost`
3. User + parolă puternică
4. Notează pentru `DATABASE_URL`:

```bash
export DATABASE_URL='mysql+pymysql://USER:PAROLA@127.0.0.1:3306/neohost'
```

(URL-encode parola dacă are caractere speciale: `@` → `%40`, etc.)

---

## Pas 3 — Încarcă fișierele hub (SSH)

Conectează-te SSH (CloudPanel → Site → SSH / sau root):

```bash
# Ca root sau site user — exemplu director:
INSTALL=/home/neohost-sec/neohost-security
mkdir -p "$INSTALL"
cd "$INSTALL"
```

### Variantă A — arhivă de pe PC

Pe PC (în repo):

```bash
bash deploy/hub/package.sh
```

Încarcă `dist/neohost-hub.tar.gz` pe server (SFTP/SCP), apoi:

```bash
cd /home/neohost-sec
tar -xzf neohost-hub.tar.gz
# structura din arhivă: neohost-hub/backend, neohost-hub/frontend/dist
mv neohost-hub "$INSTALL"   # sau extrage direct în $INSTALL
```

### Variantă B — git clone

```bash
git clone <repo-ul-tau> "$INSTALL"
cd "$INSTALL/frontend" && npm install && npm run build
```

---

## Pas 4 — Backend Python (venv + gunicorn)

```bash
INSTALL=/home/neohost-sec/neohost-security
cd "$INSTALL"

python3 -m venv venv
./venv/bin/pip install -r backend/requirements.txt

export DATABASE_URL='mysql+pymysql://USER:PAROLA@127.0.0.1:3306/neohost'
export HOST=127.0.0.1
export PORT=7654
export SECURITY_API_TOKEN=$(openssl rand -hex 32)
# Salvează TOKEN-ul undeva sigur (opțional, login panou e principal)

# Test rapid (Ctrl+C după ce vezi că pornește):
cd backend && ../venv/bin/python app.py
```

Producție — **systemd** (ca root), fișier `/etc/systemd/system/neohost-security.service`:

```ini
[Unit]
Description=NeoHost Security Hub
After=network.target mariadb.service

[Service]
Type=simple
User=neohost-sec
WorkingDirectory=/home/neohost-sec/neohost-security/backend
Environment="DATABASE_URL=mysql+pymysql://USER:PAROLA@127.0.0.1:3306/neohost"
Environment="HOST=127.0.0.1"
Environment="PORT=7654"
ExecStart=/home/neohost-sec/neohost-security/venv/bin/gunicorn \
    --worker-class flask_sock.gunicorn.Worker \
    --workers 2 \
    --bind 127.0.0.1:7654 \
    --timeout 120 \
    app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now neohost-security
systemctl status neohost-security
```

---

## Pas 5 — Frontend (fișiere statice)

Copiază build-ul React în **document root**-ul site-ului CloudPanel:

```bash
SITE_ROOT=/home/neohost-sec/htdocs/security.domeniu.md
# calea exactă o vezi în CloudPanel → Site → Vhost → Document Root

rsync -a "$INSTALL/frontend/dist/" "$SITE_ROOT/"
```

Sau, dacă ai extras din `neohost-hub.tar.gz`:

```bash
rsync -a "$INSTALL/frontend/dist/" "$SITE_ROOT/"
```

---

## Pas 6 — Nginx în CloudPanel (reverse proxy API + WebSocket)

CloudPanel gestionează Nginx. **Nu** înlocui tot vhost-ul manual — adaugă directive custom.

**Sites → security.domeniu.md → Vhost → Vhost (sau Custom Directives / Reverse Proxy)**

Adaugă **în blocul `server` HTTPS** (sub `root`):

```nginx
location /api/ {
    proxy_pass         http://127.0.0.1:7654;
    proxy_set_header   Host $host;
    proxy_set_header   X-Real-IP $remote_addr;
    proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_read_timeout 60s;
}

location /ws {
    proxy_pass          http://127.0.0.1:7654;
    proxy_http_version  1.1;
    proxy_set_header    Upgrade $http_upgrade;
    proxy_set_header    Connection "upgrade";
    proxy_set_header    Host $host;
    proxy_read_timeout  3600s;
    proxy_send_timeout  3600s;
}

location / {
    try_files $uri $uri/ /index.html;
}
```

Salvează și reîncarcă Nginx din CloudPanel (sau `nginx -t && systemctl reload nginx` ca root).

---

## Pas 7 — Verificare

1. `curl -s http://127.0.0.1:7654/api/status` pe server → răspuns JSON
2. Browser: `https://security.domeniu.md` → login panou
3. Login implicit prima dată: **admin / admin** → schimbă parola în **Profil**
4. **Servere → Adaugă server** → copiază **Agent Key**

---

## Pas 8 — Agenți pe serverele tale (NU pe CloudPanel)

Pe fiecare VPS/client Linux:

```bash
export HUB_URL='https://security.domeniu.md'
export AGENT_KEY='cheia-din-panou'
bash deploy/agent/install.sh
```

---

## Rezumat — ce stă unde pe CloudPanel

| Componentă | Locație |
|------------|---------|
| React (`frontend/dist`) | `/home/USER/htdocs/DOMENIU/` |
| Flask API | `127.0.0.1:7654` (gunicorn + systemd) |
| MariaDB | CloudPanel Databases |
| `agent.py` | **NU** pe CloudPanel |

---

## Probleme frecvente

| Simptom | Soluție |
|---------|---------|
| Pagină albă / 502 la login | `systemctl status neohost-security`; verifică `DATABASE_URL` |
| API 404 | Lipsește `location /api/` în vhost |
| WebSocket nu merge | Lipsește `location /ws` cu `Upgrade` |
| DB connection error | User DB are drepturi pe `neohost`; host `127.0.0.1` |
| CORS / wrong API URL | Frontend folosește același domeniu (proxy `/api`) — nu e nevoie de `VITE_API_URL` dacă totul e pe același host |

---

## Securitate

- Schimbă parola `admin` imediat
- Restricționează SSH / CloudPanel admin
- Opțional: IP whitelist în Profil → Whitelist
- `HUB_URL` pentru agenți = URL-ul HTTPS public
