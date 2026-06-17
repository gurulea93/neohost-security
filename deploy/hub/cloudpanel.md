# NeoHost Hub pe CloudPanel (Node.js)

Pe CloudPanel pui **doar HUB-ul** (dashboard + API Node.js). **Nu** pui agentul aici.

> Ghid generic pentru alte paneluri: [panels.md](panels.md)

---

## Ce ai nevoie

- VPS cu **CloudPanel** + SSH
- Domeniu: ex. `security.domeniu.md`
- **Node.js 18+** (`node -v`)
- **MariaDB** (CloudPanel → Databases)

---

## Pas 1 — Site în CloudPanel

1. **Sites → Add Site**
2. Tip: **Static Site** sau **PHP Site** (pentru domeniu + SSL)
3. SSL: Let's Encrypt

---

## Pas 2 — Bază de date

1. **Databases → Add Database** → `neohost`
2. Notează user + parolă

```env
DATABASE_URL=mysql://USER:PAROLA@127.0.0.1:3306/neohost
```

---

## Pas 3 — Upload hub Node.js (SSH)

```bash
INSTALL=/home/site-user/neohost-security
mkdir -p "$INSTALL"
cd "$INSTALL"

# git clone sau upload arhivă package.sh
git clone https://github.com/gurulea93/neohost-security.git .
cd frontend && npm install && npm run build
cd ../hub && npm install --omit=dev
```

Creează `hub/.env`:

```env
HOST=127.0.0.1
PORT=7654
NODE_ENV=production
SERVE_STATIC=1
DATABASE_URL=mysql://USER:PAROLA@127.0.0.1:3306/neohost
SECURITY_API_TOKEN=$(openssl rand -hex 32)
```

---

## Pas 4 — Pornește hub-ul

**PM2** (recomandat):

```bash
cd "$INSTALL/hub"
pm2 start ecosystem.config.cjs
pm2 save
pm2 startup
```

Sau **systemd** ca root: `bash deploy/hub/install.sh`

---

## Pas 5 — Fișiere statice (dacă SERVE_STATIC=0)

```bash
SITE_ROOT=/home/site-user/htdocs/security.domeniu.md
rsync -a "$INSTALL/frontend/dist/" "$SITE_ROOT/"
```

Cu `SERVE_STATIC=1` în `.env`, Node servește singur React — proxy tot traficul la 7654.

---

## Pas 6 — Nginx custom directives

**Sites → domeniu → Vhost → Custom Directives:**

```nginx
client_max_body_size 12m;

location /api/ {
    proxy_pass         http://127.0.0.1:7654;
    proxy_set_header   Host $host;
    proxy_set_header   X-Real-IP $remote_addr;
    proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header   X-Forwarded-Proto $scheme;
}

location /ws {
    proxy_pass          http://127.0.0.1:7654;
    proxy_http_version  1.1;
    proxy_set_header    Upgrade $http_upgrade;
    proxy_set_header    Connection "upgrade";
    proxy_set_header    Host $host;
    proxy_read_timeout  3600s;
}

location / {
    proxy_pass         http://127.0.0.1:7654;
    proxy_set_header   Host $host;
    proxy_set_header   X-Real-IP $remote_addr;
    proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header   X-Forwarded-Proto $scheme;
}
```

(Ultimul bloc `location /` e necesar dacă `SERVE_STATIC=1` și totul merge prin Node.)

---

## Pas 7 — Verificare

```bash
curl -s http://127.0.0.1:7654/api/status
curl -s https://security.domeniu.md/api/status
```

Login: **admin** / **admin** → schimbă parola în Profil.

---

## Agenți (servere Linux, NU CloudPanel)

```bash
export HUB_URL='https://security.domeniu.md'
export AGENT_KEY='cheia-din-panou'
bash deploy/agent/install.sh
```

---

## Probleme frecvente

| Simptom | Soluție |
|---------|---------|
| 502 | `pm2 status` sau `systemctl status neohost-security` |
| DB error | `DATABASE_URL` corect, user are drepturi pe `neohost` |
| WS nu merge | Bloc `location /ws` cu Upgrade |
| Node lipsă | Instalează Node 18+ (nodesource / nvm) |
