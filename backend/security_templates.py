"""Șabloane securitate Fail2Ban / CSF — built-in + utilizator."""

import json
import secrets

from models import SecurityTemplate, utcnow

BUILTIN_TEMPLATES = [
    {
        "kind": "fail2ban_jail",
        "slug": "f2b-sshd",
        "name": "SSH — brute force",
        "critical": True,
        "description": "Protecție esențială pentru autentificări SSH eșuate.",
        "instructions": (
            "Zone critică: acces server.\n\n"
            "Înainte de aplicare:\n"
            "• Verificați că SSH este activ: systemctl status sshd\n"
            "• Logul trebuie să existe: /var/log/auth.log (Debian/Ubuntu) sau /var/log/secure (CentOS)\n"
            "• Dacă folosiți alt port SSH, editați șablonul personalizat cu portul corect\n\n"
            "După aplicare: jailul sshd apare în listă. Test: fail2ban-client status sshd"
        ),
        "payload": {
            "jail_name": "sshd",
            "enabled": "true",
            "filter": "sshd",
            "port": "ssh",
            "logpath": "/var/log/auth.log",
            "maxretry": 5,
            "bantime": "1h",
            "findtime": "10m",
        },
    },
    {
        "kind": "fail2ban_jail",
        "slug": "f2b-nginx-http-auth",
        "name": "Nginx — autentificare HTTP",
        "critical": True,
        "description": "Blochează încercări repetate pe zone protejate cu parolă (staging, admin).",
        "instructions": (
            "Zone critică: panouri web protejate cu htpasswd.\n\n"
            "Înainte:\n"
            "• Nginx trebuie să logheze în /var/log/nginx/error.log\n"
            "• Aveți zone cu auth_basic configurate\n\n"
            "Dacă nu folosiți Nginx, nu aplicați acest șablon."
        ),
        "payload": {
            "jail_name": "nginx-http-auth",
            "enabled": "true",
            "filter": "nginx-http-auth",
            "port": "http,https",
            "logpath": "/var/log/nginx/error.log",
            "maxretry": 5,
            "bantime": "1h",
            "findtime": "10m",
        },
    },
    {
        "kind": "fail2ban_jail",
        "slug": "f2b-nginx-botsearch",
        "name": "Nginx — scanări bot",
        "critical": False,
        "description": "Detectează scanări automate după fișiere vulnerabile (wp-admin, .env, etc.).",
        "instructions": (
            "Recomandat pentru servere web expuse public.\n\n"
            "Log: /var/log/nginx/access.log sau error.log în funcție de config.\n"
            "Ajustați logpath dacă folosiți altă locație."
        ),
        "payload": {
            "jail_name": "nginx-botsearch",
            "enabled": "true",
            "filter": "nginx-botsearch",
            "port": "http,https",
            "logpath": "/var/log/nginx/access.log",
            "maxretry": 2,
            "bantime": "24h",
            "findtime": "10m",
        },
    },
    {
        "kind": "fail2ban_jail",
        "slug": "f2b-postfix-sasl",
        "name": "Postfix — autentificare mail",
        "critical": True,
        "description": "Protecție împotriva atacurilor pe SMTP AUTH (spam relay).",
        "instructions": (
            "Zone critică: server mail.\n\n"
            "Necesită Postfix + SASL activ.\n"
            "Log tipic: /var/log/mail.log\n"
            "Pe CentOS poate fi /var/log/maillog — creați șablon personalizat dacă e cazul."
        ),
        "payload": {
            "jail_name": "postfix-sasl",
            "enabled": "true",
            "filter": "postfix-sasl",
            "port": "smtp,submission,submissions,imap,imaps,pop3,pop3s",
            "logpath": "/var/log/mail.log",
            "maxretry": 3,
            "bantime": "1h",
            "findtime": "10m",
        },
    },
    {
        "kind": "fail2ban_jail",
        "slug": "f2b-recidive",
        "name": "Recidive — reincidență",
        "critical": True,
        "description": "Ban lung pentru IP-uri care au fost deja blocate în alte jailuri.",
        "instructions": (
            "Aplicați DUPĂ ce aveți cel puțin sshd activ.\n\n"
            "Necesită jailul recidive și filter preinstalat în Fail2Ban.\n"
            "Banul default este 1 săptămână pentru recidivi."
        ),
        "payload": {
            "jail_name": "recidive",
            "enabled": "true",
            "filter": "recidive",
            "logpath": "/var/log/fail2ban.log",
            "bantime": "1w",
            "findtime": "1d",
            "maxretry": 3,
        },
    },
    {
        "kind": "fail2ban_jail",
        "slug": "f2b-dovecot",
        "name": "Dovecot — IMAP/POP3",
        "critical": False,
        "description": "Protecție autentificări eșuate pe Dovecot.",
        "instructions": "Pentru servere mail cu Dovecot. Log: /var/log/mail.log",
        "payload": {
            "jail_name": "dovecot",
            "enabled": "true",
            "filter": "dovecot",
            "port": "pop3,pop3s,imap,imaps",
            "logpath": "/var/log/mail.log",
            "maxretry": 5,
            "bantime": "1h",
            "findtime": "10m",
        },
    },
    {
        "kind": "csf_preset",
        "slug": "csf-hardening-base",
        "name": "CSF — hardening de bază",
        "critical": True,
        "description": "Dezactivează modul test, activează protecții SSH și SYN flood.",
        "instructions": (
            "Zone critică: întreg serverul.\n\n"
            "Ce face:\n"
            "• TESTING = OFF (blocări reale)\n"
            "• LF_SSHD, SYNFLOOD, CONNLIMIT activate\n"
            "• Porturi inbound: 22, 80, 443\n\n"
            "Verificați că nu veți fi blocați: adăugați IP-ul dvs. în csf.allow înainte!"
        ),
        "payload": {
            "toggles": {
                "TESTING": False,
                "LF_SSHD": True,
                "SYNFLOOD": True,
                "CONNLIMIT": True,
                "PORTFLOOD": True,
            },
            "ports": {"TCP_IN": ["22", "80", "443"]},
            "enable_firewall": True,
            "restart": True,
        },
    },
    {
        "kind": "csf_preset",
        "slug": "csf-web-mail",
        "name": "CSF — web + mail",
        "critical": False,
        "description": "Preset pentru server web cu servicii mail standard.",
        "instructions": (
            "Deschide porturi: 22, 25, 80, 443, 465, 587, 993, 995.\n"
            "Activează LF_SSHD, LF_SMTPAUTH, LF_POP3D, LF_IMAPD.\n"
            "Adaptați lista de porturi dacă nu folosiți toate serviciile."
        ),
        "payload": {
            "toggles": {
                "TESTING": False,
                "LF_SSHD": True,
                "LF_SMTPAUTH": True,
                "LF_POP3D": True,
                "LF_IMAPD": True,
                "LF_HTACCESS": True,
            },
            "ports": {
                "TCP_IN": ["22", "25", "80", "443", "465", "587", "993", "995"],
            },
            "enable_firewall": True,
            "restart": True,
        },
    },
    {
        "kind": "csf_preset",
        "slug": "csf-ssh-only",
        "name": "CSF — doar SSH administrare",
        "critical": False,
        "description": "Minimal: doar SSH inbound, restul închis.",
        "instructions": (
            "Pentru servere fără servicii web publice.\n"
            "Doar port 22 TCP inbound. Asigurați-vă că aveți acces SSH!"
        ),
        "payload": {
            "toggles": {"TESTING": False, "LF_SSHD": True},
            "ports": {"TCP_IN": ["22"]},
            "enable_firewall": True,
            "restart": True,
        },
    },
    {
        "kind": "nftables_preset",
        "slug": "nft-hardening-base",
        "name": "nftables — hardening de bază",
        "critical": True,
        "description": "Policy drop pe input, porturi 22/80/443, seturi allow/deny gestionate.",
        "instructions": (
            "Zone critică: firewall la nivel kernel.\n\n"
            "Ce face:\n"
            "• Creează tabelul neohost (inet) cu lanțuri input/forward/output\n"
            "• Policy input = drop, cu excepții pentru conexiuni stabilite și lo\n"
            "• Deschide porturile 22, 80, 443\n"
            "• Seturi neohost_allow / neohost_deny pentru IP-uri\n\n"
            "Asigurați-vă că IP-ul dvs. este în allow înainte de aplicare!"
        ),
        "payload": {
            "chain_policies": {"input": "drop", "forward": "drop", "output": "accept"},
            "open_ports": ["22", "80", "443"],
            "enable": True,
            "reload": True,
        },
    },
    {
        "kind": "nftables_preset",
        "slug": "nft-ssh-only",
        "name": "nftables — doar SSH",
        "critical": False,
        "description": "Minimal: doar port 22 deschis, policy drop pe input.",
        "instructions": (
            "Pentru servere fără servicii web publice.\n"
            "Doar port 22 TCP inbound. Verificați accesul SSH înainte!"
        ),
        "payload": {
            "chain_policies": {"input": "drop", "forward": "drop", "output": "accept"},
            "open_ports": ["22"],
            "enable": True,
            "reload": True,
        },
    },
    {
        "kind": "nftables_preset",
        "slug": "nft-web-stack",
        "name": "nftables — web stack",
        "critical": False,
        "description": "SSH + HTTP/HTTPS + policy drop pe input.",
        "instructions": "Deschide 22, 80, 443. Policy input drop cu excepții.",
        "payload": {
            "chain_policies": {"input": "drop"},
            "open_ports": ["22", "80", "443"],
            "enable": True,
            "reload": True,
        },
    },
]


def ensure_builtin_templates(db):
    for tpl in BUILTIN_TEMPLATES:
        row = db.query(SecurityTemplate).filter_by(slug=tpl["slug"]).first()
        payload = json.dumps(tpl["payload"])
        if not row:
            db.add(SecurityTemplate(
                kind=tpl["kind"],
                slug=tpl["slug"],
                name=tpl["name"],
                description=tpl.get("description", ""),
                instructions=tpl.get("instructions", ""),
                critical=bool(tpl.get("critical")),
                payload=payload,
                is_builtin=True,
            ))
        else:
            row.name = tpl["name"]
            row.description = tpl.get("description", "")
            row.instructions = tpl.get("instructions", "")
            row.critical = bool(tpl.get("critical"))
            row.payload = payload
    db.commit()


def template_to_dict(t):
    return {
        "id": t.id,
        "kind": t.kind,
        "slug": t.slug,
        "name": t.name,
        "description": t.description,
        "instructions": t.instructions,
        "critical": t.critical,
        "payload": json.loads(t.payload or "{}"),
        "is_builtin": t.is_builtin,
        "created_at": t.created_at.isoformat() if t.created_at else None,
    }


def new_user_slug():
    return f"user-{secrets.token_hex(4)}"
