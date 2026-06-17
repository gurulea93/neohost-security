import { randomBytes } from "node:crypto";
import { exec, queryAll, queryOne } from "../db/index.js";

export const BUILTIN_TEMPLATES = [
  {
    kind: "fail2ban_jail",
    slug: "f2b-sshd",
    name: "SSH — brute force",
    critical: true,
    description: "Protecție esențială pentru autentificări SSH eșuate.",
    instructions: "Zone critică: acces server.\n\nÎnainte de aplicare:\n• Verificați că SSH este activ: systemctl status sshd\n• Logul trebuie să existe: /var/log/auth.log (Debian/Ubuntu) sau /var/log/secure (CentOS)\n• Dacă folosiți alt port SSH, editați șablonul personalizat cu portul corect\n\nDupă aplicare: jailul sshd apare în listă. Test: fail2ban-client status sshd",
    payload: { jail_name: "sshd", enabled: "true", filter: "sshd", port: "ssh", logpath: "/var/log/auth.log", maxretry: 5, bantime: "1h", findtime: "10m" }
  },
  {
    kind: "fail2ban_jail", slug: "f2b-nginx-http-auth", name: "Nginx — autentificare HTTP", critical: true,
    description: "Blochează încercări repetate pe zone protejate cu parolă (staging, admin).",
    instructions: "Zone critică: panouri web protejate cu htpasswd.\n\nÎnainte:\n• Nginx trebuie să logheze în /var/log/nginx/error.log\n• Aveți zone cu auth_basic configurate\n\nDacă nu folosiți Nginx, nu aplicați acest șablon.",
    payload: { jail_name: "nginx-http-auth", enabled: "true", filter: "nginx-http-auth", port: "http,https", logpath: "/var/log/nginx/error.log", maxretry: 5, bantime: "1h", findtime: "10m" }
  },
  {
    kind: "fail2ban_jail", slug: "f2b-nginx-botsearch", name: "Nginx — scanări bot", critical: false,
    description: "Detectează scanări automate după fișiere vulnerabile (wp-admin, .env, etc.).",
    instructions: "Recomandat pentru servere web expuse public.\n\nLog: /var/log/nginx/access.log sau error.log în funcție de config.\nAjustați logpath dacă folosiți altă locație.",
    payload: { jail_name: "nginx-botsearch", enabled: "true", filter: "nginx-botsearch", port: "http,https", logpath: "/var/log/nginx/access.log", maxretry: 2, bantime: "24h", findtime: "10m" }
  },
  {
    kind: "fail2ban_jail", slug: "f2b-postfix-sasl", name: "Postfix — autentificare mail", critical: true,
    description: "Protecție împotriva atacurilor pe SMTP AUTH (spam relay).",
    instructions: "Zone critică: server mail.\n\nNecesită Postfix + SASL activ.\nLog tipic: /var/log/mail.log\nPe CentOS poate fi /var/log/maillog — creați șablon personalizat dacă e cazul.",
    payload: { jail_name: "postfix-sasl", enabled: "true", filter: "postfix-sasl", port: "smtp,submission,submissions,imap,imaps,pop3,pop3s", logpath: "/var/log/mail.log", maxretry: 3, bantime: "1h", findtime: "10m" }
  },
  {
    kind: "fail2ban_jail", slug: "f2b-recidive", name: "Recidive — reincidență", critical: true,
    description: "Ban lung pentru IP-uri care au fost deja blocate în alte jailuri.",
    instructions: "Aplicați DUPĂ ce aveți cel puțin sshd activ.\n\nNecesită jailul recidive și filter preinstalat în Fail2Ban.\nBanul default este 1 săptămână pentru recidivi.",
    payload: { jail_name: "recidive", enabled: "true", filter: "recidive", logpath: "/var/log/fail2ban.log", bantime: "1w", findtime: "1d", maxretry: 3 }
  },
  {
    kind: "fail2ban_jail", slug: "f2b-dovecot", name: "Dovecot — IMAP/POP3", critical: false,
    description: "Protecție autentificări eșuate pe Dovecot.",
    instructions: "Pentru servere mail cu Dovecot. Log: /var/log/mail.log",
    payload: { jail_name: "dovecot", enabled: "true", filter: "dovecot", port: "pop3,pop3s,imap,imaps", logpath: "/var/log/mail.log", maxretry: 5, bantime: "1h", findtime: "10m" }
  },
  {
    kind: "csf_preset", slug: "csf-hardening-base", name: "CSF — hardening de bază", critical: true,
    description: "Dezactivează modul test, activează protecții SSH și SYN flood.",
    instructions: "Zone critică: întreg serverul.\n\nCe face:\n• TESTING = OFF (blocări reale)\n• LF_SSHD, SYNFLOOD, CONNLIMIT activate\n• Porturi inbound: 22, 80, 443\n\nVerificați că nu veți fi blocați: adăugați IP-ul dvs. în csf.allow înainte!",
    payload: { toggles: { TESTING: false, LF_SSHD: true, SYNFLOOD: true, CONNLIMIT: true, PORTFLOOD: true }, ports: { TCP_IN: ["22", "80", "443"] }, enable_firewall: true, restart: true }
  },
  {
    kind: "csf_preset", slug: "csf-web-mail", name: "CSF — web + mail", critical: false,
    description: "Preset pentru server web cu servicii mail standard.",
    instructions: "Deschide porturi: 22, 25, 80, 443, 465, 587, 993, 995.\nActivează LF_SSHD, LF_SMTPAUTH, LF_POP3D, LF_IMAPD.\nAdaptați lista de porturi dacă nu folosiți toate serviciile.",
    payload: { toggles: { TESTING: false, LF_SSHD: true, LF_SMTPAUTH: true, LF_POP3D: true, LF_IMAPD: true, LF_HTACCESS: true }, ports: { TCP_IN: ["22", "25", "80", "443", "465", "587", "993", "995"] }, enable_firewall: true, restart: true }
  },
  {
    kind: "csf_preset", slug: "csf-ssh-only", name: "CSF — doar SSH administrare", critical: false,
    description: "Minimal: doar SSH inbound, restul închis.",
    instructions: "Pentru servere fără servicii web publice.\nDoar port 22 TCP inbound. Asigurați-vă că aveți acces SSH!",
    payload: { toggles: { TESTING: false, LF_SSHD: true }, ports: { TCP_IN: ["22"] }, enable_firewall: true, restart: true }
  },
  {
    kind: "nftables_preset", slug: "nft-hardening-base", name: "nftables — hardening de bază", critical: true,
    description: "Policy drop pe input, porturi 22/80/443, seturi allow/deny gestionate.",
    instructions: "Zone critică: firewall la nivel kernel.\n\nCe face:\n• Creează tabelul neohost (inet) cu lanțuri input/forward/output\n• Policy input = drop, cu excepții pentru conexiuni stabilite și lo\n• Deschide porturile 22, 80, 443\n• Seturi neohost_allow / neohost_deny pentru IP-uri\n\nAsigurați-vă că IP-ul dvs. este în allow înainte de aplicare!",
    payload: { chain_policies: { input: "drop", forward: "drop", output: "accept" }, open_ports: ["22", "80", "443"], enable: true, reload: true }
  },
  {
    kind: "nftables_preset", slug: "nft-ssh-only", name: "nftables — doar SSH", critical: false,
    description: "Minimal: doar port 22 deschis, policy drop pe input.",
    instructions: "Pentru servere fără servicii web publice.\nDoar port 22 TCP inbound. Verificați accesul SSH înainte!",
    payload: { chain_policies: { input: "drop", forward: "drop", output: "accept" }, open_ports: ["22"], enable: true, reload: true }
  },
  {
    kind: "nftables_preset", slug: "nft-web-stack", name: "nftables — web stack", critical: false,
    description: "SSH + HTTP/HTTPS + policy drop pe input.",
    instructions: "Deschide 22, 80, 443. Policy input drop cu excepții.",
    payload: { chain_policies: { input: "drop" }, open_ports: ["22", "80", "443"], enable: true, reload: true }
  }
];

export async function ensureBuiltinTemplates() {
  for (const tpl of BUILTIN_TEMPLATES) {
    const row = await queryOne("SELECT id FROM security_templates WHERE slug = ?", [tpl.slug]);
    const payload = JSON.stringify(tpl.payload || {});
    if (!row) {
      await exec(
        "INSERT INTO security_templates (kind, slug, name, description, instructions, critical, payload, is_builtin, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [tpl.kind, tpl.slug, tpl.name, tpl.description || "", tpl.instructions || "", tpl.critical ? 1 : 0, payload, 1, new Date().toISOString()]
      );
    } else {
      await exec("UPDATE security_templates SET name = ?, description = ?, instructions = ?, critical = ?, payload = ? WHERE slug = ?", [
        tpl.name, tpl.description || "", tpl.instructions || "", tpl.critical ? 1 : 0, payload, tpl.slug
      ]);
    }
  }
}

export function templateToDict(row) {
  return {
    id: row.id,
    kind: row.kind,
    slug: row.slug,
    name: row.name,
    description: row.description || "",
    instructions: row.instructions || "",
    critical: !!row.critical,
    payload: JSON.parse(row.payload || "{}"),
    is_builtin: !!row.is_builtin,
    created_at: row.created_at || null
  };
}

export function newUserSlug() {
  return `user-${randomBytes(4).toString("hex")}`;
}
