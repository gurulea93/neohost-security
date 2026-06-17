"""Bot Telegram — butoane inline + Mini App NeoHost."""

import json
import threading
import time
import urllib.error
import urllib.request

from db import SessionLocal
from models import (
    Server, TelegramUser, TelegramLinkCode, JailSnapshot, ConnectionSnapshot,
    CsfSnapshot, NftablesSnapshot, BanRecord, utcnow,
)
from intelligence import compute_threat_level


def _tg_api(token, method, data=None):
    url = f"https://api.telegram.org/bot{token}/{method}"
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=35) as resp:
        return json.loads(resp.read())


def _send(token, chat_id, text, reply_markup=None):
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup
    try:
        _tg_api(token, "sendMessage", payload)
        return True
    except Exception:
        return False


def send_telegram_text(chat_id, text, db=None):
    from security import get_telegram_bot_token
    own_db = db is None
    if own_db:
        db = SessionLocal()
    try:
        bot_token = get_telegram_bot_token(db)
        if not bot_token:
            return False
        return _send(bot_token, chat_id, text)
    finally:
        if own_db:
            db.close()


def _answer_cb(token, cb_id, text=""):
    try:
        _tg_api(token, "answerCallbackQuery", {"callback_query_id": cb_id, "text": text[:200]})
    except Exception:
        pass


def _queue(db, server_id, action, payload):
    from models import AgentCommand
    cmd = AgentCommand(server_id=server_id, action=action, payload=json.dumps(payload))
    db.add(cmd)
    db.commit()


def _linked_user(db, telegram_id):
    return db.query(TelegramUser).filter_by(telegram_id=telegram_id, is_active=True).first()


def _servers(db):
    return db.query(Server).filter_by(is_active=True).order_by(Server.name).all()


def _server_by_id(db, sid):
    return db.query(Server).filter_by(id=sid, is_active=True).first()


def _threat_line(db, server_id):
    ban_times = [b.ts for b in
                 db.query(BanRecord.ts).filter_by(server_id=server_id)
                 .order_by(BanRecord.ts.desc()).limit(5000)]
    t = compute_threat_level(ban_times)
    return f"<b>{t['level']}</b> — {t['bans_hr']} bans/oră\n{t['recommendation']}"


def _main_keyboard(webapp_url):
    rows = [
        [
            {"text": "Servere", "callback_data": "menu:servers"},
            {"text": "Status", "callback_data": "menu:status"},
        ],
        [
            {"text": "Jailuri F2B", "callback_data": "menu:jails"},
            {"text": "CSF", "callback_data": "menu:csf"},
            {"text": "nftables", "callback_data": "menu:nft"},
        ],
        [
            {"text": "Conexiuni", "callback_data": "menu:connections"},
            {"text": "Ajutor", "callback_data": "menu:help"},
        ],
    ]
    if webapp_url:
        rows.insert(0, [{"text": "Panou Web App", "web_app": {"url": webapp_url}}])
    rows.append([{"text": "Meniu principal", "callback_data": "menu:home"}])
    return {"inline_keyboard": rows}


def _server_pick_keyboard(db, prefix):
    buttons = []
    for s in _servers(db):
        on = "on" if s.last_seen and (utcnow() - s.last_seen).total_seconds() < 90 else "off"
        label = f"{'F2B ' if s.cap_fail2ban else ''}{'CSF ' if s.cap_csf else ''}{'NFT ' if s.cap_nftables else ''}{s.name} ({on})"
        buttons.append([{"text": label.strip(), "callback_data": f"{prefix}:{s.id}"}])
    buttons.append([{"text": "Meniu", "callback_data": "menu:home"}])
    return {"inline_keyboard": buttons}


def _handle_link(db, token, chat_id, user, code, webapp_url):
    code = (code or "").strip().upper()
    if not code:
        _send(token, chat_id, "Trimiteți: <code>/link COD</code>", _main_keyboard(webapp_url))
        return
    row = db.query(TelegramLinkCode).filter_by(code=code, used=False).first()
    if not row or row.expires_at < utcnow():
        _send(token, chat_id, "Cod invalid sau expirat.")
        return
    existing = db.query(TelegramUser).filter_by(telegram_id=user["id"]).first()
    if existing:
        existing.username = user.get("username") or ""
        existing.first_name = user.get("first_name") or ""
        existing.is_active = True
        existing.linked_at = utcnow()
    else:
        db.add(TelegramUser(
            telegram_id=user["id"],
            username=user.get("username") or "",
            first_name=user.get("first_name") or "",
        ))
    row.used = True
    db.commit()
    _send(token, chat_id, "Cont conectat! Folosiți butoanele de mai jos:", _main_keyboard(webapp_url))


def _show_servers(db, token, chat_id, webapp_url):
    lines = ["<b>Servere</b>"]
    for s in _servers(db):
        mods = []
        if s.mod_fail2ban and s.cap_fail2ban:
            mods.append("F2B")
        if s.mod_csf and s.cap_csf:
            mods.append("CSF")
        if s.mod_nftables and s.cap_nftables:
            mods.append("NFT")
        on = "online" if s.last_seen and (utcnow() - s.last_seen).total_seconds() < 90 else "offline"
        lines.append(f"#{s.id} <b>{s.name}</b> [{', '.join(mods) or '—'}] ({on})")
    _send(token, chat_id, "\n".join(lines) or "Niciun server.", _main_keyboard(webapp_url))


def _show_status(db, token, chat_id, sid, webapp_url):
    srv = _server_by_id(db, sid)
    if not srv:
        _send(token, chat_id, "Server negăsit.", _main_keyboard(webapp_url))
        return
    _send(token, chat_id, f"<b>{srv.name}</b>\n{_threat_line(db, srv.id)}", _main_keyboard(webapp_url))


def _show_jails(db, token, chat_id, sid, webapp_url):
    srv = _server_by_id(db, sid)
    if not srv:
        _send(token, chat_id, "Server negăsit.", _main_keyboard(webapp_url))
        return
    if not srv.mod_fail2ban or not srv.cap_fail2ban:
        _send(token, chat_id, f"Fail2Ban nu e activ pe {srv.name}.", _main_keyboard(webapp_url))
        return
    snap = db.query(JailSnapshot).filter_by(server_id=srv.id).first()
    raw = json.loads(snap.data) if snap and snap.data else []
    if isinstance(raw, dict):
        jails = raw.get("jails", [])
    else:
        jails = raw
    if not jails:
        _send(token, chat_id, f"Niciun jail pe {srv.name}.", _main_keyboard(webapp_url))
        return
    lines = [f"<b>Jailuri — {srv.name}</b>"]
    kb = []
    for j in jails[:8]:
        lines.append(f"• {j['name']}: {j.get('currently_banned', 0)} banate")
        kb.append([{"text": f"Reload {j['name']}", "callback_data": f"f2b:reload:{srv.id}:{j['name']}"}])
    kb.append([{"text": "Meniu", "callback_data": "menu:home"}])
    _send(token, chat_id, "\n".join(lines), {"inline_keyboard": kb})


def _show_csf(db, token, chat_id, sid, webapp_url):
    srv = _server_by_id(db, sid)
    if not srv:
        _send(token, chat_id, "Server negăsit.", _main_keyboard(webapp_url))
        return
    if not srv.mod_csf or not srv.cap_csf:
        _send(token, chat_id, f"CSF nu e activ pe {srv.name}.", _main_keyboard(webapp_url))
        return
    snap = db.query(CsfSnapshot).filter_by(server_id=srv.id).first()
    data = json.loads(snap.data) if snap and snap.data else {}
    testing = "DA" if data.get("testing_mode") else "NU"
    _send(token, chat_id, (
        f"<b>CSF — {srv.name}</b>\n"
        f"Firewall: {'activ' if data.get('enabled') else 'inactiv'}\n"
        f"Mod test: {testing}\n"
        f"Deny: {data.get('deny_count', 0)} | Allow: {data.get('allow_count', 0)}"
    ), {
        "inline_keyboard": [
            [
                {"text": "Restart CSF", "callback_data": f"csf:restart:{sid}"},
                {"text": "Toggle test", "callback_data": f"csf:toggle:TESTING:{sid}"},
            ],
            [{"text": "Meniu", "callback_data": "menu:home"}],
        ],
    })


def _show_nftables(db, token, chat_id, sid, webapp_url):
    srv = _server_by_id(db, sid)
    if not srv:
        _send(token, chat_id, "Server negăsit.", _main_keyboard(webapp_url))
        return
    if not srv.mod_nftables or not srv.cap_nftables:
        _send(token, chat_id, f"nftables nu e activ pe {srv.name}.", _main_keyboard(webapp_url))
        return
    snap = db.query(NftablesSnapshot).filter_by(server_id=srv.id).first()
    data = json.loads(snap.data) if snap and snap.data else {}
    stats = data.get("stats") or {}
    _send(token, chat_id, (
        f"<b>nftables — {srv.name}</b>\n"
        f"Firewall: {'activ' if data.get('running') else 'inactiv'}\n"
        f"Deny: {data.get('deny_count', 0)} | Allow: {data.get('allow_count', 0)}\n"
        f"Reguli: {stats.get('rule_count', 0)} | Tabele: {stats.get('table_count', 0)}\n"
        f"Pachete: {stats.get('total_packets', 0):,}"
    ), {
        "inline_keyboard": [
            [
                {"text": "Reload", "callback_data": f"nft:reload:{sid}"},
                {"text": "On/Off FW", "callback_data": f"nft:firewall:{sid}"},
            ],
            [{"text": "Meniu", "callback_data": "menu:home"}],
        ],
    })


def _show_connections(db, token, chat_id, sid, webapp_url):
    srv = _server_by_id(db, sid)
    if not srv:
        _send(token, chat_id, "Server negăsit.", _main_keyboard(webapp_url))
        return
    snap = db.query(ConnectionSnapshot).filter_by(server_id=srv.id).first()
    conns = json.loads(snap.data) if snap and snap.data else []
    if not conns:
        _send(token, chat_id, "Nicio conexiune activă.", _main_keyboard(webapp_url))
        return
    lines = [f"<b>Conexiuni — {srv.name}</b>"]
    kb = []
    for c in conns[:6]:
        ip = c.get("ip")
        lines.append(f"• {ip}:{c.get('port')}")
        row = []
        if srv.mod_fail2ban and srv.cap_fail2ban:
            row.append({"text": f"Ban F2B {ip}", "callback_data": f"f2b:ban:{sid}:{ip}"})
        if srv.mod_nftables and srv.cap_nftables:
            row.append({"text": f"Deny NFT {ip}", "callback_data": f"nft:deny:{sid}:{ip}"})
        if srv.mod_csf and srv.cap_csf:
            row.append({"text": f"Deny CSF {ip}", "callback_data": f"csf:deny:{sid}:{ip}"})
        if row:
            kb.append(row)
    kb.append([{"text": "Meniu", "callback_data": "menu:home"}])
    _send(token, chat_id, "\n".join(lines), {"inline_keyboard": kb})


def _process_callback(db, token, cb, webapp_url):
    data = cb.get("data", "")
    chat_id = cb["message"]["chat"]["id"]
    user = cb.get("from", {})
    cb_id = cb["id"]
    linked = _linked_user(db, user.get("id"))
    if not linked and not data.startswith("menu:"):
        _answer_cb(token, cb_id, "Conectați contul cu /link")
        return

    parts = data.split(":")
    action = parts[0]

    if action == "menu":
        sub = parts[1] if len(parts) > 1 else "home"
        if sub == "home":
            _answer_cb(token, cb_id)
            _send(token, chat_id, "<b>NeoHost Security</b>\nAlegeți o acțiune:", _main_keyboard(webapp_url))
        elif sub == "servers":
            _answer_cb(token, cb_id)
            _show_servers(db, token, chat_id, webapp_url)
        elif sub == "status":
            _answer_cb(token, cb_id)
            _send(token, chat_id, "Alegeți serverul:", _server_pick_keyboard(db, "pick:status"))
        elif sub == "jails":
            _answer_cb(token, cb_id)
            _send(token, chat_id, "Alegeți serverul (Fail2Ban):", _server_pick_keyboard(db, "pick:jails"))
        elif sub == "csf":
            _answer_cb(token, cb_id)
            _send(token, chat_id, "Alegeți serverul (CSF):", _server_pick_keyboard(db, "pick:csf"))
        elif sub == "nft":
            _answer_cb(token, cb_id)
            _send(token, chat_id, "Alegeți serverul (nftables):", _server_pick_keyboard(db, "pick:nft"))
        elif sub == "connections":
            _answer_cb(token, cb_id)
            _send(token, chat_id, "Alegeți serverul:", _server_pick_keyboard(db, "pick:connections"))
        elif sub == "help":
            _answer_cb(token, cb_id)
            _send(token, chat_id, (
                "<b>Comenzi text</b>\n"
                "/ban IP [jail] [id]\n/unban IP [jail] [id]\n"
                "/csfdeny IP [id]\n/csfallow IP [id]\n"
                "/nftdeny IP [id]\n/nftallow IP [id]\n"
                "Sau folosiți butoanele și Mini App."
            ), _main_keyboard(webapp_url))
        return

    if action == "pick" and len(parts) >= 3:
        sub, sid = parts[1], int(parts[2])
        _answer_cb(token, cb_id)
        if sub == "status":
            _show_status(db, token, chat_id, sid, webapp_url)
        elif sub == "jails":
            _show_jails(db, token, chat_id, sid, webapp_url)
        elif sub == "csf":
            _show_csf(db, token, chat_id, sid, webapp_url)
        elif sub == "nft":
            _show_nftables(db, token, chat_id, sid, webapp_url)
        elif sub == "connections":
            _show_connections(db, token, chat_id, sid, webapp_url)
        return

    if action == "f2b" and len(parts) >= 3:
        sub = parts[1]
        sid = int(parts[2])
        _answer_cb(token, cb_id, "Trimis")
        if sub == "ban" and len(parts) >= 4:
            _queue(db, sid, "ban", {"ip": parts[3], "jail": "sshd"})
        elif sub == "reload" and len(parts) >= 4:
            _queue(db, sid, "reload", {})
        return

    if action == "csf" and len(parts) >= 3:
        sub = parts[1]
        sid = int(parts[2])
        _answer_cb(token, cb_id, "Trimis")
        if sub == "restart":
            _queue(db, sid, "csf_restart", {})
        elif sub == "toggle" and len(parts) >= 4:
            key = parts[2]
            snap = db.query(CsfSnapshot).filter_by(server_id=sid).first()
            cur = json.loads(snap.data).get("toggles", {}).get(key, False) if snap and snap.data else False
            _queue(db, sid, "csf_toggle", {"key": key, "enabled": not cur})
        elif sub == "deny" and len(parts) >= 4:
            _queue(db, sid, "csf_deny", {"ip": parts[3]})
        return

    if action == "nft" and len(parts) >= 3:
        sub = parts[1]
        sid = int(parts[2])
        _answer_cb(token, cb_id, "Trimis")
        if sub == "reload":
            _queue(db, sid, "nft_reload", {})
        elif sub == "firewall":
            snap = db.query(NftablesSnapshot).filter_by(server_id=sid).first()
            running = json.loads(snap.data).get("running", False) if snap and snap.data else False
            act = "nft_disable" if running else "nft_enable"
            _queue(db, sid, act, {})
        elif sub == "deny" and len(parts) >= 4:
            _queue(db, sid, "nft_deny", {"ip": parts[3]})
        return


def _process_command(db, token, chat_id, user, text, webapp_url):
    parts = text.strip().split()
    cmd = parts[0].lower().split("@")[0]
    args = parts[1:]

    if cmd in ("/start", "/help", "/menu"):
        linked = _linked_user(db, user["id"])
        if linked:
            _send(token, chat_id, "<b>NeoHost Security</b>\nPanou unificat Fail2Ban + CSF + nftables:", _main_keyboard(webapp_url))
        else:
            _send(token, chat_id, "Bun venit! Conectați contul: <code>/link COD</code> (cod din Profil → Telegram)")
        return

    if cmd == "/link":
        _handle_link(db, token, chat_id, user, args[0] if args else "", webapp_url)
        return

    linked = _linked_user(db, user["id"])
    if not linked:
        _send(token, chat_id, "Cont neconectat. /link COD")
        return

    if cmd == "/unlink":
        linked.is_active = False
        db.commit()
        _send(token, chat_id, "Deconectat.")
        return

    if cmd == "/servers":
        _show_servers(db, token, chat_id, webapp_url)
        return

    if cmd == "/ban" and args:
        ip = args[0]
        jail = "sshd"
        sid = None
        for a in args[1:]:
            if a.isdigit():
                sid = int(a)
            else:
                jail = a
        srv = _server_by_id(db, sid) if sid else (_servers(db)[0] if _servers(db) else None)
        if srv and srv.mod_fail2ban:
            _queue(db, srv.id, "ban", {"ip": ip, "jail": jail})
            _send(token, chat_id, f"Ban trimis: {ip}", _main_keyboard(webapp_url))
        return

    if cmd == "/unban" and args:
        ip = args[0]
        jail = "sshd"
        sid = None
        for a in args[1:]:
            if a.isdigit():
                sid = int(a)
            else:
                jail = a
        srv = _server_by_id(db, sid) if sid else (_servers(db)[0] if _servers(db) else None)
        if srv and srv.mod_fail2ban:
            _queue(db, srv.id, "unban", {"ip": ip, "jail": jail})
            _send(token, chat_id, f"Unban trimis: {ip}", _main_keyboard(webapp_url))
        return

    if cmd in ("/csfdeny", "/csfallow") and args:
        ip = args[0]
        sid = int(args[1]) if len(args) > 1 and args[1].isdigit() else None
        srv = _server_by_id(db, sid) if sid else (_servers(db)[0] if _servers(db) else None)
        if srv and srv.mod_csf:
            act = "csf_deny" if cmd == "/csfdeny" else "csf_allow"
            _queue(db, srv.id, act, {"ip": ip})
            _send(token, chat_id, f"CSF {act} trimis.", _main_keyboard(webapp_url))
        return

    if cmd in ("/nftdeny", "/nftallow") and args:
        ip = args[0]
        sid = int(args[1]) if len(args) > 1 and args[1].isdigit() else None
        srv = _server_by_id(db, sid) if sid else (_servers(db)[0] if _servers(db) else None)
        if srv and srv.mod_nftables:
            act = "nft_deny" if cmd == "/nftdeny" else "nft_allow"
            _queue(db, srv.id, act, {"ip": ip})
            _send(token, chat_id, f"nftables {act} trimis.", _main_keyboard(webapp_url))
        return

    _send(token, chat_id, "Folosiți butoanele sau /menu", _main_keyboard(webapp_url))


_bot_stop_event = None
_bot_lock = __import__("threading").Lock()


def _poll_loop(token, webapp_url, stop_event):
    offset = 0
    while not stop_event.is_set():
        try:
            data = _tg_api(token, "getUpdates", {"offset": offset, "timeout": 20})
            for upd in data.get("result", []):
                offset = upd["update_id"] + 1
                if stop_event.is_set():
                    break
                if "callback_query" in upd:
                    db = SessionLocal()
                    try:
                        _process_callback(db, token, upd["callback_query"], webapp_url)
                    finally:
                        db.close()
                    continue
                msg = upd.get("message") or upd.get("edited_message")
                if not msg or "text" not in msg:
                    continue
                db = SessionLocal()
                try:
                    _process_command(db, token, msg["chat"]["id"], msg.get("from", {}), msg["text"], webapp_url)
                finally:
                    db.close()
        except urllib.error.HTTPError as e:
            if stop_event.is_set():
                break
            __import__("time").sleep(5 if e.code == 409 else 10)
        except Exception:
            if not stop_event.is_set():
                __import__("time").sleep(5)


def reload_telegram_bot(token, webapp_url=""):
    global _bot_stop_event
    with _bot_lock:
        if _bot_stop_event:
            _bot_stop_event.set()
        if not token:
            print("[Telegram] Bot oprit (fără token)")
            return None
        try:
            me = _tg_api(token, "getMe")
            username = me.get("result", {}).get("username", "?")
            print(f"[Telegram] Bot pornit: @{username}")
            if webapp_url:
                print(f"[Telegram] Web App: {webapp_url}")
        except Exception as e:
            print(f"[Telegram] Eroare token: {e}")
            return None
        stop_event = threading.Event()
        _bot_stop_event = stop_event
        t = threading.Thread(target=_poll_loop, args=(token, webapp_url, stop_event), daemon=True)
        t.start()
        return t


def start_telegram_bot(token, webapp_url=""):
    return reload_telegram_bot(token, webapp_url)
