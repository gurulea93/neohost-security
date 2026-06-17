"""Notificări Telegram proactive — bannuri, amenințare, server offline."""

import json
import time
from datetime import timedelta

from models import TelegramUser, utcnow
from security import get_setting, set_setting

_last_sent = {}
_threat_cache = {}

DEFAULTS = {
    "notify_bans_enabled": True,
    "notify_threat_enabled": True,
    "notify_offline_enabled": True,
    "notify_min_interval_sec": 60,
}


def _bool_setting(db, key, default):
    raw = get_setting(db, key, "1" if default else "0")
    return raw in ("1", "true", "True", "yes")


def get_notification_settings(db):
    interval = get_setting(db, "notify_min_interval_sec", str(DEFAULTS["notify_min_interval_sec"]))
    try:
        interval = max(15, min(3600, int(interval)))
    except ValueError:
        interval = DEFAULTS["notify_min_interval_sec"]
    return {
        "notify_bans_enabled": _bool_setting(db, "notify_bans_enabled", DEFAULTS["notify_bans_enabled"]),
        "notify_threat_enabled": _bool_setting(db, "notify_threat_enabled", DEFAULTS["notify_threat_enabled"]),
        "notify_offline_enabled": _bool_setting(db, "notify_offline_enabled", DEFAULTS["notify_offline_enabled"]),
        "notify_min_interval_sec": interval,
    }


def update_notification_settings(db, data):
    out = get_notification_settings(db)
    if "notify_bans_enabled" in data:
        set_setting(db, "notify_bans_enabled", "1" if data["notify_bans_enabled"] else "0")
        out["notify_bans_enabled"] = bool(data["notify_bans_enabled"])
    if "notify_threat_enabled" in data:
        set_setting(db, "notify_threat_enabled", "1" if data["notify_threat_enabled"] else "0")
        out["notify_threat_enabled"] = bool(data["notify_threat_enabled"])
    if "notify_offline_enabled" in data:
        set_setting(db, "notify_offline_enabled", "1" if data["notify_offline_enabled"] else "0")
        out["notify_offline_enabled"] = bool(data["notify_offline_enabled"])
    if "notify_min_interval_sec" in data:
        try:
            sec = max(15, min(3600, int(data["notify_min_interval_sec"])))
        except (TypeError, ValueError):
            sec = DEFAULTS["notify_min_interval_sec"]
        set_setting(db, "notify_min_interval_sec", str(sec))
        out["notify_min_interval_sec"] = sec
    return out


def _rate_ok(key, min_sec):
    now = time.time()
    last = _last_sent.get(key, 0)
    if now - last < min_sec:
        return False
    _last_sent[key] = now
    return True


def _broadcast_telegram(db, text, rate_key, min_sec):
    if not _rate_ok(rate_key, min_sec):
        return 0
    from telegram_bot import send_telegram_text
    users = db.query(TelegramUser).filter_by(is_active=True).all()
    sent = 0
    for u in users:
        if send_telegram_text(u.telegram_id, text, db):
            sent += 1
    return sent


def notify_new_bans(db, server, bans):
    if not bans:
        return
    settings = get_notification_settings(db)
    if not settings["notify_bans_enabled"]:
        return
    min_sec = settings["notify_min_interval_sec"]
    lines = []
    for b in bans[:8]:
        cc = b.get("country_code") or ""
        country = b.get("country") or ""
        loc = f" ({cc})" if cc else (f" ({country})" if country else "")
        lines.append(f"• <code>{b.get('ip', '?')}</code> — {b.get('jail', '?')}{loc}")
    extra = f"\n… și încă {len(bans) - 8} bannuri" if len(bans) > 8 else ""
    text = (
        f"<b>🛡 NeoHost — Bannuri noi</b>\n"
        f"Server: <b>{server.name}</b>\n\n"
        + "\n".join(lines)
        + extra
    )
    _broadcast_telegram(db, text, f"ban:{server.id}", min_sec)


def notify_threat_change(db, server, threat):
    settings = get_notification_settings(db)
    if not settings["notify_threat_enabled"]:
        return
    level = (threat or {}).get("level", "low")
    score = (threat or {}).get("score", 0)
    prev = _threat_cache.get(server.id)
    _threat_cache[server.id] = level
    if prev == level:
        return
    if level not in ("high", "critical") and prev not in (None, "low", "medium"):
        return
    if level in ("low", "medium") and prev in ("high", "critical"):
        return
    labels = {"low": "Scăzut", "medium": "Mediu", "high": "Ridicat", "critical": "Critic"}
    text = (
        f"<b>⚠️ NeoHost — Nivel amenințare</b>\n"
        f"Server: <b>{server.name}</b>\n"
        f"Nivel: <b>{labels.get(level, level)}</b> (scor {score})\n"
        f"{'Acțiune recomandată: verificați jurnalele și jailurile active.' if level in ('high', 'critical') else ''}"
    )
    _broadcast_telegram(db, text, f"threat:{server.id}:{level}", settings["notify_min_interval_sec"])


def notify_server_offline(db, server):
    settings = get_notification_settings(db)
    if not settings["notify_offline_enabled"]:
        return
    if not server.last_seen:
        return
    offline_sec = (utcnow() - server.last_seen).total_seconds()
    if offline_sec < 120:
        return
    text = (
        f"<b>📡 NeoHost — Server offline</b>\n"
        f"Server: <b>{server.name}</b>\n"
        f"Ultima sincronizare: {server.last_seen.strftime('%Y-%m-%d %H:%M:%S')} UTC"
    )
    _broadcast_telegram(db, text, f"offline:{server.id}", max(300, settings["notify_min_interval_sec"]))


def check_offline_servers(db):
    from models import Server
    servers = db.query(Server).filter_by(is_active=True).all()
    for s in servers:
        if s.last_seen and (utcnow() - s.last_seen).total_seconds() > 120:
            notify_server_offline(db, s)
