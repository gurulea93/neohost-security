"""Acces panou: whitelist IP, setări hub, autentificare Telegram WebApp."""

import hashlib
import hmac
import ipaddress
import os
import secrets
from datetime import timedelta
from urllib.parse import parse_qsl

from models import HubSetting, IpWhitelist, TelegramLinkCode, TelegramUser, TelegramWebSession, utcnow

ENV_TELEGRAM_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
ENV_TELEGRAM_WEBAPP = os.environ.get("TELEGRAM_WEBAPP_URL", "").rstrip("/")


def get_telegram_bot_token(db=None):
    if db is not None:
        stored = get_setting(db, "telegram_bot_token", "")
        if stored:
            return stored
    return ENV_TELEGRAM_TOKEN


def get_telegram_webapp_url(db=None):
    if db is not None:
        stored = get_setting(db, "telegram_webapp_url", "")
        if stored:
            return stored.rstrip("/")
    return ENV_TELEGRAM_WEBAPP


def mask_token(token):
    if not token:
        return ""
    if len(token) <= 8:
        return "••••"
    return f"••••{token[-6:]}"


def client_ip_from_request(request):
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP", "")
    if real_ip:
        return real_ip.strip()
    return request.remote_addr or ""


def _ip_matches(allowed, client):
    if not allowed or not client:
        return False
    try:
        if "/" in allowed:
            return ipaddress.ip_address(client) in ipaddress.ip_network(allowed, strict=False)
        return ipaddress.ip_address(client) == ipaddress.ip_address(allowed)
    except ValueError:
        return client == allowed


def is_local_ip(ip):
    return ip in ("127.0.0.1", "::1", "localhost")


def get_setting(db, key, default=""):
    row = db.query(HubSetting).filter_by(key=key).first()
    return row.value if row else default


def set_setting(db, key, value):
    row = db.query(HubSetting).filter_by(key=key).first()
    if not row:
        row = HubSetting(key=key)
        db.add(row)
    row.value = str(value)
    db.commit()


def is_whitelist_enabled(db):
    return get_setting(db, "ip_whitelist_enabled", "0") == "1"


def check_ip_whitelist(db, client_ip):
    if is_local_ip(client_ip):
        return True
    if not is_whitelist_enabled(db):
        return True
    entries = db.query(IpWhitelist).all()
    if not entries:
        return True
    return any(_ip_matches(e.ip, client_ip) for e in entries)


def generate_link_code(db, ttl_minutes=10):
    db.query(TelegramLinkCode).filter(TelegramLinkCode.expires_at < utcnow()).delete()
    db.commit()
    for _ in range(10):
        code = secrets.token_hex(3).upper()[:6]
        if not db.query(TelegramLinkCode).filter_by(code=code, used=False).first():
            break
    expires = utcnow() + timedelta(minutes=ttl_minutes)
    db.add(TelegramLinkCode(code=code, expires_at=expires))
    db.commit()
    return code, expires


def validate_telegram_init_data(init_data, bot_token):
    if not init_data or not bot_token:
        return None
    parsed = dict(parse_qsl(init_data, keep_blank_values=True))
    received_hash = parsed.pop("hash", None)
    if not received_hash:
        return None
    data_check = "\n".join(f"{k}={v}" for k, v in sorted(parsed.items()))
    secret = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    calculated = hmac.new(secret, data_check.encode(), hashlib.sha256).hexdigest()
    if calculated != received_hash:
        return None
    import json
    user_raw = parsed.get("user")
    if not user_raw:
        return None
    try:
        return json.loads(user_raw)
    except json.JSONDecodeError:
        return None


def create_telegram_web_session(db, telegram_id, hours=24):
    db.query(TelegramWebSession).filter(TelegramWebSession.expires_at < utcnow()).delete()
    token = secrets.token_urlsafe(32)
    expires = utcnow() + timedelta(hours=hours)
    db.add(TelegramWebSession(token=token, telegram_id=telegram_id, expires_at=expires))
    db.commit()
    return token, expires


def get_telegram_web_session(db, token):
    row = db.query(TelegramWebSession).filter_by(token=token).first()
    if not row or row.expires_at < utcnow():
        return None
    user = db.query(TelegramUser).filter_by(telegram_id=row.telegram_id, is_active=True).first()
    return user
