"""Autentificare panou: utilizator, sesiune, 2FA (TOTP / Telegram)."""

import os
import random
import secrets
from datetime import timedelta

import pyotp
from werkzeug.security import check_password_hash, generate_password_hash

from models import PanelSession, PanelUser, TwoFaChallenge, utcnow

SESSION_HOURS = int(os.environ.get("PANEL_SESSION_HOURS", "24"))
CHALLENGE_MINUTES = 5
TOTP_ISSUER = os.environ.get("PANEL_TOTP_ISSUER", "NeoHost Security")


def hash_password(password):
    return generate_password_hash(str(password))


def verify_password(user, password):
    return check_password_hash(user.password_hash, str(password))


def ensure_default_admin(db):
    if db.query(PanelUser).first():
        return None
    username = os.environ.get("PANEL_ADMIN_USERNAME", "admin")
    password = os.environ.get("PANEL_ADMIN_PASSWORD", "admin")
    user = PanelUser(
        username=username,
        password_hash=hash_password(password),
        two_fa_method="none",
    )
    db.add(user)
    db.commit()
    return user


def cleanup_expired_auth(db):
    now = utcnow()
    db.query(PanelSession).filter(PanelSession.expires_at < now).delete()
    db.query(TwoFaChallenge).filter(TwoFaChallenge.expires_at < now).delete()
    db.commit()


def create_panel_session(db, user_id, ip_address="", user_agent=""):
    cleanup_expired_auth(db)
    token = secrets.token_urlsafe(32)
    expires = utcnow() + timedelta(hours=SESSION_HOURS)
    db.add(PanelSession(
        token=token,
        user_id=user_id,
        expires_at=expires,
        ip_address=(ip_address or "")[:45],
        user_agent=(user_agent or "")[:512],
    ))
    db.commit()
    return token, expires


def get_panel_session(db, token):
    if not token:
        return None
    row = db.query(PanelSession).filter_by(token=token).first()
    if not row or row.expires_at < utcnow():
        return None
    return db.query(PanelUser).filter_by(id=row.user_id, is_active=True).first()


def revoke_panel_session(db, token):
    row = db.query(PanelSession).filter_by(token=token).first()
    if row:
        db.delete(row)
        db.commit()


def list_user_sessions(db, user_id):
    cleanup_expired_auth(db)
    now = utcnow()
    rows = (
        db.query(PanelSession)
        .filter_by(user_id=user_id)
        .filter(PanelSession.expires_at >= now)
        .order_by(PanelSession.created_at.desc())
        .all()
    )
    return rows


def revoke_session_token(db, user_id, token):
    row = db.query(PanelSession).filter_by(token=token, user_id=user_id).first()
    if row:
        db.delete(row)
        db.commit()
        return True
    return False


def revoke_other_sessions(db, user_id, keep_token):
    cleanup_expired_auth(db)
    q = db.query(PanelSession).filter_by(user_id=user_id)
    if keep_token:
        q = q.filter(PanelSession.token != keep_token)
    deleted = q.delete()
    db.commit()
    return deleted


def get_primary_panel_user(db):
    return db.query(PanelUser).filter_by(is_active=True).order_by(PanelUser.id).first()


def create_2fa_challenge(db, user, method, purpose="login", code=None):
    cleanup_expired_auth(db)
    token = secrets.token_urlsafe(24)
    expires = utcnow() + timedelta(minutes=CHALLENGE_MINUTES)
    if method == "telegram" and not code:
        code = f"{random.randint(100000, 999999)}"
    db.add(TwoFaChallenge(
        token=token,
        user_id=user.id,
        code=str(code or ""),
        method=method,
        purpose=purpose,
        expires_at=expires,
    ))
    db.commit()
    return token, code, expires


def verify_2fa_challenge(db, challenge_token, user, code, method=None):
    row = db.query(TwoFaChallenge).filter_by(token=challenge_token, user_id=user.id).first()
    if not row or row.expires_at < utcnow():
        return False
    use_method = method or row.method
    if row.method != use_method:
        return False
    entered = str(code or "").strip().replace(" ", "")
    ok = False
    if use_method == "telegram":
        ok = row.code == entered
    elif use_method == "totp":
        if user.totp_secret:
            totp = pyotp.TOTP(user.totp_secret)
            ok = totp.verify(entered, valid_window=1)
    if ok:
        db.delete(row)
        db.commit()
    return ok


def generate_totp_setup(user):
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user.username, issuer_name=TOTP_ISSUER)
    return secret, uri


def verify_totp_code(user, code):
    if not user.totp_secret:
        return False
    totp = pyotp.TOTP(user.totp_secret)
    return totp.verify(str(code or "").strip().replace(" ", ""), valid_window=1)


def login_requires_2fa(user):
    return (user.two_fa_method or "none") in ("totp", "telegram")


def session_response(user, token, expires):
    return {
        "access_token": token,
        "expires_at": expires.isoformat(),
        "user": user.to_dict(),
        "auth_type": "panel",
    }
