"""SQLAlchemy models — portable across PostgreSQL / MySQL / MariaDB."""

import secrets
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text, Index,
)
from sqlalchemy.orm import relationship

from db import Base


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def new_agent_key():
    return secrets.token_hex(32)


class Server(Base):
    __tablename__ = "servers"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False)
    hostname = Column(String(255), default="")
    description = Column(String(512), default="")
    agent_key = Column(String(64), unique=True, nullable=False, default=new_agent_key)
    is_active = Column(Boolean, default=True)
    last_seen = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    mod_fail2ban = Column(Boolean, default=True)
    mod_csf = Column(Boolean, default=True)
    mod_nftables = Column(Boolean, default=True)
    cap_fail2ban = Column(Boolean, default=False)
    cap_csf = Column(Boolean, default=False)
    cap_nftables = Column(Boolean, default=False)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    location_label = Column(String(128), default="")

    bans = relationship("BanRecord", back_populates="server", cascade="all, delete-orphan")
    events = relationship("EventLog", back_populates="server", cascade="all, delete-orphan")

    def to_dict(self, include_key=False):
        online = False
        if self.last_seen:
            online = (utcnow() - self.last_seen).total_seconds() < 90
        d = {
            "id": self.id,
            "name": self.name,
            "hostname": self.hostname,
            "description": self.description,
            "is_active": self.is_active,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "online": online,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "mod_fail2ban": bool(self.mod_fail2ban),
            "mod_csf": bool(self.mod_csf),
            "mod_nftables": bool(self.mod_nftables),
            "cap_fail2ban": bool(self.cap_fail2ban),
            "cap_csf": bool(self.cap_csf),
            "cap_nftables": bool(self.cap_nftables),
            "latitude": self.latitude,
            "longitude": self.longitude,
            "location_label": self.location_label or "",
        }
        if include_key:
            d["agent_key"] = self.agent_key
        return d


class BanRecord(Base):
    __tablename__ = "ban_records"
    __table_args__ = (Index("ix_ban_server_ts", "server_id", "ts"),)

    id = Column(Integer, primary_key=True)
    server_id = Column(Integer, ForeignKey("servers.id", ondelete="CASCADE"), nullable=False)
    ts = Column(DateTime, nullable=False, default=utcnow)
    ip = Column(String(45), nullable=False)
    jail = Column(String(64), nullable=False)
    country = Column(String(128), default="")
    country_code = Column(String(8), default="")
    city = Column(String(128), default="")
    isp = Column(String(255), default="")
    lat = Column(Float, default=0)
    lon = Column(Float, default=0)

    server = relationship("Server", back_populates="bans")

    def to_dict(self):
        return {
            "ts": self.ts.isoformat(),
            "ip": self.ip,
            "jail": self.jail,
            "country": self.country,
            "country_code": self.country_code,
            "city": self.city,
            "isp": self.isp,
            "lat": self.lat,
            "lon": self.lon,
        }


class EventLog(Base):
    __tablename__ = "event_logs"
    __table_args__ = (Index("ix_event_server_ts", "server_id", "ts"),)

    id = Column(Integer, primary_key=True)
    server_id = Column(Integer, ForeignKey("servers.id", ondelete="CASCADE"), nullable=False)
    ts = Column(DateTime, nullable=False, default=utcnow)
    level = Column(String(16), nullable=False)
    message = Column(Text, nullable=False)
    ip = Column(String(45), nullable=True)
    jail = Column(String(64), nullable=True)

    server = relationship("Server", back_populates="events")

    def to_dict(self):
        return {
            "ts": self.ts.strftime("%H:%M:%S"),
            "level": self.level,
            "message": self.message,
            "ip": self.ip,
            "jail": self.jail,
        }


class NetworkMetric(Base):
    __tablename__ = "network_metrics"
    __table_args__ = (Index("ix_net_server_ts", "server_id", "ts"),)

    id = Column(Integer, primary_key=True)
    server_id = Column(Integer, ForeignKey("servers.id", ondelete="CASCADE"), nullable=False)
    ts = Column(DateTime, nullable=False, default=utcnow)
    rx_mbps = Column(Float, default=0)
    tx_mbps = Column(Float, default=0)


class ConnectionMetric(Base):
    __tablename__ = "connection_metrics"
    __table_args__ = (Index("ix_conn_server_ts", "server_id", "ts"),)

    id = Column(Integer, primary_key=True)
    server_id = Column(Integer, ForeignKey("servers.id", ondelete="CASCADE"), nullable=False)
    ts = Column(DateTime, nullable=False, default=utcnow)
    count = Column(Integer, default=0)


class JailSnapshot(Base):
    __tablename__ = "jail_snapshots"

    server_id = Column(Integer, ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True)
    updated_at = Column(DateTime, default=utcnow)
    data = Column(Text, default="[]")


class ConnectionSnapshot(Base):
    __tablename__ = "connection_snapshots"

    server_id = Column(Integer, ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True)
    updated_at = Column(DateTime, default=utcnow)
    data = Column(Text, default="[]")


class AgentCommand(Base):
    __tablename__ = "agent_commands"

    id = Column(Integer, primary_key=True)
    server_id = Column(Integer, ForeignKey("servers.id", ondelete="CASCADE"), nullable=False)
    action = Column(String(32), nullable=False)
    payload = Column(Text, default="{}")
    status = Column(String(16), default="pending")
    created_at = Column(DateTime, default=utcnow)
    completed_at = Column(DateTime, nullable=True)


class CsfSnapshot(Base):
    __tablename__ = "csf_snapshots"

    server_id = Column(Integer, ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True)
    updated_at = Column(DateTime, default=utcnow)
    data = Column(Text, default="{}")


class NftablesSnapshot(Base):
    __tablename__ = "nftables_snapshots"

    server_id = Column(Integer, ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True)
    updated_at = Column(DateTime, default=utcnow)
    data = Column(Text, default="{}")


class HubSetting(Base):
    __tablename__ = "hub_settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text, default="")


class TelegramUser(Base):
    __tablename__ = "telegram_users"

    id = Column(Integer, primary_key=True)
    telegram_id = Column(Integer, unique=True, nullable=False)
    username = Column(String(128), default="")
    first_name = Column(String(128), default="")
    linked_at = Column(DateTime, default=utcnow)
    is_active = Column(Boolean, default=True)

    def to_dict(self):
        return {
            "id": self.id,
            "telegram_id": self.telegram_id,
            "username": self.username,
            "first_name": self.first_name,
            "linked_at": self.linked_at.isoformat() if self.linked_at else None,
            "is_active": self.is_active,
        }


class TelegramLinkCode(Base):
    __tablename__ = "telegram_link_codes"

    code = Column(String(8), primary_key=True)
    created_at = Column(DateTime, default=utcnow)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)


class IpWhitelist(Base):
    __tablename__ = "ip_whitelist"

    id = Column(Integer, primary_key=True)
    ip = Column(String(64), nullable=False)
    label = Column(String(128), default="")
    created_at = Column(DateTime, default=utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "ip": self.ip,
            "label": self.label,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class TelegramWebSession(Base):
    __tablename__ = "telegram_web_sessions"

    token = Column(String(64), primary_key=True)
    telegram_id = Column(Integer, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=utcnow)


class PanelUser(Base):
    __tablename__ = "panel_users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    totp_secret = Column(String(64), nullable=True)
    two_fa_method = Column(String(16), default="none")
    telegram_id = Column(Integer, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    def to_dict(self, include_security=False):
        d = {
            "id": self.id,
            "username": self.username,
        }
        if include_security:
            d.update({
                "two_fa_method": self.two_fa_method or "none",
                "totp_configured": bool(self.totp_secret),
                "telegram_2fa_id": self.telegram_id,
            })
        return d


class PanelSession(Base):
    __tablename__ = "panel_sessions"

    token = Column(String(64), primary_key=True)
    user_id = Column(Integer, ForeignKey("panel_users.id", ondelete="CASCADE"), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=utcnow)
    ip_address = Column(String(45), default="")
    user_agent = Column(String(512), default="")

    def to_dict(self, mask_token=True):
        tok = self.token
        if mask_token and len(tok) > 12:
            tok = f"{tok[:8]}…{tok[-4:]}"
        return {
            "token": tok,
            "token_full": self.token if not mask_token else None,
            "user_id": self.user_id,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "ip_address": self.ip_address or "",
            "user_agent": self.user_agent or "",
        }


class TwoFaChallenge(Base):
    __tablename__ = "two_fa_challenges"

    token = Column(String(64), primary_key=True)
    user_id = Column(Integer, ForeignKey("panel_users.id", ondelete="CASCADE"), nullable=False)
    code = Column(String(16), default="")
    method = Column(String(16), nullable=False)
    purpose = Column(String(32), default="login")
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=utcnow)


class BrandingHistory(Base):
    __tablename__ = "branding_history"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("panel_users.id", ondelete="SET NULL"), nullable=True)
    username = Column(String(64), default="")
    changes = Column(Text, default="{}")
    snapshot = Column(Text, default="{}")
    created_at = Column(DateTime, default=utcnow)

    def to_dict(self):
        import json
        try:
            changes = json.loads(self.changes or "{}")
        except Exception:
            changes = {}
        try:
            snapshot = json.loads(self.snapshot or "{}")
        except Exception:
            snapshot = {}
        return {
            "id": self.id,
            "username": self.username or "",
            "changes": changes,
            "snapshot": snapshot,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class SecurityTemplate(Base):
    __tablename__ = "security_templates"

    id = Column(Integer, primary_key=True)
    kind = Column(String(32), nullable=False)
    slug = Column(String(64), unique=True, nullable=False)
    name = Column(String(128), nullable=False)
    description = Column(Text, default="")
    instructions = Column(Text, default="")
    critical = Column(Boolean, default=False)
    payload = Column(Text, default="{}")
    is_builtin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow)
