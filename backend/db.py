"""Database setup — PostgreSQL, MySQL, MariaDB, SQLite (local dev)."""

import os
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session

DATABASE_URL = os.environ.get("DATABASE_URL", "")

Base = declarative_base()
engine = None
SessionLocal = scoped_session(sessionmaker())


def _resolve_database_url():
    url = DATABASE_URL
    if not url:
        db_file = Path(__file__).parent / "neohost-dev.db"
        url = f"sqlite:///{db_file.as_posix()}"
        print(f"[DB] Mod local: SQLite -> {db_file}")
    if url.startswith("mariadb://"):
        url = url.replace("mariadb://", "mysql+pymysql://", 1)
    return url


def init_db(app=None):
    global engine
    url = _resolve_database_url()
    connect_args = {}
    if url.startswith("postgresql"):
        connect_args["connect_timeout"] = 10
    elif url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    engine = create_engine(url, pool_pre_ping=True, pool_recycle=3600, connect_args=connect_args)
    SessionLocal.configure(bind=engine, autocommit=False, autoflush=False)
    from models import Server, BanRecord, EventLog, NetworkMetric, ConnectionMetric  # noqa: F401
    from models import JailSnapshot, ConnectionSnapshot, AgentCommand  # noqa: F401
    from models import CsfSnapshot, NftablesSnapshot, HubSetting, TelegramUser, TelegramLinkCode, IpWhitelist  # noqa: F401
    from models import TelegramWebSession, PanelUser, PanelSession, TwoFaChallenge, SecurityTemplate  # noqa: F401
    from models import BrandingHistory  # noqa: F401
    Base.metadata.create_all(bind=engine)
    _migrate_sqlite_columns(engine)
    from panel_auth import ensure_default_admin
    from security_templates import ensure_builtin_templates
    db = SessionLocal()
    try:
        ensure_default_admin(db)
        ensure_builtin_templates(db)
    finally:
        db.close()
    if app:
        @app.teardown_appcontext
        def _close_db(_exc=None):
            SessionLocal.remove()


def _migrate_sqlite_columns(engine):
    if not str(engine.url).startswith("sqlite"):
        return
    cols = [
        ("servers", "mod_fail2ban", "BOOLEAN DEFAULT 1"),
        ("servers", "mod_csf", "BOOLEAN DEFAULT 1"),
        ("servers", "cap_fail2ban", "BOOLEAN DEFAULT 0"),
        ("servers", "cap_csf", "BOOLEAN DEFAULT 0"),
        ("servers", "mod_nftables", "BOOLEAN DEFAULT 1"),
        ("servers", "cap_nftables", "BOOLEAN DEFAULT 0"),
        ("servers", "latitude", "FLOAT"),
        ("servers", "longitude", "FLOAT"),
        ("servers", "location_label", "VARCHAR(128) DEFAULT ''"),
        ("panel_sessions", "ip_address", "VARCHAR(45) DEFAULT ''"),
        ("panel_sessions", "user_agent", "VARCHAR(512) DEFAULT ''"),
    ]
    with engine.connect() as conn:
        for table, col, typedef in cols:
            try:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {typedef}"))
                conn.commit()
            except Exception:
                pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
