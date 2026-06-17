#!/usr/bin/env python3
"""
NeoHost Security Monitor — Hub central (hosting)
Dashboard multi-server cu PostgreSQL / MySQL / MariaDB
"""

import csv
import io
import json
import os
import threading
import urllib.request
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, jsonify, request, Response, g
from flask_cors import CORS
from flask_sock import Sock

from db import init_db, SessionLocal
from models import (
    Server, BanRecord, EventLog, NetworkMetric, ConnectionMetric,
    JailSnapshot, ConnectionSnapshot, AgentCommand, CsfSnapshot, NftablesSnapshot,
    HubSetting, TelegramUser, TelegramLinkCode, IpWhitelist, PanelUser, SecurityTemplate,
    utcnow, new_agent_key,
)
from intelligence import (
    compute_threat_level, compute_top_attackers, compute_country_stats,
    compute_jail_stats, compute_ban_timeline,
)
from security_templates import ensure_builtin_templates, template_to_dict, new_user_slug
from security_audit import run_security_audit
from branding import get_branding, update_branding, list_branding_history
from notifications import get_notification_settings, update_notification_settings, notify_new_bans, notify_threat_change
from panel_auth import (
    verify_password, hash_password, create_panel_session, get_panel_session,
    revoke_panel_session, get_primary_panel_user, create_2fa_challenge,
    verify_2fa_challenge, generate_totp_setup, verify_totp_code,
    login_requires_2fa, session_response,
    list_user_sessions, revoke_session_token, revoke_other_sessions,
)
from security import (
    client_ip_from_request, check_ip_whitelist, generate_link_code,
    get_setting, set_setting, is_whitelist_enabled,
    validate_telegram_init_data, create_telegram_web_session, get_telegram_web_session,
    get_telegram_bot_token, get_telegram_webapp_url, mask_token,
)

app = Flask(__name__)
CORS(app, origins=["*"])
sock = Sock(app)

API_TOKEN = os.environ.get("SECURITY_API_TOKEN", "schimba-acest-token-secret")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_WEBAPP_URL = os.environ.get("TELEGRAM_WEBAPP_URL", "").rstrip("/")
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
METRIC_RETENTION_HOURS = int(os.environ.get("METRIC_RETENTION_HOURS", "48"))

ws_clients = {}  # ws -> server_id
ws_lock = threading.Lock()
ip_geo_cache = {}


def get_db():
    return SessionLocal()


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401
        token = auth[7:]
        db = get_db()
        try:
            client_ip = client_ip_from_request(request)
            if token == API_TOKEN:
                if not check_ip_whitelist(db, client_ip):
                    return jsonify({
                        "error": "IP neautorizat pentru panou",
                        "code": "ip_not_whitelisted",
                        "client_ip": client_ip,
                    }), 403
                g.auth_type = "legacy_token"
                return f(*args, **kwargs)
            panel_user = get_panel_session(db, token)
            if panel_user:
                if not check_ip_whitelist(db, client_ip):
                    return jsonify({
                        "error": "IP neautorizat pentru panou",
                        "code": "ip_not_whitelisted",
                        "client_ip": client_ip,
                    }), 403
                g.panel_user = panel_user
                g.panel_token = token
                g.auth_type = "panel"
                return f(*args, **kwargs)
            tg_user = get_telegram_web_session(db, token)
            if tg_user:
                g.telegram_user = tg_user
                g.auth_type = "telegram"
                return f(*args, **kwargs)
        finally:
            db.close()
        return jsonify({"error": "Unauthorized"}), 401
    return decorated


def _account_user(db):
    user = getattr(g, "panel_user", None)
    if user:
        return user
    if getattr(g, "auth_type", None) == "legacy_token":
        return get_primary_panel_user(db)
    return None


def _session_meta():
    return (
        client_ip_from_request(request),
        (request.headers.get("User-Agent") or "")[:512],
    )


def _ws_token_ok(db, token):
    if token == API_TOKEN:
        return True
    return get_panel_session(db, token) is not None


def require_agent(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-Agent-Key", "")
        if not key:
            return jsonify({"error": "X-Agent-Key lipsă"}), 401
        db = get_db()
        server = db.query(Server).filter_by(agent_key=key, is_active=True).first()
        if not server:
            db.close()
            return jsonify({"error": "Agent key invalid"}), 401
        g.server = server
        g.db = db
        try:
            return f(*args, **kwargs)
        finally:
            db.close()
    return decorated


def server_id_param():
    sid = request.args.get("server_id", type=int)
    if not sid:
        body = request.get_json(silent=True) or {}
        sid = body.get("server_id")
    return sid


def get_server_or_404(sid):
    db = get_db()
    server = db.query(Server).filter_by(id=sid, is_active=True).first()
    if not server:
        db.close()
        return None, None
    return server, db


def broadcast_ws(server_id, payload):
    msg = json.dumps(payload, default=str)
    dead = set()
    with ws_lock:
        targets = [(ws, sid) for ws, sid in ws_clients.items() if sid == server_id]
    for ws, _ in targets:
        try:
            ws.send(msg)
        except Exception:
            dead.add(ws)
    if dead:
        with ws_lock:
            for ws in dead:
                ws_clients.pop(ws, None)


def get_geo(ip):
    if ip in ip_geo_cache:
        return ip_geo_cache[ip]
    try:
        url = (
            f"http://ip-api.com/json/{ip}"
            f"?fields=status,country,countryCode,regionName,city,isp,org,as,reverse,lat,lon"
        )
        with urllib.request.urlopen(url, timeout=4) as resp:
            data = json.loads(resp.read())
        if data.get("status") == "success":
            geo = {
                "country": data.get("country", "Unknown"),
                "country_code": data.get("countryCode", ""),
                "region": data.get("regionName", ""),
                "city": data.get("city", ""),
                "isp": data.get("isp", ""),
                "org": data.get("org", ""),
                "asn": data.get("as", ""),
                "rdns": data.get("reverse", ""),
                "lat": data.get("lat", 0),
                "lon": data.get("lon", 0),
            }
            ip_geo_cache[ip] = geo
            return geo
    except Exception:
        pass
    return {
        "country": "Unknown", "country_code": "", "isp": "", "org": "",
        "asn": "", "rdns": "", "lat": 0, "lon": 0, "region": "", "city": "",
    }


def get_abuse_score(ip):
    if not ABUSEIPDB_KEY:
        return {"score": None, "reports": None, "url": f"https://www.abuseipdb.com/check/{ip}"}
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        req = urllib.request.Request(url, headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        d = data.get("data", {})
        return {
            "score": d.get("abuseConfidenceScore", 0),
            "reports": d.get("totalReports", 0),
            "url": f"https://www.abuseipdb.com/check/{ip}",
        }
    except Exception:
        return {"score": None, "reports": None, "url": f"https://www.abuseipdb.com/check/{ip}"}


def load_bans(db, server_id, jail=None, limit=5000):
    q = db.query(BanRecord).filter_by(server_id=server_id).order_by(BanRecord.ts.desc())
    if jail:
        q = q.filter_by(jail=jail)
    return [b.to_dict() for b in q.limit(limit).all()]


def load_intel(db, server_id, jail=None):
    bans = load_bans(db, server_id, jail=jail)
    ban_times = []
    for b in db.query(BanRecord.ts).filter_by(server_id=server_id).order_by(BanRecord.ts.desc()).limit(5000):
        ban_times.append(b.ts)
    return {
        "threat": compute_threat_level(ban_times),
        "top10": compute_top_attackers(bans, 10),
        "countries": compute_country_stats(bans),
        "jail_stats": compute_jail_stats(bans),
        "timeline": compute_ban_timeline(bans),
        "total_bans": len(bans),
    }


def load_net_history(db, server_id, limit=120):
    rows = (
        db.query(NetworkMetric)
        .filter_by(server_id=server_id)
        .order_by(NetworkMetric.ts.desc())
        .limit(limit)
        .all()
    )
    return [{"ts": r.ts.strftime("%H:%M:%S"), "rx": r.rx_mbps, "tx": r.tx_mbps} for r in reversed(rows)]


def load_conn_history(db, server_id, limit=120):
    rows = (
        db.query(ConnectionMetric)
        .filter_by(server_id=server_id)
        .order_by(ConnectionMetric.ts.desc())
        .limit(limit)
        .all()
    )
    return [{"ts": r.ts.strftime("%H:%M:%S"), "count": r.count} for r in reversed(rows)]


def queue_command(db, server_id, action, payload):
    cmd = AgentCommand(server_id=server_id, action=action, payload=json.dumps(payload))
    db.add(cmd)
    db.commit()
    return cmd.id


# ── Server management ─────────────────────────────────────────────────────────

def _parse_server_coord(val, label, lo, hi):
    if val is None or val == "":
        return None
    try:
        f = float(val)
    except (TypeError, ValueError):
        raise ValueError(f"{label} invalid")
    if f < lo or f > hi:
        raise ValueError(f"{label} în afara intervalului ({lo}…{hi})")
    return f


def _apply_server_coords(server, data):
    if "latitude" in data:
        server.latitude = _parse_server_coord(data.get("latitude"), "Latitudine", -90, 90)
    if "longitude" in data:
        server.longitude = _parse_server_coord(data.get("longitude"), "Longitudine", -180, 180)
    if "location_label" in data:
        server.location_label = (data.get("location_label") or "").strip()[:128]

@app.route("/api/servers", methods=["GET"])
@require_auth
def api_servers_list():
    db = get_db()
    servers = db.query(Server).order_by(Server.name).all()
    result = [s.to_dict() for s in servers]
    db.close()
    return jsonify({"servers": result})


@app.route("/api/servers", methods=["POST"])
@require_auth
def api_servers_create():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Numele serverului este obligatoriu"}), 400
    db = get_db()
    try:
        server = Server(
            name=name,
            hostname=(data.get("hostname") or "").strip(),
            description=(data.get("description") or "").strip(),
            agent_key=new_agent_key(),
            mod_fail2ban=bool(data.get("mod_fail2ban", True)),
            mod_csf=bool(data.get("mod_csf", True)),
            mod_nftables=bool(data.get("mod_nftables", True)),
        )
        _apply_server_coords(server, data)
    except ValueError as exc:
        db.close()
        return jsonify({"error": str(exc)}), 400
    db.add(server)
    db.commit()
    result = server.to_dict(include_key=True)
    db.close()
    return jsonify({"server": result}), 201


@app.route("/api/servers/<int:sid>", methods=["GET"])
@require_auth
def api_servers_get(sid):
    db = get_db()
    server = db.query(Server).filter_by(id=sid).first()
    if not server:
        db.close()
        return jsonify({"error": "Server negăsit"}), 404
    result = server.to_dict(include_key=True)
    db.close()
    return jsonify({"server": result})


@app.route("/api/servers/<int:sid>", methods=["PUT"])
@require_auth
def api_servers_update(sid):
    data = request.get_json(silent=True) or {}
    db = get_db()
    server = db.query(Server).filter_by(id=sid).first()
    if not server:
        db.close()
        return jsonify({"error": "Server negăsit"}), 404
    if "name" in data:
        server.name = data["name"].strip()
    if "hostname" in data:
        server.hostname = data["hostname"].strip()
    if "description" in data:
        server.description = data["description"].strip()
    if "is_active" in data:
        server.is_active = bool(data["is_active"])
    if "mod_fail2ban" in data:
        server.mod_fail2ban = bool(data["mod_fail2ban"])
    if "mod_csf" in data:
        server.mod_csf = bool(data["mod_csf"])
    if "mod_nftables" in data:
        server.mod_nftables = bool(data["mod_nftables"])
    try:
        _apply_server_coords(server, data)
    except ValueError as exc:
        db.close()
        return jsonify({"error": str(exc)}), 400
    db.commit()
    result = server.to_dict()
    db.close()
    return jsonify({"server": result})


@app.route("/api/servers/<int:sid>", methods=["DELETE"])
@require_auth
def api_servers_delete(sid):
    db = get_db()
    server = db.query(Server).filter_by(id=sid).first()
    if not server:
        db.close()
        return jsonify({"error": "Server negăsit"}), 404
    db.delete(server)
    db.commit()
    db.close()
    return jsonify({"success": True})


@app.route("/api/servers/<int:sid>/regenerate-key", methods=["POST"])
@require_auth
def api_servers_regen_key(sid):
    db = get_db()
    server = db.query(Server).filter_by(id=sid).first()
    if not server:
        db.close()
        return jsonify({"error": "Server negăsit"}), 404
    server.agent_key = new_agent_key()
    db.commit()
    result = server.to_dict(include_key=True)
    db.close()
    return jsonify({"server": result})


# ── Agent API ─────────────────────────────────────────────────────────────────

@app.route("/api/agent/report", methods=["POST"])
@require_agent
def api_agent_report():
    server = g.server
    db = g.db
    data = request.get_json(silent=True) or {}
    now = utcnow()
    server.last_seen = now

    caps = data.get("capabilities", {})
    if caps:
        server.cap_fail2ban = bool(caps.get("fail2ban"))
        server.cap_csf = bool(caps.get("csf"))
        server.cap_nftables = bool(caps.get("nftables"))

    if "jails" in data and server.mod_fail2ban:
        snap = db.query(JailSnapshot).filter_by(server_id=server.id).first()
        if not snap:
            snap = JailSnapshot(server_id=server.id)
            db.add(snap)
        f2b_payload = data.get("fail2ban") or {"jails": data["jails"]}
        snap.data = json.dumps(f2b_payload)
        snap.updated_at = now

    if "connections" in data:
        snap = db.query(ConnectionSnapshot).filter_by(server_id=server.id).first()
        if not snap:
            snap = ConnectionSnapshot(server_id=server.id)
            db.add(snap)
        snap.data = json.dumps(data["connections"])
        snap.updated_at = now

    if "csf" in data and server.mod_csf:
        csf_snap = db.query(CsfSnapshot).filter_by(server_id=server.id).first()
        if not csf_snap:
            csf_snap = CsfSnapshot(server_id=server.id)
            db.add(csf_snap)
        csf_snap.data = json.dumps(data["csf"])
        csf_snap.updated_at = now

    if "nftables" in data and server.mod_nftables:
        nft_snap = db.query(NftablesSnapshot).filter_by(server_id=server.id).first()
        if not nft_snap:
            nft_snap = NftablesSnapshot(server_id=server.id)
            db.add(nft_snap)
        nft_snap.data = json.dumps(data["nftables"])
        nft_snap.updated_at = now

    net = data.get("net", {})
    if net:
        db.add(NetworkMetric(
            server_id=server.id, ts=now,
            rx_mbps=net.get("rx_mbps", 0), tx_mbps=net.get("tx_mbps", 0),
        ))

    conns = data.get("connections", [])
    db.add(ConnectionMetric(server_id=server.id, ts=now, count=len(conns)))

    new_ban_rows = []

    for ev in data.get("events", []):
        db.add(EventLog(
            server_id=server.id,
            ts=datetime.fromisoformat(ev["ts"]) if ev.get("ts") and "T" in str(ev["ts"]) else now,
            level=ev.get("level", "INFO"),
            message=ev.get("message", ""),
            ip=ev.get("ip"), jail=ev.get("jail"),
        ))

    for ban in data.get("bans", []):
        ip = ban.get("ip", "")
        jail = ban.get("jail", "unknown")
        recent = (
            db.query(BanRecord)
            .filter_by(server_id=server.id, ip=ip, jail=jail)
            .filter(BanRecord.ts >= now - timedelta(minutes=10))
            .first()
        )
        if recent:
            continue
        if ban.get("country"):
            geo = ban
        else:
            geo = get_geo(ban.get("ip", ""))
        ts_raw = ban.get("ts")
        try:
            ts = datetime.fromisoformat(ts_raw) if ts_raw else now
        except Exception:
            ts = now
        ban_row = {
            "ip": ban.get("ip", ""),
            "jail": ban.get("jail", "unknown"),
            "country": geo.get("country", ""),
            "country_code": geo.get("country_code", ""),
        }
        new_ban_rows.append(ban_row)
        db.add(BanRecord(
            server_id=server.id, ts=ts,
            ip=ban_row["ip"], jail=ban_row["jail"],
            country=ban_row["country"], country_code=ban_row["country_code"],
            city=geo.get("city", ""), isp=geo.get("isp", ""),
            lat=geo.get("lat", 0), lon=geo.get("lon", 0),
        ))

    db.commit()

    if new_ban_rows:
        try:
            notify_new_bans(db, server, new_ban_rows)
        except Exception:
            pass

    net_h = load_net_history(db, server.id)
    conn_h = load_conn_history(db, server.id)
    intel = load_intel(db, server.id)
    try:
        notify_threat_change(db, server, intel.get("threat"))
    except Exception:
        pass
    events = [e.to_dict() for e in
              db.query(EventLog).filter_by(server_id=server.id).order_by(EventLog.ts.desc()).limit(30)]
    ban_hist = load_bans(db, server.id, limit=100)

    f2b_live = None
    csf_live = None
    nft_live = None
    if server.mod_fail2ban:
        snap_f2b = db.query(JailSnapshot).filter_by(server_id=server.id).first()
        if snap_f2b and snap_f2b.data:
            raw = json.loads(snap_f2b.data)
            f2b_live = raw if isinstance(raw, dict) else {"jails": raw, "installed": True}
    if server.mod_csf:
        snap_csf = db.query(CsfSnapshot).filter_by(server_id=server.id).first()
        if snap_csf and snap_csf.data:
            csf_live = json.loads(snap_csf.data)
    if server.mod_nftables:
        snap_nft = db.query(NftablesSnapshot).filter_by(server_id=server.id).first()
        if snap_nft and snap_nft.data:
            nft_live = json.loads(snap_nft.data)

    broadcast_ws(server.id, {
        "type": "tick",
        "data": {
            "ts": now.strftime("%H:%M:%S"),
            "net": net,
            "connections": conns,
            "net_history": net_h,
            "conn_history": conn_h,
            "threat": intel["threat"],
            "countries": intel["countries"],
            "top10": intel["top10"],
            "fail2ban": f2b_live,
            "csf": csf_live,
            "nftables": nft_live,
        },
    })

    return jsonify({"success": True, "server_id": server.id})


@app.route("/api/agent/commands", methods=["GET"])
@require_agent
def api_agent_commands():
    server = g.server
    db = g.db
    cmds = (
        db.query(AgentCommand)
        .filter_by(server_id=server.id, status="pending")
        .order_by(AgentCommand.created_at)
        .limit(20)
        .all()
    )
    result = [{"id": c.id, "action": c.action, "payload": json.loads(c.payload or "{}")} for c in cmds]
    return jsonify({"commands": result})


@app.route("/api/agent/commands/<int:cid>/done", methods=["POST"])
@require_agent
def api_agent_command_done(cid):
    server = g.server
    db = g.db
    cmd = db.query(AgentCommand).filter_by(id=cid, server_id=server.id).first()
    if cmd:
        data = request.get_json(silent=True) or {}
        cmd.status = "done" if data.get("success", True) else "failed"
        cmd.completed_at = utcnow()
        db.commit()
    return jsonify({"success": True})


# ── Dashboard API (per server) ────────────────────────────────────────────────

def _sid_required():
    sid = server_id_param()
    if not sid:
        return None, (jsonify({"error": "server_id obligatoriu"}), 400)
    server, db = get_server_or_404(sid)
    if not server:
        return None, (jsonify({"error": "Server negăsit"}), 404)
    return (server, db), None


def _load_fail2ban(db, server_id):
    snap = db.query(JailSnapshot).filter_by(server_id=server_id).first()
    if not snap or not snap.data:
        return {"installed": False, "running": False, "jails": []}
    raw = json.loads(snap.data)
    if isinstance(raw, list):
        return {"installed": True, "running": bool(raw), "jails": raw}
    return raw


def _load_csf(db, server_id):
    snap = db.query(CsfSnapshot).filter_by(server_id=server_id).first()
    if not snap or not snap.data:
        return {}
    try:
        return json.loads(snap.data)
    except json.JSONDecodeError:
        return {}


def _load_nftables(db, server_id):
    snap = db.query(NftablesSnapshot).filter_by(server_id=server_id).first()
    if not snap or not snap.data:
        return {}
    try:
        return json.loads(snap.data)
    except json.JSONDecodeError:
        return {}


# ── Securitate: șabloane, audit, jail provisioning ─────────────────────────────

@app.route("/api/security/templates")
@require_auth
def api_security_templates_list():
    kind = request.args.get("kind", "")
    db = get_db()
    ensure_builtin_templates(db)
    q = db.query(SecurityTemplate).order_by(
        SecurityTemplate.is_builtin.desc(),
        SecurityTemplate.critical.desc(),
        SecurityTemplate.name,
    )
    if kind:
        q = q.filter_by(kind=kind)
    rows = [template_to_dict(t) for t in q.all()]
    db.close()
    return jsonify({"templates": rows})


@app.route("/api/security/templates", methods=["POST"])
@require_auth
def api_security_templates_create():
    data = request.get_json(silent=True) or {}
    kind = (data.get("kind") or "").strip()
    name = (data.get("name") or "").strip()
    if kind not in ("fail2ban_jail", "csf_preset", "nftables_preset") or not name:
        return jsonify({"error": "kind și name obligatorii"}), 400
    payload = data.get("payload") or {}
    if kind == "fail2ban_jail" and not payload.get("jail_name"):
        return jsonify({"error": "payload.jail_name obligatoriu pentru Fail2Ban"}), 400
    db = get_db()
    tpl = SecurityTemplate(
        kind=kind,
        slug=new_user_slug(),
        name=name,
        description=(data.get("description") or "").strip(),
        instructions=(data.get("instructions") or "").strip(),
        critical=bool(data.get("critical")),
        payload=json.dumps(payload),
        is_builtin=False,
    )
    db.add(tpl)
    db.commit()
    out = template_to_dict(tpl)
    db.close()
    return jsonify({"template": out}), 201


@app.route("/api/security/templates/<int:tid>", methods=["PUT"])
@require_auth
def api_security_templates_update(tid):
    data = request.get_json(silent=True) or {}
    db = get_db()
    tpl = db.query(SecurityTemplate).filter_by(id=tid).first()
    if not tpl:
        db.close()
        return jsonify({"error": "Șablon negăsit"}), 404
    if tpl.is_builtin:
        db.close()
        return jsonify({
            "error": "Șabloanele predefinite nu pot fi modificate. Folosiți «Duplică» pentru o copie editabilă.",
        }), 403
    name = (data.get("name") or tpl.name).strip()
    if not name:
        db.close()
        return jsonify({"error": "name obligatoriu"}), 400
    payload = data.get("payload")
    if payload is not None:
        if tpl.kind == "fail2ban_jail" and not payload.get("jail_name"):
            db.close()
            return jsonify({"error": "payload.jail_name obligatoriu pentru Fail2Ban"}), 400
        tpl.payload = json.dumps(payload)
    tpl.name = name
    if "description" in data:
        tpl.description = (data.get("description") or "").strip()
    if "instructions" in data:
        tpl.instructions = (data.get("instructions") or "").strip()
    if "critical" in data:
        tpl.critical = bool(data.get("critical"))
    db.commit()
    out = template_to_dict(tpl)
    db.close()
    return jsonify({"template": out})


@app.route("/api/security/templates/<int:tid>", methods=["DELETE"])
@require_auth
def api_security_templates_delete(tid):
    db = get_db()
    tpl = db.query(SecurityTemplate).filter_by(id=tid).first()
    if not tpl:
        db.close()
        return jsonify({"error": "Șablon negăsit"}), 404
    if tpl.is_builtin:
        db.close()
        return jsonify({"error": "Șabloanele predefinite nu pot fi șterse"}), 403
    db.delete(tpl)
    db.commit()
    db.close()
    return jsonify({"success": True})


@app.route("/api/security/templates/<int:tid>/apply", methods=["POST"])
@require_auth
def api_security_templates_apply(tid):
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    tpl = db.query(SecurityTemplate).filter_by(id=tid).first()
    if not tpl:
        db.close()
        return jsonify({"error": "Șablon negăsit"}), 404
    payload = json.loads(tpl.payload or "{}")
    if tpl.kind == "fail2ban_jail":
        if not server.mod_fail2ban:
            db.close()
            return jsonify({"error": "Fail2Ban dezactivat"}), 400
        queue_command(db, server.id, "f2b_add_jail", {"config": payload})
    elif tpl.kind == "csf_preset":
        if not server.mod_csf:
            db.close()
            return jsonify({"error": "CSF dezactivat"}), 400
        queue_command(db, server.id, "csf_apply_preset", {"preset": payload})
    elif tpl.kind == "nftables_preset":
        if not server.mod_nftables:
            db.close()
            return jsonify({"error": "nftables dezactivat"}), 400
        queue_command(db, server.id, "nft_apply_preset", {"preset": payload})
    else:
        db.close()
        return jsonify({"error": "Tip șablon necunoscut"}), 400
    db.close()
    return jsonify({"success": True, "queued": True, "template": template_to_dict(tpl)})


@app.route("/api/security/templates/<int:tid>/apply-bulk", methods=["POST"])
@require_auth
def api_security_templates_apply_bulk(tid):
    data = request.get_json(silent=True) or {}
    server_ids = data.get("server_ids") or []
    if not server_ids:
        return jsonify({"error": "server_ids obligatoriu"}), 400
    db = get_db()
    tpl = db.query(SecurityTemplate).filter_by(id=tid).first()
    if not tpl:
        db.close()
        return jsonify({"error": "Șablon negăsit"}), 404
    payload = json.loads(tpl.payload or "{}")
    queued = 0
    for sid in server_ids:
        server = db.query(Server).filter_by(id=int(sid), is_active=True).first()
        if not server:
            continue
        if tpl.kind == "fail2ban_jail" and server.mod_fail2ban:
            queue_command(db, server.id, "f2b_add_jail", {"config": payload})
            queued += 1
        elif tpl.kind == "csf_preset" and server.mod_csf:
            queue_command(db, server.id, "csf_apply_preset", {"preset": payload})
            queued += 1
        elif tpl.kind == "nftables_preset" and server.mod_nftables:
            queue_command(db, server.id, "nft_apply_preset", {"preset": payload})
            queued += 1
    db.close()
    return jsonify({"success": True, "queued": queued})


@app.route("/api/security/audit")
@require_auth
def api_security_audit():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    f2b = _load_fail2ban(db, server.id) if server.mod_fail2ban else {}
    csf = _load_csf(db, server.id) if server.mod_csf else {}
    nft = _load_nftables(db, server.id) if server.mod_nftables else {}
    intel = load_intel(db, server.id)
    audit = run_security_audit(server, f2b, csf, intel, nft)
    db.close()
    return jsonify(audit)


@app.route("/api/fail2ban/jail", methods=["POST"])
@require_auth
def api_fail2ban_jail_add():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    if not server.mod_fail2ban:
        db.close()
        return jsonify({"error": "Fail2Ban dezactivat"}), 400
    data = request.get_json(silent=True) or {}
    template_id = data.get("template_id")
    config = data.get("config") or {}
    if template_id:
        tpl = db.query(SecurityTemplate).filter_by(id=int(template_id)).first()
        if not tpl or tpl.kind != "fail2ban_jail":
            db.close()
            return jsonify({"error": "Șablon invalid"}), 400
        config = json.loads(tpl.payload or "{}")
    if not config.get("jail_name"):
        db.close()
        return jsonify({"error": "jail_name obligatoriu"}), 400
    queue_command(db, server.id, "f2b_add_jail", {"config": config})
    db.close()
    return jsonify({"success": True, "queued": True})


@app.route("/api/fail2ban/jail/<jail>", methods=["DELETE"])
@require_auth
def api_fail2ban_jail_delete(jail):
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    if not server.mod_fail2ban:
        db.close()
        return jsonify({"error": "Fail2Ban dezactivat"}), 400
    queue_command(db, server.id, "f2b_remove_jail", {"jail_name": jail})
    db.close()
    return jsonify({"success": True, "queued": True, "note": "Se șterg doar jailuri create din panou (neohost-*.conf)"})


@app.route("/api/jails")
@require_auth
def api_jails():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    if not server.mod_fail2ban:
        db.close()
        return jsonify({"jails": [], "fail2ban": {"installed": False}})
    f2b = _load_fail2ban(db, server.id)
    db.close()
    return jsonify({"jails": f2b.get("jails", []), "fail2ban": f2b})


@app.route("/api/fail2ban")
@require_auth
def api_fail2ban():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    if not server.mod_fail2ban:
        db.close()
        return jsonify({"fail2ban": {"installed": False, "mod_enabled": False}})
    f2b = _load_fail2ban(db, server.id)
    snap = db.query(JailSnapshot).filter_by(server_id=server.id).first()
    if snap and snap.updated_at:
        f2b["updated_at"] = snap.updated_at.isoformat()
    f2b["mod_enabled"] = True
    f2b["cap_detected"] = bool(server.cap_fail2ban)
    db.close()
    return jsonify({"fail2ban": f2b})


@app.route("/api/fail2ban/jail/<jail>/toggle", methods=["POST"])
@require_auth
def api_fail2ban_jail_toggle(jail):
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    if not server.mod_fail2ban:
        db.close()
        return jsonify({"error": "Fail2Ban dezactivat"}), 400
    enabled = bool((request.get_json(silent=True) or {}).get("enabled"))
    action = "start" if enabled else "stop"
    queue_command(db, server.id, action, {"jail": jail})
    db.close()
    return jsonify({"success": True, "queued": True})


@app.route("/api/jails/ban", methods=["POST"])
@require_auth
def api_ban_multi():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    if not server.mod_fail2ban:
        db.close()
        return jsonify({"error": "Fail2Ban dezactivat pentru acest server"}), 400
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    jails = data.get("jails") or []
    if not jails and data.get("jail"):
        jails = [data.get("jail")]
    if not ip:
        db.close()
        return jsonify({"error": "IP lipsă"}), 400
    if not jails:
        db.close()
        return jsonify({"error": "Selectați cel puțin un jail"}), 400
    for jail in jails:
        queue_command(db, server.id, "ban", {"ip": ip, "jail": str(jail).strip()})
    db.close()
    return jsonify({"success": True, "queued": True, "ip": ip, "jails": jails})


@app.route("/api/jails/unban", methods=["POST"])
@require_auth
def api_unban_multi():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    if not server.mod_fail2ban:
        db.close()
        return jsonify({"error": "Fail2Ban dezactivat pentru acest server"}), 400
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    jails = data.get("jails") or []
    if not jails and data.get("jail"):
        jails = [data.get("jail")]
    if not ip:
        db.close()
        return jsonify({"error": "IP lipsă"}), 400
    if not jails:
        db.close()
        return jsonify({"error": "Selectați cel puțin un jail"}), 400
    for jail in jails:
        queue_command(db, server.id, "unban", {"ip": ip, "jail": str(jail).strip()})
    db.close()
    return jsonify({"success": True, "queued": True, "ip": ip, "jails": jails})


@app.route("/api/fail2ban/active-bans")
@require_auth
def api_fail2ban_active_bans():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    if not server.mod_fail2ban:
        db.close()
        return jsonify({"bans": []})
    f2b = _load_fail2ban(db, server.id)
    history = load_bans(db, server.id, limit=5000)
    latest = {}
    for b in history:
        key = (b["ip"], b["jail"])
        if key not in latest:
            latest[key] = b["ts"]
    rows = []
    for j in f2b.get("jails", []):
        for ip in j.get("banned_ips", []):
            rows.append({
                "ip": ip,
                "jail": j["name"],
                "ts": latest.get((ip, j["name"])),
                "active": True,
            })
    db.close()
    return jsonify({"bans": rows})


@app.route("/api/jails/<jail>/ban", methods=["POST"])
@require_auth
def api_ban(jail):
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    if not server.mod_fail2ban:
        db.close()
        return jsonify({"error": "Fail2Ban dezactivat pentru acest server"}), 400
    ip = (request.get_json(silent=True) or {}).get("ip", "").strip()
    if not ip:
        db.close()
        return jsonify({"error": "IP lipsă"}), 400
    queue_command(db, server.id, "ban", {"ip": ip, "jail": jail})
    db.close()
    return jsonify({"success": True, "queued": True, "ip": ip, "jail": jail})


@app.route("/api/jails/<jail>/unban", methods=["POST"])
@require_auth
def api_unban(jail):
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    ip = (request.get_json(silent=True) or {}).get("ip", "").strip()
    if not ip:
        db.close()
        return jsonify({"error": "IP lipsă"}), 400
    queue_command(db, server.id, "unban", {"ip": ip, "jail": jail})
    db.close()
    return jsonify({"success": True, "queued": True})


@app.route("/api/jails/<jail>/start", methods=["POST"])
@require_auth
def api_start_jail(jail):
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    queue_command(db, server.id, "start", {"jail": jail})
    db.close()
    return jsonify({"success": True, "queued": True})


@app.route("/api/jails/<jail>/stop", methods=["POST"])
@require_auth
def api_stop_jail(jail):
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    queue_command(db, server.id, "stop", {"jail": jail})
    db.close()
    return jsonify({"success": True, "queued": True})


@app.route("/api/reload", methods=["POST"])
@require_auth
def api_reload():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    queue_command(db, server.id, "reload", {})
    db.close()
    return jsonify({"success": True, "queued": True})


@app.route("/api/intelligence")
@require_auth
def api_intelligence():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    jail = request.args.get("jail")
    result = load_intel(db, server.id, jail=jail)
    db.close()
    return jsonify(result)


@app.route("/api/ip/<ip>")
@require_auth
def api_ip_details(ip):
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    geo = get_geo(ip)
    abuse = get_abuse_score(ip)
    history = [b for b in load_bans(db, server.id) if b["ip"] == ip]
    db.close()
    return jsonify({
        "ip": ip, "geo": geo, "abuse": abuse,
        "ban_count": len(history), "ban_history": history[:20],
        "abuseipdb_url": f"https://www.abuseipdb.com/check/{ip}",
    })


@app.route("/api/ban_history")
@require_auth
def api_ban_history():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    jail = request.args.get("jail")
    limit = min(int(request.args.get("limit", 200)), 5000)
    data = load_bans(db, server.id, jail=jail, limit=limit)
    db.close()
    return jsonify({"bans": data, "total": len(data)})


@app.route("/api/export/csv")
@require_auth
def api_export_csv():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    jail = request.args.get("jail")
    data = load_bans(db, server.id, jail=jail, limit=5000)
    db.close()
    si = io.StringIO()
    w = csv.DictWriter(si, fieldnames=["ts", "ip", "jail", "country", "country_code", "city", "isp", "lat", "lon"])
    w.writeheader()
    w.writerows(data)
    return Response(si.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=ban_history.csv"})


@app.route("/api/export/json")
@require_auth
def api_export_json():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    jail = request.args.get("jail")
    data = load_bans(db, server.id, jail=jail, limit=5000)
    db.close()
    return Response(
        json.dumps({"exported": utcnow().isoformat(), "bans": data}, indent=2, default=str),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=ban_history.json"},
    )


@app.route("/api/network")
@require_auth
def api_network():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    history = load_net_history(db, server.id)
    current = history[-1] if history else {"rx": 0, "tx": 0}
    db.close()
    return jsonify({
        "current": {"rx_mbps": current.get("rx", 0), "tx_mbps": current.get("tx", 0)},
        "history": history,
    })


@app.route("/api/connections")
@require_auth
def api_connections():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    snap = db.query(ConnectionSnapshot).filter_by(server_id=server.id).first()
    conns = json.loads(snap.data) if snap and snap.data else []
    history = load_conn_history(db, server.id)
    db.close()
    return jsonify({"connections": conns, "history": history})


@app.route("/api/log")
@require_auth
def api_log():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    events = [e.to_dict() for e in
              db.query(EventLog).filter_by(server_id=server.id).order_by(EventLog.ts.desc()).limit(200)]
    db.close()
    return jsonify({"events": events})


# ── Autentificare panou ─────────────────────────────────────────────────────────

@app.route("/api/auth/login", methods=["POST"])
def api_auth_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "Utilizator și parolă obligatorii"}), 400
    db = get_db()
    user = db.query(PanelUser).filter_by(username=username, is_active=True).first()
    if not user or not verify_password(user, password):
        db.close()
        return jsonify({"error": "Utilizator sau parolă incorectă"}), 401
    client_ip = client_ip_from_request(request)
    if not check_ip_whitelist(db, client_ip):
        db.close()
        return jsonify({
            "error": "IP neautorizat pentru panou",
            "code": "ip_not_whitelisted",
            "client_ip": client_ip,
        }), 403
    if not login_requires_2fa(user):
        ip, ua = _session_meta()
        token, expires = create_panel_session(db, user.id, ip, ua)
        db.close()
        return jsonify(session_response(user, token, expires))
    method = user.two_fa_method
    challenge_token, code, expires = create_2fa_challenge(db, user, method, purpose="login")
    if method == "telegram":
        if not user.telegram_id:
            db.close()
            return jsonify({"error": "2FA Telegram neconfigurat"}), 500
        from telegram_bot import send_telegram_text
        sent = send_telegram_text(
            user.telegram_id,
            f"<b>NeoHost Security</b>\nCod autentificare: <code>{code}</code>\nValabil 5 minute.",
            db,
        )
        if not sent:
            db.close()
            return jsonify({"error": "Nu am putut trimite codul pe Telegram"}), 503
        db.close()
        return jsonify({
            "requires_2fa": True,
            "challenge_token": challenge_token,
            "method": "telegram",
            "expires_at": expires.isoformat(),
            "message": "Cod trimis pe Telegram",
        })
    db.close()
    return jsonify({
        "requires_2fa": True,
        "challenge_token": challenge_token,
        "method": "totp",
        "expires_at": expires.isoformat(),
        "message": "Introduceți codul din Google Authenticator",
    })


@app.route("/api/auth/verify-2fa", methods=["POST"])
def api_auth_verify_2fa():
    data = request.get_json(silent=True) or {}
    challenge_token = (data.get("challenge_token") or "").strip()
    code = (data.get("code") or "").strip()
    method = (data.get("method") or "").strip()
    if not challenge_token or not code:
        return jsonify({"error": "Cod 2FA obligatoriu"}), 400
    db = get_db()
    from models import TwoFaChallenge
    row = db.query(TwoFaChallenge).filter_by(token=challenge_token, purpose="login").first()
    if not row or row.expires_at < utcnow():
        db.close()
        return jsonify({"error": "Sesiune 2FA expirată"}), 401
    user = db.query(PanelUser).filter_by(id=row.user_id, is_active=True).first()
    if not user:
        db.close()
        return jsonify({"error": "Utilizator negăsit"}), 401
    use_method = method or row.method
    if not verify_2fa_challenge(db, challenge_token, user, code, use_method):
        db.close()
        return jsonify({"error": "Cod 2FA invalid"}), 401
    client_ip = client_ip_from_request(request)
    if not check_ip_whitelist(db, client_ip):
        db.close()
        return jsonify({
            "error": "IP neautorizat pentru panou",
            "code": "ip_not_whitelisted",
            "client_ip": client_ip,
        }), 403
    ip, ua = _session_meta()
    token, expires = create_panel_session(db, user.id, ip, ua)
    db.close()
    return jsonify(session_response(user, token, expires))


@app.route("/api/auth/logout", methods=["POST"])
@require_auth
def api_auth_logout():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        db = get_db()
        revoke_panel_session(db, auth[7:])
        db.close()
    return jsonify({"success": True})


# ── Profil / Telegram / Whitelist ─────────────────────────────────────────────

@app.route("/api/profile")
@require_auth
def api_profile():
    db = get_db()
    telegram_users = [u.to_dict() for u in db.query(TelegramUser).filter_by(is_active=True).all()]
    whitelist = [w.to_dict() for w in db.query(IpWhitelist).order_by(IpWhitelist.created_at.desc()).all()]
    client_ip = client_ip_from_request(request)
    bot_username = get_setting(db, "telegram_bot_username", "")
    tg_token = get_telegram_bot_token(db)
    webapp_url = get_telegram_webapp_url(db)
    enabled = is_whitelist_enabled(db)
    account = _account_user(db)
    account_data = account.to_dict(include_security=True) if account else None
    db.close()
    return jsonify({
        "client_ip": client_ip,
        "account": account_data,
        "settings": {
            "ip_whitelist_enabled": enabled,
            "telegram_configured": bool(tg_token),
            "telegram_bot_username": bot_username,
            "telegram_token_hint": mask_token(tg_token),
            "telegram_webapp_url": webapp_url,
            "telegram_token_from_env": bool(os.environ.get("TELEGRAM_BOT_TOKEN", "")),
        },
        "telegram_users": telegram_users,
        "whitelist": whitelist,
    })


@app.route("/api/profile/settings", methods=["PUT"])
@require_auth
def api_profile_settings():
    data = request.get_json(silent=True) or {}
    db = get_db()
    if "ip_whitelist_enabled" in data:
        set_setting(db, "ip_whitelist_enabled", "1" if data["ip_whitelist_enabled"] else "0")
    db.close()
    return jsonify({"success": True})


@app.route("/api/branding")
def api_branding_public():
    db = get_db()
    data = get_branding(db)
    db.close()
    return jsonify(data)


@app.route("/api/profile/branding", methods=["PUT"])
@require_auth
def api_profile_branding():
    data = request.get_json(silent=True) or {}
    db = get_db()
    user = _account_user(db)
    try:
        out = update_branding(db, data, user=user)
    except ValueError as exc:
        db.close()
        return jsonify({"error": str(exc)}), 400
    db.close()
    return jsonify({"success": True, "branding": out})


@app.route("/api/profile/branding/history")
@require_auth
def api_profile_branding_history():
    db = get_db()
    limit = request.args.get("limit", 30, type=int)
    rows = list_branding_history(db, limit=limit)
    db.close()
    return jsonify({"history": rows})


@app.route("/api/profile/notifications")
@require_auth
def api_profile_notifications_get():
    db = get_db()
    settings = get_notification_settings(db)
    db.close()
    return jsonify({"settings": settings})


@app.route("/api/profile/notifications", methods=["PUT"])
@require_auth
def api_profile_notifications_put():
    data = request.get_json(silent=True) or {}
    db = get_db()
    settings = update_notification_settings(db, data)
    db.close()
    return jsonify({"success": True, "settings": settings})


@app.route("/api/profile/sessions")
@require_auth
def api_profile_sessions():
    db = get_db()
    user = _account_user(db)
    if not user:
        db.close()
        return jsonify({"error": "Cont panou indisponibil"}), 403
    current = getattr(g, "panel_token", None)
    rows = list_user_sessions(db, user.id)
    sessions = []
    for s in rows:
        d = s.to_dict(mask_token=True)
        d["current"] = bool(current and s.token == current)
        d["token_id"] = s.token[:16]
        sessions.append(d)
    db.close()
    return jsonify({"sessions": sessions})


@app.route("/api/profile/sessions/<token_id>", methods=["DELETE"])
@require_auth
def api_profile_session_revoke(token_id):
    db = get_db()
    user = _account_user(db)
    if not user:
        db.close()
        return jsonify({"error": "Cont panou indisponibil"}), 403
    rows = list_user_sessions(db, user.id)
    target = next((s for s in rows if s.token.startswith(token_id) or s.token == token_id), None)
    if not target:
        db.close()
        return jsonify({"error": "Sesiune negăsită"}), 404
    revoke_session_token(db, user.id, target.token)
    db.close()
    return jsonify({"success": True})


@app.route("/api/profile/sessions/revoke-others", methods=["POST"])
@require_auth
def api_profile_sessions_revoke_others():
    db = get_db()
    user = _account_user(db)
    if not user:
        db.close()
        return jsonify({"error": "Cont panou indisponibil"}), 403
    keep = getattr(g, "panel_token", None)
    n = revoke_other_sessions(db, user.id, keep)
    db.close()
    return jsonify({"success": True, "revoked": n})


@app.route("/api/profile/account", methods=["PUT"])
@require_auth
def api_profile_account():
    data = request.get_json(silent=True) or {}
    current_password = data.get("current_password") or ""
    new_username = (data.get("new_username") or "").strip()
    new_password = data.get("new_password") or ""
    confirm_password = data.get("confirm_password") or ""
    if not current_password:
        return jsonify({"error": "Parola curentă obligatorie"}), 400
    db = get_db()
    user = _account_user(db)
    if not user:
        db.close()
        return jsonify({"error": "Cont panou indisponibil"}), 403
    if not verify_password(user, current_password):
        db.close()
        return jsonify({"error": "Parola curentă incorectă"}), 401
    if new_username and new_username != user.username:
        taken = db.query(PanelUser).filter_by(username=new_username).first()
        if taken and taken.id != user.id:
            db.close()
            return jsonify({"error": "Utilizatorul există deja"}), 400
        user.username = new_username
    if new_password:
        if new_password != confirm_password:
            db.close()
            return jsonify({"error": "Parolele noi nu coincid"}), 400
        if len(new_password) < 6:
            db.close()
            return jsonify({"error": "Parola nouă: minim 6 caractere"}), 400
        user.password_hash = hash_password(new_password)
    user.updated_at = utcnow()
    db.commit()
    username = user.username
    db.close()
    return jsonify({"success": True, "username": username})


@app.route("/api/profile/2fa/totp/setup", methods=["POST"])
@require_auth
def api_profile_2fa_totp_setup():
    data = request.get_json(silent=True) or {}
    current_password = data.get("current_password") or ""
    db = get_db()
    user = _account_user(db)
    if not user:
        db.close()
        return jsonify({"error": "Cont panou indisponibil"}), 403
    if not verify_password(user, current_password):
        db.close()
        return jsonify({"error": "Parola curentă incorectă"}), 401
    secret, uri = generate_totp_setup(user)
    user.totp_secret = secret
    user.updated_at = utcnow()
    db.commit()
    db.close()
    return jsonify({"secret": secret, "uri": uri})


@app.route("/api/profile/2fa/totp/enable", methods=["POST"])
@require_auth
def api_profile_2fa_totp_enable():
    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").strip()
    if not code:
        return jsonify({"error": "Cod obligatoriu"}), 400
    db = get_db()
    user = _account_user(db)
    if not user or not user.totp_secret:
        db.close()
        return jsonify({"error": "Configurați mai întâi TOTP"}), 400
    if not verify_totp_code(user, code):
        db.close()
        return jsonify({"error": "Cod TOTP invalid"}), 400
    user.two_fa_method = "totp"
    user.updated_at = utcnow()
    db.commit()
    db.close()
    return jsonify({"success": True, "two_fa_method": "totp"})


@app.route("/api/profile/2fa/telegram/send", methods=["POST"])
@require_auth
def api_profile_2fa_telegram_send():
    data = request.get_json(silent=True) or {}
    current_password = data.get("current_password") or ""
    telegram_user_id = data.get("telegram_user_id")
    if not current_password or not telegram_user_id:
        return jsonify({"error": "Parolă și cont Telegram obligatorii"}), 400
    db = get_db()
    user = _account_user(db)
    if not user:
        db.close()
        return jsonify({"error": "Cont panou indisponibil"}), 403
    if not verify_password(user, current_password):
        db.close()
        return jsonify({"error": "Parola curentă incorectă"}), 401
    tg = db.query(TelegramUser).filter_by(id=int(telegram_user_id), is_active=True).first()
    if not tg:
        db.close()
        return jsonify({"error": "Cont Telegram negăsit"}), 404
    challenge_token, code, expires = create_2fa_challenge(
        db, user, "telegram", purpose="enable_telegram"
    )
    from telegram_bot import send_telegram_text
    sent = send_telegram_text(
        tg.telegram_id,
        f"<b>NeoHost Security</b>\nCod activare 2FA: <code>{code}</code>",
        db,
    )
    if not sent:
        db.close()
        return jsonify({"error": "Nu am putut trimite codul pe Telegram"}), 503
    db.close()
    return jsonify({
        "challenge_token": challenge_token,
        "telegram_user_id": tg.id,
        "expires_at": expires.isoformat(),
    })


@app.route("/api/profile/2fa/telegram/enable", methods=["POST"])
@require_auth
def api_profile_2fa_telegram_enable():
    data = request.get_json(silent=True) or {}
    challenge_token = (data.get("challenge_token") or "").strip()
    code = (data.get("code") or "").strip()
    telegram_user_id = data.get("telegram_user_id")
    if not challenge_token or not code or not telegram_user_id:
        return jsonify({"error": "Date incomplete"}), 400
    db = get_db()
    user = _account_user(db)
    if not user:
        db.close()
        return jsonify({"error": "Cont panou indisponibil"}), 403
    if not verify_2fa_challenge(db, challenge_token, user, code, "telegram"):
        db.close()
        return jsonify({"error": "Cod invalid sau expirat"}), 400
    tg = db.query(TelegramUser).filter_by(id=int(telegram_user_id), is_active=True).first()
    if not tg:
        db.close()
        return jsonify({"error": "Cont Telegram negăsit"}), 404
    user.telegram_id = tg.telegram_id
    user.two_fa_method = "telegram"
    user.updated_at = utcnow()
    db.commit()
    db.close()
    return jsonify({"success": True, "two_fa_method": "telegram"})


@app.route("/api/profile/2fa/disable", methods=["POST"])
@require_auth
def api_profile_2fa_disable():
    data = request.get_json(silent=True) or {}
    current_password = data.get("current_password") or ""
    code = (data.get("code") or "").strip()
    challenge_token = (data.get("challenge_token") or "").strip()
    if not current_password:
        return jsonify({"error": "Parola curentă obligatorie"}), 400
    db = get_db()
    user = _account_user(db)
    if not user:
        db.close()
        return jsonify({"error": "Cont panou indisponibil"}), 403
    if not verify_password(user, current_password):
        db.close()
        return jsonify({"error": "Parola curentă incorectă"}), 401
    method = user.two_fa_method or "none"
    if method == "none":
        db.close()
        return jsonify({"error": "2FA nu este activ"}), 400
    if method == "totp":
        if not code or not verify_totp_code(user, code):
            db.close()
            return jsonify({"error": "Cod Google Authenticator obligatoriu"}), 400
    elif method == "telegram":
        if not challenge_token:
            if not user.telegram_id:
                db.close()
                return jsonify({"error": "Telegram 2FA neconfigurat"}), 400
            ct, otp, exp = create_2fa_challenge(db, user, "telegram", purpose="disable")
            from telegram_bot import send_telegram_text
            send_telegram_text(
                user.telegram_id,
                f"<b>NeoHost Security</b>\nCod dezactivare 2FA: <code>{otp}</code>",
                db,
            )
            db.close()
            return jsonify({
                "requires_code": True,
                "challenge_token": ct,
                "expires_at": exp.isoformat(),
            })
        if not code or not verify_2fa_challenge(db, challenge_token, user, code, "telegram"):
            db.close()
            return jsonify({"error": "Cod Telegram invalid"}), 400
    user.two_fa_method = "none"
    user.totp_secret = None
    user.telegram_id = None
    user.updated_at = utcnow()
    db.commit()
    db.close()
    return jsonify({"success": True, "two_fa_method": "none"})


@app.route("/api/profile/telegram/config", methods=["PUT"])
@require_auth
def api_profile_telegram_config():
    data = request.get_json(silent=True) or {}
    db = get_db()
    token = data.get("bot_token")
    webapp_url = data.get("webapp_url")
    if token is not None:
        token = str(token).strip()
        if token:
            set_setting(db, "telegram_bot_token", token)
        else:
            row = db.query(HubSetting).filter_by(key="telegram_bot_token").first()
            if row:
                db.delete(row)
                db.commit()
    if webapp_url is not None:
        webapp_url = str(webapp_url).strip().rstrip("/")
        if webapp_url:
            set_setting(db, "telegram_webapp_url", webapp_url)
        else:
            row = db.query(HubSetting).filter_by(key="telegram_webapp_url").first()
            if row:
                db.delete(row)
                db.commit()
    resolved_token = get_telegram_bot_token(db)
    resolved_webapp = get_telegram_webapp_url(db)
    bot_username = ""
    if resolved_token:
        try:
            import urllib.request as ur
            with ur.urlopen(f"https://api.telegram.org/bot{resolved_token}/getMe", timeout=10) as resp:
                me = json.loads(resp.read())
            bot_username = me.get("result", {}).get("username", "")
            if bot_username:
                set_setting(db, "telegram_bot_username", bot_username)
        except Exception:
            pass
    from telegram_bot import reload_telegram_bot
    reload_telegram_bot(resolved_token, resolved_webapp)
    if resolved_token and resolved_webapp:
        try:
            body = json.dumps({
                "menu_button": {
                    "type": "web_app",
                    "text": "Panou NeoHost",
                    "web_app": {"url": resolved_webapp},
                },
            }).encode()
            req = urllib.request.Request(
                f"https://api.telegram.org/bot{resolved_token}/setChatMenuButton",
                data=body,
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception:
            pass
    db.close()
    return jsonify({
        "success": True,
        "telegram_configured": bool(resolved_token),
        "telegram_bot_username": bot_username,
        "telegram_token_hint": mask_token(resolved_token),
        "telegram_webapp_url": resolved_webapp,
    })


@app.route("/api/profile/telegram/code", methods=["POST"])
@require_auth
def api_profile_telegram_code():
    db = get_db()
    code, expires = generate_link_code(db)
    bot_username = get_setting(db, "telegram_bot_username", "")
    db.close()
    return jsonify({
        "code": code,
        "expires_at": expires.isoformat(),
        "bot_username": bot_username,
    })


@app.route("/api/profile/telegram/<int:uid>", methods=["DELETE"])
@require_auth
def api_profile_telegram_unlink(uid):
    db = get_db()
    user = db.query(TelegramUser).filter_by(id=uid).first()
    if user:
        user.is_active = False
        db.commit()
    db.close()
    return jsonify({"success": True})


@app.route("/api/profile/whitelist", methods=["GET"])
@require_auth
def api_profile_whitelist_list():
    db = get_db()
    items = [w.to_dict() for w in db.query(IpWhitelist).order_by(IpWhitelist.created_at.desc()).all()]
    db.close()
    return jsonify({"whitelist": items})


@app.route("/api/profile/whitelist", methods=["POST"])
@require_auth
def api_profile_whitelist_add():
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "IP obligatoriu"}), 400
    db = get_db()
    existing = db.query(IpWhitelist).filter_by(ip=ip).first()
    if existing:
        db.close()
        return jsonify({"error": "IP deja în listă"}), 409
    entry = IpWhitelist(ip=ip, label=(data.get("label") or "").strip())
    db.add(entry)
    db.commit()
    result = entry.to_dict()
    db.close()
    return jsonify({"entry": result}), 201


@app.route("/api/profile/whitelist/<int:wid>", methods=["DELETE"])
@require_auth
def api_profile_whitelist_delete(wid):
    db = get_db()
    entry = db.query(IpWhitelist).filter_by(id=wid).first()
    if entry:
        db.delete(entry)
        db.commit()
    db.close()
    return jsonify({"success": True})


# ── CSF Firewall ──────────────────────────────────────────────────────────────

@app.route("/api/csf")
@require_auth
def api_csf():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    snap = db.query(CsfSnapshot).filter_by(server_id=server.id).first()
    data = json.loads(snap.data) if snap and snap.data else {"installed": False}
    data["updated_at"] = snap.updated_at.isoformat() if snap and snap.updated_at else None
    data["mod_enabled"] = bool(server.mod_csf)
    db.close()
    return jsonify({"csf": data})


@app.route("/api/csf/deny", methods=["POST"])
@require_auth
def api_csf_deny():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    if not server.mod_csf:
        db.close()
        return jsonify({"error": "CSF dezactivat pentru acest server"}), 400
    ip = (request.get_json(silent=True) or {}).get("ip", "").strip()
    if not ip:
        db.close()
        return jsonify({"error": "IP lipsă"}), 400
    queue_command(db, server.id, "csf_deny", {"ip": ip})
    db.close()
    return jsonify({"success": True, "queued": True})


@app.route("/api/csf/allow", methods=["POST"])
@require_auth
def api_csf_allow():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    if not server.mod_csf:
        db.close()
        return jsonify({"error": "CSF dezactivat pentru acest server"}), 400
    ip = (request.get_json(silent=True) or {}).get("ip", "").strip()
    if not ip:
        db.close()
        return jsonify({"error": "IP lipsă"}), 400
    queue_command(db, server.id, "csf_allow", {"ip": ip})
    db.close()
    return jsonify({"success": True, "queued": True})


@app.route("/api/csf/remove", methods=["POST"])
@require_auth
def api_csf_remove():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    if not server.mod_csf:
        db.close()
        return jsonify({"error": "CSF dezactivat pentru acest server"}), 400
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    list_type = data.get("list", "deny")
    if not ip:
        db.close()
        return jsonify({"error": "IP lipsă"}), 400
    action = "csf_remove_allow" if list_type == "allow" else "csf_remove_deny"
    queue_command(db, server.id, action, {"ip": ip})
    db.close()
    return jsonify({"success": True, "queued": True})


@app.route("/api/csf/restart", methods=["POST"])
@require_auth
def api_csf_restart():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    if not server.mod_csf:
        db.close()
        return jsonify({"error": "CSF dezactivat pentru acest server"}), 400
    queue_command(db, server.id, "csf_restart", {})
    db.close()
    return jsonify({"success": True, "queued": True})


@app.route("/api/csf/toggle", methods=["POST"])
@require_auth
def api_csf_toggle():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    if not server.mod_csf:
        db.close()
        return jsonify({"error": "CSF dezactivat pentru acest server"}), 400
    data = request.get_json(silent=True) or {}
    key = (data.get("key") or "").strip()
    if not key:
        db.close()
        return jsonify({"error": "key obligatoriu"}), 400
    queue_command(db, server.id, "csf_toggle", {"key": key, "enabled": bool(data.get("enabled"))})
    db.close()
    return jsonify({"success": True, "queued": True})


@app.route("/api/csf/firewall", methods=["POST"])
@require_auth
def api_csf_firewall():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    if not server.mod_csf:
        db.close()
        return jsonify({"error": "CSF dezactivat pentru acest server"}), 400
    enabled = bool((request.get_json(silent=True) or {}).get("enabled"))
    action = "csf_enable" if enabled else "csf_disable"
    queue_command(db, server.id, action, {})
    db.close()
    return jsonify({"success": True, "queued": True})


@app.route("/api/csf/port", methods=["POST"])
@require_auth
def api_csf_port():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    if not server.mod_csf:
        db.close()
        return jsonify({"error": "CSF dezactivat pentru acest server"}), 400
    data = request.get_json(silent=True) or {}
    list_key = (data.get("list") or "TCP_IN").strip()
    port = str(data.get("port", "")).strip()
    if not port:
        db.close()
        return jsonify({"error": "port obligatoriu"}), 400
    queue_command(db, server.id, "csf_port", {
        "list": list_key,
        "port": port,
        "enabled": bool(data.get("enabled")),
    })
    db.close()
    return jsonify({"success": True, "queued": True})


# ── nftables Firewall ─────────────────────────────────────────────────────────

@app.route("/api/nftables")
@require_auth
def api_nftables():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    snap = db.query(NftablesSnapshot).filter_by(server_id=server.id).first()
    data = json.loads(snap.data) if snap and snap.data else {"installed": False}
    data["updated_at"] = snap.updated_at.isoformat() if snap and snap.updated_at else None
    data["mod_enabled"] = bool(server.mod_nftables)
    db.close()
    return jsonify({"nftables": data})


@app.route("/api/nftables/deny", methods=["POST"])
@require_auth
def api_nftables_deny():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    if not server.mod_nftables:
        db.close()
        return jsonify({"error": "nftables dezactivat pentru acest server"}), 400
    ip = (request.get_json(silent=True) or {}).get("ip", "").strip()
    if not ip:
        db.close()
        return jsonify({"error": "IP lipsă"}), 400
    queue_command(db, server.id, "nft_deny", {"ip": ip})
    db.close()
    return jsonify({"success": True, "queued": True})


@app.route("/api/nftables/allow", methods=["POST"])
@require_auth
def api_nftables_allow():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    if not server.mod_nftables:
        db.close()
        return jsonify({"error": "nftables dezactivat pentru acest server"}), 400
    ip = (request.get_json(silent=True) or {}).get("ip", "").strip()
    if not ip:
        db.close()
        return jsonify({"error": "IP lipsă"}), 400
    queue_command(db, server.id, "nft_allow", {"ip": ip})
    db.close()
    return jsonify({"success": True, "queued": True})


@app.route("/api/nftables/remove", methods=["POST"])
@require_auth
def api_nftables_remove():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    if not server.mod_nftables:
        db.close()
        return jsonify({"error": "nftables dezactivat pentru acest server"}), 400
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    list_type = data.get("list", "deny")
    if not ip:
        db.close()
        return jsonify({"error": "IP lipsă"}), 400
    queue_command(db, server.id, "nft_remove", {"ip": ip, "list": list_type})
    db.close()
    return jsonify({"success": True, "queued": True})


@app.route("/api/nftables/reload", methods=["POST"])
@require_auth
def api_nftables_reload():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    if not server.mod_nftables:
        db.close()
        return jsonify({"error": "nftables dezactivat pentru acest server"}), 400
    queue_command(db, server.id, "nft_reload", {})
    db.close()
    return jsonify({"success": True, "queued": True})


@app.route("/api/nftables/firewall", methods=["POST"])
@require_auth
def api_nftables_firewall():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    if not server.mod_nftables:
        db.close()
        return jsonify({"error": "nftables dezactivat pentru acest server"}), 400
    enabled = bool((request.get_json(silent=True) or {}).get("enabled"))
    action = "nft_enable" if enabled else "nft_disable"
    queue_command(db, server.id, action, {})
    db.close()
    return jsonify({"success": True, "queued": True})


@app.route("/api/nftables/chain-policy", methods=["POST"])
@require_auth
def api_nftables_chain_policy():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    if not server.mod_nftables:
        db.close()
        return jsonify({"error": "nftables dezactivat pentru acest server"}), 400
    data = request.get_json(silent=True) or {}
    chain = (data.get("chain") or "input").strip()
    policy = (data.get("policy") or "drop").strip()
    if policy not in ("accept", "drop"):
        db.close()
        return jsonify({"error": "policy invalidă"}), 400
    queue_command(db, server.id, "nft_chain_policy", {"chain": chain, "policy": policy})
    db.close()
    return jsonify({"success": True, "queued": True})


@app.route("/api/nftables/set", methods=["POST"])
@require_auth
def api_nftables_set():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    if not server.mod_nftables:
        db.close()
        return jsonify({"error": "nftables dezactivat pentru acest server"}), 400
    data = request.get_json(silent=True) or {}
    set_name = (data.get("set") or "").strip()
    ip = (data.get("ip") or "").strip()
    if not set_name or not ip:
        db.close()
        return jsonify({"error": "set și ip obligatorii"}), 400
    queue_command(db, server.id, "nft_set", {
        "set": set_name,
        "ip": ip,
        "remove": bool(data.get("remove")),
    })
    db.close()
    return jsonify({"success": True, "queued": True})


@app.route("/api/nftables/flush", methods=["POST"])
@require_auth
def api_nftables_flush():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    if not server.mod_nftables:
        db.close()
        return jsonify({"error": "nftables dezactivat pentru acest server"}), 400
    set_name = ((request.get_json(silent=True) or {}).get("set") or "").strip()
    if not set_name:
        db.close()
        return jsonify({"error": "set obligatoriu"}), 400
    queue_command(db, server.id, "nft_flush", {"set": set_name})
    db.close()
    return jsonify({"success": True, "queued": True})


@app.route("/api/nftables/rule", methods=["POST"])
@require_auth
def api_nftables_rule():
    ctx, err = _sid_required()
    if err:
        return err
    server, db = ctx
    if not server.mod_nftables:
        db.close()
        return jsonify({"error": "nftables dezactivat pentru acest server"}), 400
    data = request.get_json(silent=True) or {}
    if data.get("delete"):
        handle = data.get("handle")
        if not handle:
            db.close()
            return jsonify({"error": "handle obligatoriu"}), 400
        queue_command(db, server.id, "nft_delete_rule", {
            "handle": handle,
            "chain": data.get("chain", "input"),
        })
    else:
        chain = (data.get("chain") or "input").strip()
        expr = (data.get("expr") or "").strip()
        if not expr:
            db.close()
            return jsonify({"error": "expr obligatoriu"}), 400
        queue_command(db, server.id, "nft_add_rule", {"chain": chain, "expr": expr})
    db.close()
    return jsonify({"success": True, "queued": True})


@app.route("/api/telegram/webapp-auth", methods=["POST"])
def api_telegram_webapp_auth():
    db = get_db()
    bot_token = get_telegram_bot_token(db)
    if not bot_token:
        db.close()
        return jsonify({"error": "Bot Telegram neconfigurat"}), 503
    data = request.get_json(silent=True) or {}
    init_data = data.get("init_data", "")
    tg_user = validate_telegram_init_data(init_data, bot_token)
    if not tg_user:
        return jsonify({"error": "init_data invalid"}), 401
    db = get_db()
    linked = db.query(TelegramUser).filter_by(telegram_id=tg_user["id"], is_active=True).first()
    if not linked:
        db.close()
        return jsonify({"error": "Cont Telegram neconectat. Folosiți /link în bot."}), 403
    token, expires = create_telegram_web_session(db, tg_user["id"])
    servers = [s.to_dict() for s in db.query(Server).filter_by(is_active=True).order_by(Server.name)]
    db.close()
    return jsonify({
        "access_token": token,
        "expires_at": expires.isoformat(),
        "user": linked.to_dict(),
        "servers": servers,
    })


@app.route("/api/status")
def api_status():
    db = get_db()
    server_count = db.query(Server).count()
    db.close()
    return jsonify({
        "status": "ok",
        "ts": utcnow().isoformat(),
        "version": "3.0",
        "mode": "hub",
        "servers": server_count,
    })


@sock.route("/ws")
def ws_handler(ws):
    try:
        raw = ws.receive(timeout=5)
        if not raw:
            return
        msg = json.loads(raw)
        token = msg.get("token", "")
        db = get_db()
        if not _ws_token_ok(db, token):
            db.close()
            ws.send(json.dumps({"type": "error", "message": "Unauthorized"}))
            return
        server_id = msg.get("server_id")
        if not server_id:
            db.close()
            ws.send(json.dumps({"type": "error", "message": "server_id obligatoriu"}))
            return
        server = db.query(Server).filter_by(id=server_id).first()
        if not server:
            db.close()
            ws.send(json.dumps({"type": "error", "message": "Server negăsit"}))
            return
        ws.send(json.dumps({"type": "auth", "message": "ok"}))
        intel = load_intel(db, server.id)
        ws.send(json.dumps({
            "type": "history",
            "net_history": load_net_history(db, server.id),
            "conn_history": load_conn_history(db, server.id),
            "events": [e.to_dict() for e in
                       db.query(EventLog).filter_by(server_id=server.id).order_by(EventLog.ts.desc()).limit(30)],
            "ban_history": load_bans(db, server.id, limit=100),
            "intelligence": intel,
        }, default=str))
        db.close()
        with ws_lock:
            ws_clients[ws] = server_id
        while True:
            data = ws.receive(timeout=30)
            if data is None:
                break
    except Exception:
        pass
    finally:
        with ws_lock:
            ws_clients.pop(ws, None)


def cleanup_old_metrics():
    while True:
        try:
            db = get_db()
            cutoff = utcnow() - timedelta(hours=METRIC_RETENTION_HOURS)
            db.query(NetworkMetric).filter(NetworkMetric.ts < cutoff).delete()
            db.query(ConnectionMetric).filter(ConnectionMetric.ts < cutoff).delete()
            db.commit()
            db.close()
        except Exception:
            pass
        import time
        time.sleep(3600)


def _cache_telegram_bot_username():
    db = get_db()
    token = get_telegram_bot_token(db)
    webapp = get_telegram_webapp_url(db)
    db.close()
    if not token:
        return
    try:
        import urllib.request as ur
        with ur.urlopen(f"https://api.telegram.org/bot{token}/getMe", timeout=10) as resp:
            data = json.loads(resp.read())
        username = data.get("result", {}).get("username", "")
        if username:
            db = get_db()
            set_setting(db, "telegram_bot_username", username)
            db.close()
        if webapp:
            body = json.dumps({
                "menu_button": {
                    "type": "web_app",
                    "text": "Panou NeoHost",
                    "web_app": {"url": webapp},
                },
            }).encode()
            req = urllib.request.Request(
                f"https://api.telegram.org/bot{token}/setChatMenuButton",
                data=body,
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


def _start_services():
    threading.Thread(target=cleanup_old_metrics, daemon=True).start()
    db = get_db()
    token = get_telegram_bot_token(db)
    webapp = get_telegram_webapp_url(db)
    db.close()
    _cache_telegram_bot_username()
    if token:
        from telegram_bot import reload_telegram_bot
        reload_telegram_bot(token, webapp)


init_db(app)
_start_services()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7654))
    host = os.environ.get("HOST", "127.0.0.1")
    if API_TOKEN == "schimba-acest-token-secret":
        print("[NeoHost] ATENȚIE: token implicit activ! Setați SECURITY_API_TOKEN.")
    print(f"[NeoHost] Security Hub v3 pe {host}:{port}")
    app.run(host=host, port=port, debug=False, threaded=True)
