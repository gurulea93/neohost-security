#!/usr/bin/env python3
"""
NeoHost Security Agent — rulează pe fiecare server Linux administrat.
Colectează date Fail2Ban și le trimite către Hub-ul central.
"""

import json
import os
import re
import socket
import time
import urllib.error
import urllib.request
from datetime import datetime

from collector import (
    collect_snapshot, f2b_ban, f2b_unban, f2b_start_jail, f2b_stop_jail, f2b_reload,
    f2b_add_jail, f2b_remove_jail,
    csf_deny, csf_allow, csf_remove_deny, csf_remove_allow, csf_restart,
    csf_set_toggle, csf_enable, csf_disable, csf_toggle_port, csf_apply_preset,
    nft_allow, nft_deny, nft_remove, nft_reload, nft_enable, nft_disable,
    nft_add_to_set, nft_remove_from_set, nft_flush_set, nft_add_rule, nft_delete_rule,
    nft_set_chain_policy, nft_apply_preset,
    f2b_installed,
)

HUB_URL = os.environ.get("HUB_URL", "http://127.0.0.1:7654").rstrip("/")
AGENT_KEY = os.environ.get("AGENT_KEY", "")
INTERVAL = float(os.environ.get("AGENT_INTERVAL", "5"))
HOSTNAME = os.environ.get("AGENT_HOSTNAME", socket.gethostname())

_seen_bans = set()


def hub_request(method, path, data=None):
    url = f"{HUB_URL}{path}"
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(
        url, data=body, method=method,
        headers={"Content-Type": "application/json", "X-Agent-Key": AGENT_KEY},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def ingest_log_bans():
    log_path = "/var/log/fail2ban.log"
    if not os.path.exists(log_path):
        return []
    pattern = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*Ban\s+([\d\.:a-fA-F]+)")
    bans = []
    try:
        with open(log_path) as f:
            lines = f.readlines()[-500:]
    except Exception:
        return []
    for line in reversed(lines):
        m = pattern.search(line)
        if not m:
            continue
        ts_str, ip = m.group(1), m.group(2)
        key = f"{ts_str}:{ip}"
        if key in _seen_bans:
            continue
        _seen_bans.add(key)
        jm = re.search(r"\[([^\]]+)\]", line)
        jail = jm.group(1) if jm else "unknown"
        try:
            ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").isoformat()
        except Exception:
            ts = datetime.now().isoformat()
        bans.append({"ts": ts, "ip": ip, "jail": jail})
        if len(bans) >= 50:
            break
    return bans


def execute_command(cmd):
    action = cmd.get("action")
    payload = cmd.get("payload", {})
    cid = cmd.get("id")
    success = False
    try:
        if action == "ban":
            success = f2b_ban(payload.get("ip", ""), payload.get("jail", "sshd"))
        elif action == "unban":
            success = f2b_unban(payload.get("ip", ""), payload.get("jail", "sshd"))
        elif action == "start":
            f2b_start_jail(payload.get("jail", "sshd"))
            success = True
        elif action == "stop":
            f2b_stop_jail(payload.get("jail", "sshd"))
            success = True
        elif action == "reload":
            f2b_reload()
            success = True
        elif action == "f2b_add_jail":
            success = f2b_add_jail(payload.get("config") or payload)
        elif action == "f2b_remove_jail":
            success = f2b_remove_jail(payload.get("jail_name") or payload.get("jail", ""))
        elif action == "csf_apply_preset":
            success = csf_apply_preset(payload.get("preset") or payload)
        elif action == "csf_deny":
            success = csf_deny(payload.get("ip", ""))
        elif action == "csf_allow":
            success = csf_allow(payload.get("ip", ""))
        elif action == "csf_remove_deny":
            success = csf_remove_deny(payload.get("ip", ""))
        elif action == "csf_remove_allow":
            success = csf_remove_allow(payload.get("ip", ""))
        elif action == "csf_restart":
            success = csf_restart()
        elif action == "csf_toggle":
            success = csf_set_toggle(payload.get("key", ""), bool(payload.get("enabled")))
        elif action == "csf_enable":
            success = csf_enable()
        elif action == "csf_disable":
            success = csf_disable()
        elif action == "csf_port":
            success = csf_toggle_port(
                payload.get("list", "TCP_IN"),
                payload.get("port", ""),
                bool(payload.get("enabled")),
            )
        elif action == "nft_apply_preset":
            success = nft_apply_preset(payload.get("preset") or payload)
        elif action == "nft_allow":
            success = nft_allow(payload.get("ip", ""))
        elif action == "nft_deny":
            success = nft_deny(payload.get("ip", ""))
        elif action == "nft_remove":
            success = nft_remove(payload.get("ip", ""), payload.get("list", "deny"))
        elif action == "nft_reload":
            success = nft_reload()
        elif action == "nft_enable":
            success = nft_enable()
        elif action == "nft_disable":
            success = nft_disable()
        elif action == "nft_set":
            set_name = payload.get("set", "")
            ip = payload.get("ip", "")
            if payload.get("remove"):
                success = nft_remove_from_set(set_name, ip)
            else:
                success = nft_add_to_set(set_name, ip)
        elif action == "nft_flush":
            success = nft_flush_set(payload.get("set", ""))
        elif action == "nft_add_rule":
            success = nft_add_rule(payload.get("chain", "input"), payload.get("expr", ""))
        elif action == "nft_delete_rule":
            success = nft_delete_rule(payload.get("handle"), payload.get("chain", "input"))
        elif action == "nft_chain_policy":
            success = nft_set_chain_policy(payload.get("chain", "input"), payload.get("policy", "drop"))
    except Exception:
        success = False
    if cid:
        try:
            hub_request("POST", f"/api/agent/commands/{cid}/done", {"success": success})
        except Exception:
            pass
    return success


def poll_commands():
    try:
        data = hub_request("GET", "/api/agent/commands")
        for cmd in data.get("commands", []):
            execute_command(cmd)
    except Exception:
        pass


def report():
    snap = collect_snapshot()
    bans = ingest_log_bans() if f2b_installed() else []
    payload = {
        "hostname": HOSTNAME,
        "fail2ban": snap.get("fail2ban", {}),
        "jails": snap["jails"],
        "net": snap["net"],
        "connections": snap["connections"],
        "csf": snap.get("csf", {}),
        "nftables": snap.get("nftables", {}),
        "capabilities": snap.get("capabilities", {}),
        "bans": bans,
        "events": [],
    }
    hub_request("POST", "/api/agent/report", payload)


def main():
    if not AGENT_KEY:
        print("[Agent] EROARE: setați AGENT_KEY (din dashboard → Servere)")
        raise SystemExit(1)
    print(f"[Agent] Conectat la {HUB_URL} | hostname={HOSTNAME} | interval={INTERVAL}s")
    while True:
        try:
            poll_commands()
            report()
        except urllib.error.HTTPError as e:
            print(f"[Agent] HTTP {e.code}: {e.reason}")
        except Exception as e:
            print(f"[Agent] Eroare: {e}")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
