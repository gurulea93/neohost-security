"""Colectare locală Fail2Ban / CSF / nftables / rețea — folosit de agent pe fiecare server."""

import json
import os
import re
import subprocess
import time


def run_cmd(cmd, timeout=5):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return r.stdout.strip()
    except Exception:
        return ""


def f2b_installed():
    return bool(run_cmd(["which", "fail2ban-client"], timeout=3)) or os.path.isfile("/usr/bin/fail2ban-client")


def f2b_get_jails():
    if not f2b_installed():
        return []
    raw = run_cmd(["fail2ban-client", "status"])
    m = re.search(r"Jail list:\s+(.+)", raw)
    return [j.strip() for j in m.group(1).split(",")] if m else []


def f2b_get_jail_status(jail):
    raw = run_cmd(["fail2ban-client", "status", jail])
    if not raw:
        return {
            "name": jail, "active": False,
            "currently_banned": 0, "total_banned": 0,
            "currently_failed": 0, "total_failed": 0, "banned_ips": [],
        }

    def ei(p):
        m = re.search(p, raw)
        return int(m.group(1)) if m else 0

    def el(p):
        m = re.search(p, raw)
        return [x.strip() for x in m.group(1).split()] if m else []

    return {
        "name": jail, "active": True,
        "currently_banned": ei(r"Currently banned:\s+(\d+)"),
        "total_banned": ei(r"Total banned:\s+(\d+)"),
        "currently_failed": ei(r"Currently failed:\s+(\d+)"),
        "total_failed": ei(r"Total failed:\s+(\d+)"),
        "banned_ips": el(r"Banned IP list:\s+(.+)"),
    }


def collect_fail2ban():
    if not f2b_installed():
        return {
            "installed": False, "running": False, "jails": [],
            "jail_count": 0, "active_jails": 0, "total_banned": 0,
        }
    raw = run_cmd(["fail2ban-client", "status"])
    running = bool(raw) and "Number of jail" in raw
    jails = [f2b_get_jail_status(j) for j in f2b_get_jails()]
    return {
        "installed": True,
        "running": running,
        "jail_count": len(jails),
        "active_jails": sum(1 for j in jails if j.get("active")),
        "total_banned": sum(j.get("currently_banned", 0) for j in jails),
        "jails": jails,
    }


def f2b_ban(ip, jail):
    if not f2b_installed():
        return False
    return bool(run_cmd(["fail2ban-client", "set", jail, "banip", ip], timeout=10))


def f2b_unban(ip, jail):
    if not f2b_installed():
        return False
    return bool(run_cmd(["fail2ban-client", "set", jail, "unbanip", ip], timeout=10))


def f2b_start_jail(jail):
    if f2b_installed():
        run_cmd(["fail2ban-client", "start", jail], timeout=10)


def f2b_stop_jail(jail):
    if f2b_installed():
        run_cmd(["fail2ban-client", "stop", jail], timeout=10)


def f2b_reload():
    if f2b_installed():
        run_cmd(["fail2ban-client", "reload"], timeout=15)


NEOHOST_JAIL_DIR = "/etc/fail2ban/jail.d"
NEOHOST_JAIL_PREFIX = "neohost-"


def f2b_managed_jail_path(jail_name):
    return f"{NEOHOST_JAIL_DIR}/{NEOHOST_JAIL_PREFIX}{jail_name}.conf"


def f2b_add_jail(config):
    if not f2b_installed() or not config:
        return False
    jail_name = config.get("jail_name") or config.get("name")
    if not jail_name:
        return False
    try:
        os.makedirs(NEOHOST_JAIL_DIR, exist_ok=True)
        lines = [f"[{jail_name}]"]
        skip = {"jail_name", "name"}
        for key, val in config.items():
            if key in skip:
                continue
            lines.append(f"{key} = {val}")
        with open(f2b_managed_jail_path(jail_name), "w") as f:
            f.write("\n".join(lines) + "\n")
        f2b_reload()
        f2b_start_jail(jail_name)
        return True
    except OSError:
        return False


def f2b_remove_jail(jail_name):
    if not jail_name:
        return False
    path = f2b_managed_jail_path(jail_name)
    if not os.path.isfile(path):
        return False
    try:
        f2b_stop_jail(jail_name)
        os.remove(path)
        f2b_reload()
        return True
    except OSError:
        return False


def f2b_list_managed_jails():
    if not os.path.isdir(NEOHOST_JAIL_DIR):
        return []
    out = []
    for name in os.listdir(NEOHOST_JAIL_DIR):
        if name.startswith(NEOHOST_JAIL_PREFIX) and name.endswith(".conf"):
            out.append(name[len(NEOHOST_JAIL_PREFIX):-5])
    return out


def csf_apply_preset(preset):
    if not _csf_installed() or not preset:
        return False
    try:
        for key, val in (preset.get("toggles") or {}).items():
            csf_set_toggle(key, bool(val))
        for list_key, ports in (preset.get("ports") or {}).items():
            if list_key in CSF_PORT_LISTS and isinstance(ports, list):
                _csf_write_value(list_key, ",".join(str(p) for p in ports))
        if preset.get("enable_firewall"):
            csf_enable()
        if preset.get("restart", True):
            csf_restart()
        return True
    except Exception:
        return False


def get_net_stats():
    try:
        with open("/proc/net/dev") as f:
            lines = f.readlines()
    except OSError:
        return {}
    stats = {}
    for line in lines[2:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        iface = parts[0].rstrip(":")
        if iface == "lo":
            continue
        stats[iface] = {"rx_bytes": int(parts[1]), "tx_bytes": int(parts[9])}
    return stats


_prev_net = {}
_prev_ts = 0.0


def compute_net_speed():
    global _prev_net, _prev_ts
    now = time.time()
    current = get_net_stats()
    if not _prev_net or not current:
        _prev_net = current
        _prev_ts = now
        return {"rx_mbps": 0.0, "tx_mbps": 0.0, "interfaces": []}
    elapsed = max(now - _prev_ts, 0.1)
    total_rx = total_tx = 0.0
    ifaces = []
    for iface, vals in current.items():
        prev = _prev_net.get(iface, {})
        rx = max(0, vals["rx_bytes"] - prev.get("rx_bytes", 0)) / elapsed / 1_048_576
        tx = max(0, vals["tx_bytes"] - prev.get("tx_bytes", 0)) / elapsed / 1_048_576
        total_rx += rx
        total_tx += tx
        ifaces.append({"name": iface, "rx_mbps": round(rx, 2), "tx_mbps": round(tx, 2)})
    _prev_net = current
    _prev_ts = now
    return {"rx_mbps": round(total_rx, 2), "tx_mbps": round(total_tx, 2), "interfaces": ifaces}


def get_active_connections():
    raw = run_cmd(["ss", "-tunp", "--no-header"], timeout=5)
    seen = {}
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        proto = parts[0]
        state = parts[1] if proto != "udp" else "UDP"
        remote = parts[5]
        if remote in ("*:*", "0.0.0.0:*", ":::*"):
            continue
        if remote.startswith("["):
            m = re.match(r"\[(.+)\]:(\d+)", remote)
            if not m:
                continue
            ip, port = m.group(1), int(m.group(2))
        elif ":" in remote:
            r = remote.rsplit(":", 1)
            ip, port = r[0], int(r[1])
        else:
            continue
        if ip in ("127.0.0.1", "::1", "0.0.0.0"):
            continue
        if ip in seen:
            seen[ip]["count"] += 1
        else:
            seen[ip] = {
                "ip": ip, "port": port, "proto": proto.upper(),
                "state": state, "count": 1,
                "country": "", "country_code": "",
            }
    conns = list(seen.values())[:50]
    for c in conns:
        c["rps"] = c["count"]
    return conns


def collect_snapshot():
    f2b = collect_fail2ban()
    csf = csf_collect()
    nft = nft_collect()
    net = compute_net_speed()
    conns = get_active_connections()
    return {
        "fail2ban": f2b,
        "jails": f2b["jails"],
        "csf": csf,
        "nftables": nft,
        "net": net,
        "connections": conns,
        "capabilities": {
            "fail2ban": f2b["installed"],
            "csf": csf.get("installed", False),
            "nftables": nft.get("installed", False),
        },
    }


# ── CSF Firewall ──────────────────────────────────────────────────────────────

CSF_CONF = "/etc/csf/csf.conf"
CSF_DENY = "/etc/csf/csf.deny"
CSF_ALLOW = "/etc/csf/csf.allow"
CSF_TEMPBAN = "/var/lib/csf/csf.tempban"
CSF_TEMPALLOW = "/var/lib/csf/csf.tempallow"

CSF_TOGGLES = {
    "TESTING": "Mod test (nu blochează efectiv)",
    "IPV6": "Suport IPv6",
    "LF_SSHD": "Protecție brute-force SSH",
    "LF_FTPD": "Protecție FTP",
    "LF_SMTPAUTH": "Protecție SMTP auth",
    "LF_POP3D": "Protecție POP3",
    "LF_IMAPD": "Protecție IMAP",
    "LF_HTACCESS": "Protecție htaccess",
    "LF_MODSEC": "Protecție ModSecurity",
    "LF_BIND": "Protecție BIND/named",
    "LF_SUHOSIN": "Protecție Suhosin",
    "LF_CPANEL": "Protecție cPanel",
    "LF_EXIMSCAN": "Protecție Exim scan",
    "SYNFLOOD": "Protecție SYN flood",
    "CONNLIMIT": "Limită conexiuni per IP",
    "PORTFLOOD": "Protecție port flood",
    "UDPFLOOD": "Protecție UDP flood",
    "PT_ALL_USERS": "Process tracking — toți userii",
    "PT_USERPROC": "Process tracking — procese/user",
    "ICMP_IN": "Permite ICMP inbound (ping)",
    "ICMP_OUT": "Permite ICMP outbound",
    "RESTRICT_SYSLOG": "Restricționează syslog",
    "LF_CLI": "Detectare login CLI",
}

CSF_PORT_LISTS = ("TCP_IN", "TCP_OUT", "UDP_IN", "UDP_OUT")

CSF_PORT_CATALOG = {
    "TCP_IN": {
        "20": "FTP-DATA", "21": "FTP", "22": "SSH", "25": "SMTP", "53": "DNS",
        "80": "HTTP", "110": "POP3", "143": "IMAP", "443": "HTTPS", "465": "SMTPS",
        "587": "SMTP-TLS", "993": "IMAPS", "995": "POP3S", "3306": "MySQL",
        "8080": "HTTP-ALT", "8443": "HTTPS-ALT", "2082": "cPanel", "2083": "cPanel-SSL",
        "2086": "WHM", "2087": "WHM-SSL",
    },
    "TCP_OUT": {
        "20": "FTP-DATA", "21": "FTP", "22": "SSH", "25": "SMTP", "53": "DNS",
        "80": "HTTP", "110": "POP3", "143": "IMAP", "443": "HTTPS", "465": "SMTPS",
        "587": "SMTP-TLS", "993": "IMAPS", "995": "POP3S", "3306": "MySQL",
    },
    "UDP_IN": {
        "53": "DNS", "123": "NTP", "161": "SNMP",
    },
    "UDP_OUT": {
        "53": "DNS", "123": "NTP",
    },
}


def _csf_installed():
    return bool(run_cmd(["which", "csf"], timeout=3)) or os.path.isfile("/usr/sbin/csf")


def _read_csf_file(path):
    ips = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                ip = line.split()[0].split("|")[0]
                if ip:
                    ips.append(ip)
    except OSError:
        pass
    return ips


def _parse_csf_bool(val):
    return str(val).strip().strip('"').lower() in ("1", "on", "yes", "true")


def _csf_read_raw_value(key):
    if not _csf_installed():
        return ""
    try:
        with open(CSF_CONF) as f:
            content = f.read()
    except OSError:
        return ""
    m = re.search(rf'^{re.escape(key)}\s*=\s*"?([^"\n#]+)"?', content, re.MULTILINE)
    return m.group(1).strip().strip('"') if m else ""


def _csf_write_value(key, value):
    try:
        with open(CSF_CONF) as f:
            lines = f.readlines()
        pattern = re.compile(rf'^({re.escape(key)}\s*=\s*)["\']?[^"\'\n#]*["\']?')
        found = False
        new_lines = []
        for line in lines:
            if pattern.match(line):
                new_lines.append(f'{key} = "{value}"\n')
                found = True
            else:
                new_lines.append(line)
        if not found:
            new_lines.append(f'{key} = "{value}"\n')
        with open(CSF_CONF, "w") as f:
            f.writelines(new_lines)
        return True
    except OSError:
        return False


def _parse_port_list(raw):
    ports = set()
    for part in raw.replace(" ", "").split(","):
        if not part or ":" in part or "/" in part:
            continue
        if part.isdigit():
            ports.add(part)
    return ports


def csf_read_ports():
    result = {}
    for key in CSF_PORT_LISTS:
        raw = _csf_read_raw_value(key)
        result[key] = sorted(_parse_port_list(raw), key=lambda p: int(p))
    return result


def csf_ports_state():
    """Return port -> enabled for catalog + any extra ports in config."""
    open_ports = csf_read_ports()
    state = {}
    for list_key in CSF_PORT_LISTS:
        catalog = CSF_PORT_CATALOG.get(list_key, {})
        open_set = set(open_ports.get(list_key, []))
        all_ports = set(catalog.keys()) | open_set
        state[list_key] = {
            "open": sorted(open_set, key=lambda p: int(p)),
            "ports": [
                {
                    "port": p,
                    "label": catalog.get(p, "Custom"),
                    "enabled": p in open_set,
                }
                for p in sorted(all_ports, key=lambda p: int(p) if p.isdigit() else 0)
            ],
        }
    return state


def csf_toggle_port(list_key, port, enabled):
    if list_key not in CSF_PORT_LISTS or not _csf_installed():
        return False
    port = str(port).strip()
    if not port.isdigit():
        return False
    current = _parse_port_list(_csf_read_raw_value(list_key))
    if enabled:
        current.add(port)
    else:
        current.discard(port)
    new_val = ",".join(sorted(current, key=lambda p: int(p)))
    if not _csf_write_value(list_key, new_val):
        return False
    run_cmd(["csf", "-r"], timeout=30)
    return True


def csf_read_toggles():
    toggles = {k: False for k in CSF_TOGGLES}
    if not _csf_installed():
        return toggles
    try:
        with open(CSF_CONF) as f:
            content = f.read()
    except OSError:
        return toggles
    for key in CSF_TOGGLES:
        m = re.search(rf'^{re.escape(key)}\s*=\s*"?([^"\n#]+)"?', content, re.MULTILINE)
        if m:
            toggles[key] = _parse_csf_bool(m.group(1))
    return toggles


def csf_firewall_running():
    if not _csf_installed():
        return False
    out = run_cmd(["csf", "-l"], timeout=8).lower()
    return "not running" not in out and ("chain input" in out or "csf is enabled" in out)


def csf_set_toggle(key, enabled):
    if key not in CSF_TOGGLES or not _csf_installed():
        return False
    val = "1" if enabled else "0"
    if not _csf_write_value(key, val):
        return False
    run_cmd(["csf", "-r"], timeout=30)
    return True


def csf_collect():
    if not _csf_installed():
        return {
            "installed": False, "enabled": False,
            "deny": [], "allow": [], "temp_deny": [], "temp_allow": [],
            "toggles": {}, "toggle_labels": CSF_TOGGLES, "ports": {},
        }
    temp_deny = _read_csf_file(CSF_TEMPBAN)
    temp_allow = _read_csf_file(CSF_TEMPALLOW)
    toggles = csf_read_toggles()
    running = csf_firewall_running()
    return {
        "installed": True,
        "enabled": running,
        "testing_mode": toggles.get("TESTING", False),
        "deny": _read_csf_file(CSF_DENY),
        "allow": _read_csf_file(CSF_ALLOW),
        "temp_deny": temp_deny,
        "temp_allow": temp_allow,
        "deny_count": len(_read_csf_file(CSF_DENY)) + len(temp_deny),
        "allow_count": len(_read_csf_file(CSF_ALLOW)) + len(temp_allow),
        "toggles": toggles,
        "toggle_labels": CSF_TOGGLES,
        "ports": csf_ports_state(),
    }


def csf_deny(ip):
    if not _csf_installed():
        return False
    return bool(run_cmd(["csf", "-d", ip], timeout=15))


def csf_allow(ip):
    if not _csf_installed():
        return False
    return bool(run_cmd(["csf", "-a", ip], timeout=15))


def csf_remove_deny(ip):
    if _csf_installed():
        run_cmd(["csf", "-dr", ip], timeout=15)
    return True


def csf_remove_allow(ip):
    if _csf_installed():
        run_cmd(["csf", "-ar", ip], timeout=15)
    return True


def csf_restart():
    if _csf_installed():
        run_cmd(["csf", "-r"], timeout=30)
    return True


def csf_enable():
    if _csf_installed():
        run_cmd(["csf", "-e"], timeout=15)
    return True


def csf_disable():
    if _csf_installed():
        run_cmd(["csf", "-x"], timeout=15)
    return True


# ── nftables ────────────────────────────────────────────────────────────────────

NEOHOST_NFT_FAMILY = "inet"
NEOHOST_NFT_TABLE = "neohost"
NEOHOST_NFT_ALLOW = "neohost_allow"
NEOHOST_NFT_DENY = "neohost_deny"
NEOHOST_NFT_CONF = "/etc/nftables.conf"

NEOHOST_NFT_CHAINS = {
    "input": {"type": "filter", "hook": "input", "priority": 0, "policy": "drop"},
    "forward": {"type": "filter", "hook": "forward", "priority": 0, "policy": "drop"},
    "output": {"type": "filter", "hook": "output", "priority": 0, "policy": "accept"},
}


def _nft_installed():
    return bool(run_cmd(["which", "nft"], timeout=3)) or os.path.isfile("/usr/sbin/nft")


def _nft_json(args, timeout=20):
    raw = run_cmd(["nft", "-j"] + args, timeout=timeout)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def _nft_service_running():
    out = run_cmd(["systemctl", "is-active", "nftables"], timeout=5).lower()
    if out in ("active", "activating"):
        return True
    raw = run_cmd(["nft", "list", "ruleset"], timeout=8)
    return bool(raw.strip())


def _nft_ensure_managed():
    if not _nft_installed():
        return False
    table_ref = f"{NEOHOST_NFT_FAMILY} {NEOHOST_NFT_TABLE}"
    if not run_cmd(["nft", "list", "table", NEOHOST_NFT_FAMILY, NEOHOST_NFT_TABLE], timeout=8):
        run_cmd(["nft", "add", "table", NEOHOST_NFT_FAMILY, NEOHOST_NFT_TABLE], timeout=8)
    for chain, cfg in NEOHOST_NFT_CHAINS.items():
        if not run_cmd(["nft", "list", "chain", table_ref, chain], timeout=8):
            run_cmd([
                "nft", "add", "chain", NEOHOST_NFT_FAMILY, NEOHOST_NFT_TABLE, chain,
                "{", "type", cfg["type"], "hook", cfg["hook"],
                "priority", str(cfg["priority"]), ";", "policy", cfg["policy"], ";", "}",
            ], timeout=8)
    for set_name in (NEOHOST_NFT_ALLOW, NEOHOST_NFT_DENY):
        if not run_cmd(["nft", "list", "set", table_ref, set_name], timeout=8):
            run_cmd([
                "nft", "add", "set", NEOHOST_NFT_FAMILY, NEOHOST_NFT_TABLE, set_name,
                "{", "type", "ipv4_addr", ";", "flags", "interval", ";", "}",
            ], timeout=8)
    _nft_ensure_base_rules()
    return True


def _nft_ensure_base_rules():
    table_ref = f"{NEOHOST_NFT_FAMILY} {NEOHOST_NFT_TABLE}"
    raw = run_cmd(["nft", "-a", "list", "chain", table_ref, "input"], timeout=10)
    if raw and NEOHOST_NFT_ALLOW in raw and NEOHOST_NFT_DENY in raw:
        return
    run_cmd([
        "nft", "insert", "rule", NEOHOST_NFT_FAMILY, NEOHOST_NFT_TABLE, "input",
        "ct", "state", "established,related", "accept",
    ], timeout=8)
    run_cmd([
        "nft", "insert", "rule", NEOHOST_NFT_FAMILY, NEOHOST_NFT_TABLE, "input",
        "iif", "lo", "accept",
    ], timeout=8)
    run_cmd([
        "nft", "add", "rule", NEOHOST_NFT_FAMILY, NEOHOST_NFT_TABLE, "input",
        "ip", "saddr", "@", NEOHOST_NFT_ALLOW, "accept",
    ], timeout=8)
    run_cmd([
        "nft", "add", "rule", NEOHOST_NFT_FAMILY, NEOHOST_NFT_TABLE, "input",
        "ip", "saddr", "@", NEOHOST_NFT_DENY, "drop",
    ], timeout=8)
    for port in ("22", "80", "443"):
        run_cmd([
            "nft", "add", "rule", NEOHOST_NFT_FAMILY, NEOHOST_NFT_TABLE, "input",
            "tcp", "dport", port, "accept",
        ], timeout=8)


def _nft_parse_set_elements(set_obj):
    elements = []
    for elem in set_obj.get("elem", []) or []:
        if isinstance(elem, dict):
            val = elem.get("elem", {}).get("val")
            if isinstance(val, str):
                elements.append(val)
            elif isinstance(val, dict):
                prefix = val.get("prefix", {})
                addr = prefix.get("addr")
                if addr:
                    length = prefix.get("len")
                    elements.append(f"{addr}/{length}" if length else addr)
        elif isinstance(elem, str):
            elements.append(elem)
    return elements


def _nft_parse_ruleset(data):
    tables = []
    total_packets = total_bytes = 0
    allow_ips = []
    deny_ips = []
    for nft_obj in (data or {}).get("nftables", []):
        if "table" in nft_obj:
            tbl = nft_obj["table"]
            family = tbl.get("family", "")
            name = tbl.get("name", "")
            table_entry = {"family": family, "name": name, "chains": [], "sets": []}
            tables.append(table_entry)
            continue
        if "chain" in nft_obj:
            ch = nft_obj["chain"]
            if not tables:
                continue
            table_entry = tables[-1]
            table_entry["chains"].append({
                "name": ch.get("name", ""),
                "type": ch.get("type", ""),
                "hook": ch.get("hook", ""),
                "policy": ch.get("policy", ""),
                "rules": [],
            })
            continue
        if "rule" in nft_obj:
            rule = nft_obj["rule"]
            if not tables or not tables[-1]["chains"]:
                continue
            chain = tables[-1]["chains"][-1]
            expr = rule.get("expr", [])
            expr_text = _nft_expr_to_text(expr)
            packets = bytes_ = 0
            for part in expr:
                if "counter" in part:
                    ctr = part["counter"]
                    packets = ctr.get("packets", 0)
                    bytes_ = ctr.get("bytes", 0)
                    total_packets += packets
                    total_bytes += bytes_
            chain["rules"].append({
                "handle": rule.get("handle"),
                "expr": expr_text,
                "packets": packets,
                "bytes": bytes_,
            })
            continue
        if "set" in nft_obj:
            st = nft_obj["set"]
            if not tables:
                continue
            set_name = st.get("name", "")
            elements = _nft_parse_set_elements(st)
            tables[-1]["sets"].append({
                "name": set_name,
                "type": st.get("type", ""),
                "elements": elements,
                "size": len(elements),
            })
            if set_name == NEOHOST_NFT_ALLOW:
                allow_ips = elements
            elif set_name == NEOHOST_NFT_DENY:
                deny_ips = elements
    return tables, allow_ips, deny_ips, total_packets, total_bytes


def _nft_expr_to_text(expr):
    parts = []
    for part in expr or []:
        if "match" in part:
            m = part["match"]
            left = m.get("left", {})
            right = m.get("right", "")
            if left.get("payload"):
                proto = left["payload"].get("protocol", "")
                field = left["payload"].get("field", "")
                parts.append(f"{proto} {field} {right}".strip())
            elif left.get("meta"):
                parts.append(f"meta {left['meta'].get('key', '')} {right}".strip())
            else:
                parts.append(str(right))
        elif "counter" in part:
            ctr = part["counter"]
            parts.append(f"counter packets {ctr.get('packets', 0)} bytes {ctr.get('bytes', 0)}")
        elif "accept" in part:
            parts.append("accept")
        elif "drop" in part:
            parts.append("drop")
        elif "jump" in part:
            parts.append(f"jump {part['jump'].get('target', '')}")
        elif "lookup" in part:
            lk = part["lookup"]
            parts.append(f"lookup @{lk.get('set', '')}")
        else:
            parts.append(next(iter(part.keys()), ""))
    return " ".join(p for p in parts if p)


def nft_collect():
    if not _nft_installed():
        return {
            "installed": False, "running": False,
            "tables": [], "allow": [], "deny": [],
            "allow_count": 0, "deny_count": 0,
            "managed_sets": {"allow": NEOHOST_NFT_ALLOW, "deny": NEOHOST_NFT_DENY},
            "stats": {"total_packets": 0, "total_bytes": 0, "table_count": 0, "rule_count": 0, "set_count": 0},
            "ruleset_source": NEOHOST_NFT_CONF,
            "chains": {},
        }
    running = _nft_service_running()
    data = _nft_json(["list", "ruleset"])
    if data:
        tables, allow_ips, deny_ips, total_packets, total_bytes = _nft_parse_ruleset(data)
    else:
        tables, allow_ips, deny_ips, total_packets, total_bytes = [], [], [], 0, 0
    rule_count = sum(len(c.get("rules", [])) for t in tables for c in t.get("chains", []))
    set_count = sum(len(t.get("sets", [])) for t in tables)
    chains = {}
    for t in tables:
        if t.get("name") == NEOHOST_NFT_TABLE:
            for ch in t.get("chains", []):
                chains[ch["name"]] = {
                    "policy": ch.get("policy", ""),
                    "hook": ch.get("hook", ""),
                    "rule_count": len(ch.get("rules", [])),
                }
    return {
        "installed": True,
        "running": running,
        "tables": tables,
        "allow": allow_ips,
        "deny": deny_ips,
        "allow_count": len(allow_ips),
        "deny_count": len(deny_ips),
        "managed_sets": {"allow": NEOHOST_NFT_ALLOW, "deny": NEOHOST_NFT_DENY},
        "stats": {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "table_count": len(tables),
            "rule_count": rule_count,
            "set_count": set_count,
        },
        "ruleset_source": NEOHOST_NFT_CONF if os.path.isfile(NEOHOST_NFT_CONF) else "",
        "chains": chains,
    }


def nft_reload():
    if not _nft_installed():
        return False
    if os.path.isfile(NEOHOST_NFT_CONF):
        ok = bool(run_cmd(["nft", "-f", NEOHOST_NFT_CONF], timeout=20))
        _nft_ensure_managed()
        return ok
    run_cmd(["systemctl", "reload", "nftables"], timeout=20)
    _nft_ensure_managed()
    return True


def nft_enable():
    if not _nft_installed():
        return False
    run_cmd(["systemctl", "enable", "--now", "nftables"], timeout=15)
    _nft_ensure_managed()
    return _nft_service_running()


def nft_disable():
    if not _nft_installed():
        return False
    run_cmd(["systemctl", "stop", "nftables"], timeout=15)
    run_cmd(["nft", "flush", "ruleset"], timeout=15)
    return True


def nft_add_to_set(set_name, ip):
    if not _nft_installed() or not ip:
        return False
    _nft_ensure_managed()
    table_ref = f"{NEOHOST_NFT_FAMILY} {NEOHOST_NFT_TABLE}"
    return bool(run_cmd(["nft", "add", "element", table_ref, set_name, "{", ip, "}"], timeout=10))


def nft_remove_from_set(set_name, ip):
    if not _nft_installed() or not ip:
        return False
    table_ref = f"{NEOHOST_NFT_FAMILY} {NEOHOST_NFT_TABLE}"
    return bool(run_cmd(["nft", "delete", "element", table_ref, set_name, "{", ip, "}"], timeout=10))


def nft_allow(ip):
    nft_remove_from_set(NEOHOST_NFT_DENY, ip)
    return nft_add_to_set(NEOHOST_NFT_ALLOW, ip)


def nft_deny(ip):
    nft_remove_from_set(NEOHOST_NFT_ALLOW, ip)
    return nft_add_to_set(NEOHOST_NFT_DENY, ip)


def nft_remove(ip, list_type="deny"):
    set_name = NEOHOST_NFT_ALLOW if list_type == "allow" else NEOHOST_NFT_DENY
    return nft_remove_from_set(set_name, ip)


def nft_flush_set(set_name):
    if not _nft_installed():
        return False
    table_ref = f"{NEOHOST_NFT_FAMILY} {NEOHOST_NFT_TABLE}"
    run_cmd(["nft", "flush", "set", table_ref, set_name], timeout=10)
    return True


def nft_add_rule(chain, expr):
    if not _nft_installed() or not chain or not expr:
        return False
    _nft_ensure_managed()
    parts = expr.split()
    return bool(run_cmd(
        ["nft", "add", "rule", NEOHOST_NFT_FAMILY, NEOHOST_NFT_TABLE, chain] + parts,
        timeout=10,
    ))


def nft_delete_rule(handle, chain="input"):
    if not _nft_installed() or not handle:
        return False
    return bool(run_cmd([
        "nft", "delete", "rule", NEOHOST_NFT_FAMILY, NEOHOST_NFT_TABLE, chain, "handle", str(handle),
    ], timeout=10))


def nft_set_chain_policy(chain, policy):
    if not _nft_installed() or chain not in NEOHOST_NFT_CHAINS:
        return False
    if policy not in ("accept", "drop"):
        return False
    return bool(run_cmd([
        "nft", "chain", NEOHOST_NFT_FAMILY, NEOHOST_NFT_TABLE, chain,
        "{", "policy", policy, ";", "}",
    ], timeout=10))


def nft_apply_preset(preset):
    if not _nft_installed() or not preset:
        return False
    try:
        _nft_ensure_managed()
        for ip in preset.get("allow") or []:
            nft_allow(str(ip))
        for ip in preset.get("deny") or []:
            nft_deny(str(ip))
        for chain, policy in (preset.get("chain_policies") or {}).items():
            nft_set_chain_policy(chain, policy)
        for rule in preset.get("rules") or []:
            nft_add_rule(rule.get("chain", "input"), rule.get("expr", ""))
        open_ports = preset.get("open_ports") or []
        for port in open_ports:
            nft_add_rule("input", f"tcp dport {port} accept")
        if preset.get("enable"):
            nft_enable()
        if preset.get("reload", True):
            nft_reload()
        return True
    except Exception:
        return False
