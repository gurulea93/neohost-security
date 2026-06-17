"""Calcule threat intelligence din liste de bannuri."""

from collections import defaultdict
from datetime import datetime, timedelta


def compute_threat_level(ban_times):
    now = datetime.utcnow()
    bans_hr = sum(1 for t in ban_times if (now - t).total_seconds() < 3600)
    last_min = sum(1 for t in ban_times if (now - t).total_seconds() < 60)
    if bans_hr == 0:
        level, rec = "LOW", "Trafic normal. Nicio acțiune necesară."
    elif bans_hr < 10:
        level, rec = "LOW", "Activitate normală de scanare. Monitorizare standard."
    elif bans_hr < 50:
        level, rec = "MEDIUM", "Activitate suspectă detectată. Verificați jailurile active."
    elif bans_hr < 200:
        level, rec = "HIGH", "Atac în desfășurare! Considerați blocarea /24 sau CSF."
    else:
        level, rec = "CRITICAL", "Atac DDoS masiv! Activați modul CSFDENY sau contactați datacenter."
    return {"level": level, "bans_hr": bans_hr, "bans_last_min": last_min, "recommendation": rec}


def compute_top_attackers(bans, limit=10):
    counts = defaultdict(lambda: {"count": 0, "jails": set(), "country": "", "country_code": "", "isp": ""})
    for b in bans:
        ip = b["ip"]
        counts[ip]["count"] += 1
        counts[ip]["jails"].add(b["jail"])
        if b.get("country"):
            counts[ip]["country"] = b["country"]
            counts[ip]["country_code"] = b.get("country_code", "")
            counts[ip]["isp"] = b.get("isp", "")
    return [
        {"ip": ip, "count": d["count"], "jails": list(d["jails"]),
         "country": d["country"], "country_code": d["country_code"], "isp": d["isp"]}
        for ip, d in sorted(counts.items(), key=lambda x: x[1]["count"], reverse=True)[:limit]
    ]


def compute_country_stats(bans):
    counts = defaultdict(lambda: {
        "count": 0, "country": "", "lat": 0, "lon": 0, "code": "",
        "ip_counts": defaultdict(int),
        "jail_counts": defaultdict(int),
        "isp_counts": defaultdict(int),
    })
    for b in bans:
        cc = b.get("country_code") or "XX"
        entry = counts[cc]
        entry["count"] += 1
        if b.get("country"):
            entry["country"] = b["country"]
            entry["code"] = cc
        if b.get("lat"):
            entry["lat"] = b["lat"]
            entry["lon"] = b["lon"]
        ip = b.get("ip")
        if ip:
            entry["ip_counts"][ip] += 1
        jail = b.get("jail")
        if jail:
            entry["jail_counts"][jail] += 1
        isp = b.get("isp")
        if isp:
            entry["isp_counts"][isp] += 1
    return [
        {
            "code": cc,
            "country": d["country"],
            "count": d["count"],
            "lat": d["lat"],
            "lon": d["lon"],
            "unique_ips": len(d["ip_counts"]),
            "ips": [
                {"ip": ip, "count": c}
                for ip, c in sorted(d["ip_counts"].items(), key=lambda x: x[1], reverse=True)[:30]
            ],
            "jails": [
                {"name": j, "count": c}
                for j, c in sorted(d["jail_counts"].items(), key=lambda x: x[1], reverse=True)[:8]
            ],
            "isps": [
                {"name": isp, "count": c}
                for isp, c in sorted(d["isp_counts"].items(), key=lambda x: x[1], reverse=True)[:5]
            ],
        }
        for cc, d in sorted(counts.items(), key=lambda x: x[1]["count"], reverse=True)
    ]


def compute_jail_stats(bans):
    counts = defaultdict(int)
    for b in bans:
        counts[b["jail"]] += 1
    return [{"jail": j, "count": c} for j, c in sorted(counts.items(), key=lambda x: x[1], reverse=True)]


def compute_ban_timeline(bans):
    now = datetime.utcnow()
    buckets = defaultdict(int)
    for b in bans:
        try:
            ts = b["ts"] if isinstance(b["ts"], datetime) else datetime.fromisoformat(str(b["ts"]))
            if (now - ts).total_seconds() <= 86400:
                buckets[ts.strftime("%H:00")] += 1
        except Exception:
            pass
    result = []
    for i in range(23, -1, -1):
        t = now - timedelta(hours=i)
        result.append({"hour": t.strftime("%H:00"), "count": buckets.get(t.strftime("%H:00"), 0)})
    return result
