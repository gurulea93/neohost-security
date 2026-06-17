"""Analiză securitate per server — recomandări + șabloane aplicabile."""

CRITICAL_JAILS = {
    "sshd": "f2b-sshd",
    "nginx-http-auth": "f2b-nginx-http-auth",
    "postfix-sasl": "f2b-postfix-sasl",
    "recidive": "f2b-recidive",
}

CSF_CHECKS = [
    ("testing", "csf-hardening-base", "CSF rulează în mod TESTING — blocările nu sunt reale."),
    ("firewall_disabled", "csf-hardening-base", "Firewall CSF este dezactivat."),
    ("lf_sshd_off", "csf-hardening-base", "LF_SSHD este dezactivat — fără protecție SSH la nivel CSF."),
]


def run_security_audit(server, f2b, csf, intel, nft=None):
    findings = []
    score = 100
    jail_names = {j.get("name") for j in (f2b or {}).get("jails", [])}
    active_jails = {j.get("name") for j in (f2b or {}).get("jails", []) if j.get("active")}

    if server.mod_fail2ban:
        if not f2b or not f2b.get("installed"):
            findings.append({
                "id": "f2b_missing",
                "severity": "high",
                "title": "Fail2Ban neinstalat",
                "detail": "Agentul nu detectează Fail2Ban pe acest server.",
                "template_slug": "f2b-sshd",
            })
            score -= 25
        else:
            if not f2b.get("running"):
                findings.append({
                    "id": "f2b_stopped",
                    "severity": "critical",
                    "title": "Fail2Ban oprit",
                    "detail": "Serviciul Fail2Ban nu rulează.",
                    "template_slug": None,
                })
                score -= 30
            for jail, slug in CRITICAL_JAILS.items():
                if jail not in jail_names:
                    findings.append({
                        "id": f"missing_jail_{jail}",
                        "severity": "high",
                        "title": f"Jail lipsă: {jail}",
                        "detail": f"Jailul critic «{jail}» nu este configurat.",
                        "template_slug": slug,
                    })
                    score -= 12
                elif jail not in active_jails:
                    findings.append({
                        "id": f"inactive_jail_{jail}",
                        "severity": "medium",
                        "title": f"Jail inactiv: {jail}",
                        "detail": f"Jailul «{jail}» există dar nu este pornit.",
                        "template_slug": None,
                    })
                    score -= 8

    if server.mod_csf and csf:
        if csf.get("installed"):
            toggles = csf.get("toggles") or {}
            if toggles.get("TESTING"):
                findings.append({
                    "id": "csf_testing",
                    "severity": "critical",
                    "title": "CSF în mod TESTING",
                    "detail": CSF_CHECKS[0][2],
                    "template_slug": "csf-hardening-base",
                })
                score -= 20
            if not csf.get("firewall_enabled", True):
                findings.append({
                    "id": "csf_fw_off",
                    "severity": "critical",
                    "title": "Firewall CSF dezactivat",
                    "detail": CSF_CHECKS[1][2],
                    "template_slug": "csf-hardening-base",
                })
                score -= 25
            if toggles.get("LF_SSHD") is False:
                findings.append({
                    "id": "csf_lf_sshd",
                    "severity": "high",
                    "title": "LF_SSHD dezactivat",
                    "detail": CSF_CHECKS[2][2],
                    "template_slug": "csf-hardening-base",
                })
                score -= 15
        elif server.cap_csf:
            findings.append({
                "id": "csf_not_running",
                "severity": "medium",
                "title": "CSF nefuncțional",
                "detail": "Modulul CSF este activ în panou dar agentul nu raportează CSF.",
                "template_slug": None,
            })
            score -= 10

    if server.mod_nftables and nft:
        if nft.get("installed"):
            if not nft.get("running"):
                findings.append({
                    "id": "nft_stopped",
                    "severity": "critical",
                    "title": "nftables oprit",
                    "detail": "Serviciul nftables nu rulează — regulile nu sunt active.",
                    "template_slug": "nft-hardening-base",
                })
                score -= 25
            chains = nft.get("chains") or {}
            input_policy = (chains.get("input") or {}).get("policy", "")
            if input_policy and input_policy != "drop":
                findings.append({
                    "id": "nft_input_policy",
                    "severity": "high",
                    "title": "Policy input permisiv",
                    "detail": f"Lanțul input are policy «{input_policy}» — recomandat drop cu excepții.",
                    "template_slug": "nft-hardening-base",
                })
                score -= 15
            deny_count = nft.get("deny_count", 0)
            if deny_count == 0 and (intel or {}).get("threat", {}).get("level") in ("HIGH", "CRITICAL"):
                findings.append({
                    "id": "nft_empty_deny",
                    "severity": "medium",
                    "title": "Listă deny goală",
                    "detail": "Nicio adresă în setul de blocare nftables, deși amenințarea este ridicată.",
                    "template_slug": None,
                })
                score -= 8
        elif server.cap_nftables:
            findings.append({
                "id": "nft_not_running",
                "severity": "medium",
                "title": "nftables nefuncțional",
                "detail": "Modulul nftables este activ în panou dar agentul nu raportează nftables.",
                "template_slug": None,
            })
            score -= 10

    threat = (intel or {}).get("threat") or {}
    level = threat.get("level", "LOW")
    if level in ("HIGH", "CRITICAL"):
        findings.append({
            "id": "threat_elevated",
            "severity": "high" if level == "HIGH" else "critical",
            "title": f"Amenințare {level}",
            "detail": threat.get("recommendation", "Activitate suspectă ridicată."),
            "template_slug": "f2b-recidive",
        })
        score -= 15 if level == "HIGH" else 25

    score = max(0, min(100, score))
    grade = "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 30 else "F"

    return {
        "score": score,
        "grade": grade,
        "findings": findings,
        "summary": {
            "jails_total": len(jail_names),
            "jails_active": len(active_jails),
            "threat_level": level,
            "csf_testing": bool((csf or {}).get("toggles", {}).get("TESTING")),
            "nft_running": bool((nft or {}).get("running")),
        },
    }
