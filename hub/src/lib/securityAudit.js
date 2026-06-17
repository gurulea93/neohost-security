const CRITICAL_JAILS = {
  sshd: "f2b-sshd",
  "nginx-http-auth": "f2b-nginx-http-auth",
  "postfix-sasl": "f2b-postfix-sasl",
  recidive: "f2b-recidive"
};

export function runSecurityAudit(server, f2b, csf, intel, nft = {}) {
  const findings = [];
  let score = 100;
  const jails = new Set((f2b?.jails || []).map((j) => j.name));
  const active = new Set((f2b?.jails || []).filter((j) => j.active).map((j) => j.name));

  if (server.mod_fail2ban) {
    if (!f2b?.installed) {
      findings.push({ id: "f2b_missing", severity: "high", title: "Fail2Ban neinstalat", detail: "Agentul nu detectează Fail2Ban pe acest server.", template_slug: "f2b-sshd" });
      score -= 25;
    } else if (!f2b.running) {
      findings.push({ id: "f2b_stopped", severity: "critical", title: "Fail2Ban oprit", detail: "Serviciul Fail2Ban nu rulează.", template_slug: null });
      score -= 30;
    }
    for (const [jail, slug] of Object.entries(CRITICAL_JAILS)) {
      if (!jails.has(jail)) {
        findings.push({ id: `missing_jail_${jail}`, severity: "high", title: `Jail lipsă: ${jail}`, detail: `Jailul critic «${jail}» nu este configurat.`, template_slug: slug });
        score -= 12;
      } else if (!active.has(jail)) {
        findings.push({ id: `inactive_jail_${jail}`, severity: "medium", title: `Jail inactiv: ${jail}`, detail: `Jailul «${jail}» există dar nu este pornit.`, template_slug: null });
        score -= 8;
      }
    }
  }
  if (server.mod_csf && csf?.installed) {
    const toggles = csf.toggles || {};
    if (toggles.TESTING) {
      findings.push({ id: "csf_testing", severity: "critical", title: "CSF în mod TESTING", detail: "CSF rulează în mod TESTING — blocările nu sunt reale.", template_slug: "csf-hardening-base" });
      score -= 20;
    }
    if (csf.firewall_enabled === false) {
      findings.push({ id: "csf_fw_off", severity: "critical", title: "Firewall CSF dezactivat", detail: "Firewall CSF este dezactivat.", template_slug: "csf-hardening-base" });
      score -= 25;
    }
    if (toggles.LF_SSHD === false) {
      findings.push({ id: "csf_lf_sshd", severity: "high", title: "LF_SSHD dezactivat", detail: "LF_SSHD este dezactivat — fără protecție SSH la nivel CSF.", template_slug: "csf-hardening-base" });
      score -= 15;
    }
  }
  if (server.mod_nftables && nft?.installed) {
    if (!nft.running) {
      findings.push({ id: "nft_stopped", severity: "critical", title: "nftables oprit", detail: "Serviciul nftables nu rulează — regulile nu sunt active.", template_slug: "nft-hardening-base" });
      score -= 25;
    }
    const input = nft?.chains?.input?.policy || "";
    if (input && input !== "drop") {
      findings.push({ id: "nft_input_policy", severity: "high", title: "Policy input permisiv", detail: `Lanțul input are policy «${input}» — recomandat drop cu excepții.`, template_slug: "nft-hardening-base" });
      score -= 15;
    }
  }

  const level = intel?.threat?.level || "LOW";
  if (level === "HIGH" || level === "CRITICAL") {
    findings.push({
      id: "threat_elevated",
      severity: level === "HIGH" ? "high" : "critical",
      title: `Amenințare ${level}`,
      detail: intel?.threat?.recommendation || "Activitate suspectă ridicată.",
      template_slug: "f2b-recidive"
    });
    score -= level === "HIGH" ? 15 : 25;
  }
  score = Math.max(0, Math.min(100, score));
  const grade = score >= 85 ? "A" : score >= 70 ? "B" : score >= 50 ? "C" : score >= 30 ? "D" : "F";
  return {
    score,
    grade,
    findings,
    summary: {
      jails_total: jails.size,
      jails_active: active.size,
      threat_level: level,
      csf_testing: !!csf?.toggles?.TESTING,
      nft_running: !!nft?.running
    }
  };
}
