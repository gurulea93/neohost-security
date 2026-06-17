import { useState, useEffect } from "react";
import { FormSelect } from "./components/ui/form-select";

const API = "";

export default function TelegramApp() {
  const [token, setToken] = useState(null);
  const [servers, setServers] = useState([]);
  const [serverId, setServerId] = useState(null);
  const [status, setStatus] = useState(null);
  const [csf, setCsf] = useState(null);
  const [nft, setNft] = useState(null);
  const [error, setError] = useState("");
  const [banIp, setBanIp] = useState("");
  const [nftIp, setNftIp] = useState("");
  const [msg, setMsg] = useState("");

  useEffect(() => {
    const tg = window.Telegram?.WebApp;
    if (tg) {
      tg.ready();
      tg.expand();
      document.documentElement.classList.add("dark");
    }
    const initData = tg?.initData || "";
    if (!initData) {
      setError("Deschideți din Telegram (buton Panou Web App).");
      return;
    }
    fetch(`${API}/api/telegram/webapp-auth`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ init_data: initData }),
    })
      .then((r) => r.json().then((d) => ({ ok: r.ok, d })))
      .then(({ ok, d }) => {
        if (!ok) throw new Error(d.error || "Auth eșuat");
        setToken(d.access_token);
        setServers(d.servers || []);
        if (d.servers?.length) setServerId(d.servers[0].id);
      })
      .catch((e) => setError(e.message));
  }, []);

  const authFetch = (path, opts = {}) =>
    fetch(`${API}${path}`, {
      ...opts,
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        ...opts.headers,
      },
    });

  const qs = serverId ? `?server_id=${serverId}` : "";

  useEffect(() => {
    if (!token || !serverId) return;
    authFetch(`/api/intelligence${qs}`).then((r) => r.json()).then(setStatus).catch(() => {});
    const srv = servers.find((s) => s.id === serverId);
    if (srv?.mod_csf && srv?.cap_csf) {
      authFetch(`/api/csf${qs}`).then((r) => r.json()).then((d) => setCsf(d.csf)).catch(() => {});
    } else {
      setCsf(null);
    }
    if (srv?.mod_nftables && srv?.cap_nftables) {
      authFetch(`/api/nftables${qs}`).then((r) => r.json()).then((d) => setNft(d.nftables)).catch(() => {});
    } else {
      setNft(null);
    }
  }, [token, serverId, servers]);

  const doBan = async () => {
    if (!banIp.trim()) return;
    const r = await authFetch(`/api/jails/sshd/ban${qs}`, { method: "POST", body: JSON.stringify({ ip: banIp.trim() }) });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      setMsg(d.error || "Eroare ban");
      return;
    }
    setMsg(`Ban trimis: ${banIp}`);
    setBanIp("");
  };

  const csfAction = async (path, body = {}) => {
    await authFetch(`/api/csf/${path}${qs}`, { method: "POST", body: JSON.stringify(body) });
    setMsg("Comandă CSF trimisă");
    setTimeout(() => authFetch(`/api/csf${qs}`).then((r) => r.json()).then((d) => setCsf(d.csf)), 2000);
  };

  const nftAction = async (path, body = {}) => {
    await authFetch(`/api/nftables/${path}${qs}`, { method: "POST", body: JSON.stringify(body) });
    setMsg("Comandă nftables trimisă");
    setTimeout(() => authFetch(`/api/nftables${qs}`).then((r) => r.json()).then((d) => setNft(d.nftables)), 2000);
  };

  const doNftDeny = async () => {
    if (!nftIp.trim()) return;
    await nftAction("deny", { ip: nftIp.trim() });
    setNftIp("");
  };

  if (error) {
    return <div className="tg-app"><p className="tg-error">{error}</p></div>;
  }
  if (!token) {
    return <div className="tg-app"><p>Se conectează…</p></div>;
  }

  const active = servers.find((s) => s.id === serverId);
  const hasModule = active && (active.cap_fail2ban || active.cap_csf || active.cap_nftables);

  return (
    <div className="tg-app">
      <header className="tg-header">
        <h1>NeoHost Security</h1>
        <FormSelect
          value={serverId || ""}
          onChange={(v) => setServerId(parseInt(v, 10))}
          options={servers.map((s) => ({ value: s.id, label: s.name }))}
        />
      </header>

      {msg && <div className="tg-toast">{msg}</div>}

      {status?.threat && (
        <section className="tg-card">
          <h2>Amenințare</h2>
          <p className="tg-threat">{status.threat.level}</p>
          <p className="tg-muted">{status.threat.recommendation}</p>
        </section>
      )}

      {active?.mod_fail2ban && active?.cap_fail2ban && (
        <section className="tg-card">
          <h2>Fail2Ban</h2>
          <div className="tg-row">
            <input className="form-input" placeholder="IP de banat" value={banIp} onChange={(e) => setBanIp(e.target.value)} />
            <button type="button" className="btn btn-danger btn-sm" onClick={doBan}>Ban</button>
          </div>
        </section>
      )}

      {active?.mod_csf && active?.cap_csf && csf?.installed && (
        <section className="tg-card">
          <h2>CSF Firewall</h2>
          <p className="tg-muted">
            {csf.enabled ? "Activ" : "Inactiv"} · Deny: {csf.deny_count ?? 0} · Allow: {csf.allow_count ?? 0}
            {csf.testing_mode ? " · Mod TEST" : ""}
          </p>
          <div className="tg-btns">
            <button type="button" className="btn btn-sm" onClick={() => csfAction("restart")}>Restart</button>
            <button type="button" className="btn btn-sm" onClick={() => csfAction("firewall", { enabled: !csf.enabled })}>
              {csf.enabled ? "Oprește" : "Pornește"}
            </button>
            <button type="button" className="btn btn-sm" onClick={() => csfAction("toggle", { key: "TESTING", enabled: !csf.testing_mode })}>
              Test {csf.testing_mode ? "OFF" : "ON"}
            </button>
          </div>
        </section>
      )}

      {active?.mod_nftables && active?.cap_nftables && nft?.installed && (
        <section className="tg-card">
          <h2>nftables</h2>
          <p className="tg-muted">
            {nft.running ? "Activ" : "Inactiv"} · Deny: {nft.deny_count ?? 0} · Allow: {nft.allow_count ?? 0}
            {" · "}Reguli: {nft.stats?.rule_count ?? 0}
          </p>
          <div className="tg-row">
            <input className="form-input" placeholder="IP deny" value={nftIp} onChange={(e) => setNftIp(e.target.value)} />
            <button type="button" className="btn btn-danger btn-sm" onClick={doNftDeny}>Deny</button>
          </div>
          <div className="tg-btns">
            <button type="button" className="btn btn-sm" onClick={() => nftAction("reload")}>Reload</button>
            <button type="button" className="btn btn-sm" onClick={() => nftAction("firewall", { enabled: !nft.running })}>
              {nft.running ? "Oprește" : "Pornește"}
            </button>
          </div>
        </section>
      )}

      {active && !hasModule && (
        <p className="tg-muted">Agentul nu a raportat încă module. Așteptați sync.</p>
      )}
    </div>
  );
}
