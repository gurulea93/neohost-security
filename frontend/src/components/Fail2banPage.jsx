import { useState, useEffect, useCallback, useMemo } from "react";
import Icon from "../Icons";
import { useTheme } from "../context/ThemeContext";
import { uiTheme } from "../theme";
import { ToggleSettingRow } from "./ui/toggle-setting-row";
import { FormSelect } from "./ui/form-select";

import { useI18n } from "../i18n";

export default function Fail2banPage({
  authFetch, serverId, server, liveData, showToast,
  manualIp, setManualIp,
}) {
  const { theme: colorTheme } = useTheme();
  const { t } = useI18n();
  const theme = uiTheme(colorTheme === "dark");
  const [f2b, setF2b] = useState(null);
  const [activeBans, setActiveBans] = useState([]);
  const [pending, setPending] = useState({});
  const [selectedJails, setSelectedJails] = useState([]);
  const [banSearch, setBanSearch] = useState("");
  const [banSort, setBanSort] = useState("date-desc");
  const qs = serverId ? `?server_id=${serverId}` : "";

  const load = useCallback(async () => {
    if (!serverId) return;
    try {
      const [f2bR, bansR] = await Promise.all([
        authFetch(`/api/fail2ban${qs}`),
        authFetch(`/api/fail2ban/active-bans${qs}`),
      ]);
      const f2bD = await f2bR.json();
      const bansD = await bansR.json();
      setF2b(f2bD.fail2ban || {});
      setActiveBans(bansD.bans || []);
    } catch {
      showToast(t("f2b.loadError"), theme.error);
    }
  }, [authFetch, qs, serverId]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (liveData) {
      setF2b((prev) => ({ ...prev, ...liveData }));
      const rows = [];
      for (const j of liveData.jails || []) {
        for (const ip of j.banned_ips || []) {
          rows.push({ ip, jail: j.name, ts: null, active: true });
        }
      }
      if (rows.length) {
        setActiveBans((prev) => {
          const map = new Map(prev.map((r) => [`${r.ip}|${r.jail}`, r]));
          for (const r of rows) {
            const k = `${r.ip}|${r.jail}`;
            map.set(k, { ...map.get(k), ...r });
          }
          return [...map.values()];
        });
      }
    }
  }, [liveData]);

  const jails = f2b?.jails || [];
  const jailNames = useMemo(() => jails.map((j) => j.name), [jails]);

  useEffect(() => {
    if (!jailNames.length) return;
    setSelectedJails((prev) => {
      const valid = prev.filter((j) => jailNames.includes(j));
      if (valid.length) return valid;
      return jailNames.includes("sshd") ? ["sshd"] : [jailNames[0]];
    });
  }, [jailNames]);

  const toggleJailSelect = (name) => {
    setSelectedJails((prev) =>
      prev.includes(name) ? prev.filter((j) => j !== name) : [...prev, name]
    );
  };

  const selectAllJails = () => setSelectedJails([...jailNames]);
  const clearJails = () => setSelectedJails([]);

  const queueJailToggle = async (jail, enabled) => {
    const key = `jail:${jail.name}`;
    setPending((p) => ({ ...p, [key]: true }));
    setF2b((prev) => ({
      ...prev,
      jails: (prev?.jails || []).map((j) => (j.name === jail.name ? { ...j, active: enabled } : j)),
    }));
    try {
      const r = await authFetch(`/api/fail2ban/jail/${encodeURIComponent(jail.name)}/toggle${qs}`, {
        method: "POST",
        body: JSON.stringify({ enabled }),
      });
      if (!r.ok) throw new Error();
      showToast(t("f2b.jailToggled", { name: jail.name, state: enabled ? t("f2b.started") : t("f2b.stopped") }));
    } catch {
      showToast(t("f2b.cmdError"), theme.error);
      load();
    } finally {
      setPending((p) => ({ ...p, [key]: false }));
    }
  };

  const banIpMulti = async (ip, jailsList = selectedJails) => {
    if (!ip?.trim() || !jailsList.length) {
      showToast(t("f2b.ipJailRequired"), theme.warning);
      return;
    }
    const r = await authFetch(`/api/jails/ban${qs}`, {
      method: "POST",
      body: JSON.stringify({ ip: ip.trim(), jails: jailsList }),
    });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      showToast(d.error || t("f2b.cmdError"), theme.error);
      return;
    }
    showToast(t("f2b.banSent", { count: jailsList.length }), theme.error);
    setTimeout(load, 2000);
  };

  const unbanIpMulti = async (ip, jailsList) => {
    const targets = jailsList?.length ? jailsList : selectedJails;
    if (!ip?.trim() || !targets.length) return;
    const r = await authFetch(`/api/jails/unban${qs}`, {
      method: "POST",
      body: JSON.stringify({ ip: ip.trim(), jails: targets }),
    });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      showToast(d.error || t("f2b.cmdError"), theme.error);
      return;
    }
    showToast(t("f2b.unbanSent", { count: targets.length }), theme.success);
    setTimeout(load, 2000);
  };

  const filteredBans = useMemo(() => {
    let list = activeBans.filter((b) =>
      !banSearch.trim() || b.ip.includes(banSearch.trim()) || b.jail.includes(banSearch.trim())
    );
    list = [...list].sort((a, b) => {
      if (banSort === "ip") return a.ip.localeCompare(b.ip);
      if (banSort === "jail") return a.jail.localeCompare(b.jail);
      const ta = a.ts || "";
      const tb = b.ts || "";
      if (banSort === "date-asc") return ta.localeCompare(tb);
      return tb.localeCompare(ta);
    });
    return list;
  }, [activeBans, banSearch, banSort]);

  if (!server?.mod_fail2ban) {
    return (
      <div className="card empty-state">
        <p>Fail2Ban este dezactivat pentru acest server.</p>
      </div>
    );
  }

  if (!f2b?.installed && !server?.cap_fail2ban) {
    return (
      <div className="card empty-state">
        <Icon name="shield" size={32} />
        <p style={{ marginTop: 12 }}>Fail2Ban nu este detectat pe agent.</p>
      </div>
    );
  }

  return (
    <>
      <div className="mb-3 flex items-center gap-2 text-xs text-muted-foreground">
        <span className={`inline-flex h-2 w-2 rounded-full ${f2b?.running ? "bg-green-500 animate-pulse" : "bg-red-500"}`} />
        Live — actualizat {f2b?.updated_at ? new Date(f2b.updated_at).toLocaleTimeString("ro-RO") : "…"}
      </div>

      <div className="metrics-grid">
        <div className="metric-card">
          <div className="metric-card-top"><label>Status serviciu</label></div>
          <div className="value" style={{ fontSize: "1rem", color: f2b?.running ? theme.success : theme.error }}>
            {f2b?.running ? "Rulează" : "Oprit"}
          </div>
        </div>
        <div className="metric-card">
          <div className="metric-card-top"><label>{t("dashboard.activeJails")}</label></div>
          <div className="value">{f2b?.active_jails ?? jails.filter((j) => j.active).length}</div>
        </div>
        <div className="metric-card">
          <div className="metric-card-top"><label>IP-uri banate</label></div>
          <div className="value" style={{ color: theme.error }}>{filteredBans.length || f2b?.total_banned || 0}</div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">{t("f2b.jailsLive")}</h3>
          <button type="button" className="btn btn-sm" onClick={async () => {
            await authFetch(`/api/reload${qs}`, { method: "POST" });
            showToast(t("f2b.reloadSent"));
          }}>
            <Icon name="refresh" size={14} /> Reload
          </button>
        </div>
        <div className="grid gap-2">
          {jails.map((j) => (
            <ToggleSettingRow
              key={j.name}
              label={j.name}
              description={`${j.currently_banned || 0} banate · ${j.currently_failed || 0} eșuate`}
              checked={j.active}
              pending={pending[`jail:${j.name}`]}
              onCheckedChange={(v) => queueJailToggle(j, v)}
            />
          ))}
        </div>
      </div>

      <div className="card">
        <h3 className="card-title">{t("f2b.manualBan")}</h3>
        <p className="text-xs text-muted-foreground mb-3">Selectați jailurile în care se aplică acțiunea</p>
        <div className="flex flex-wrap gap-2 mb-4">
          {jailNames.map((name) => {
            const on = selectedJails.includes(name);
            return (
              <button
                key={name}
                type="button"
                className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                  on
                    ? "bg-purple-500/20 border-purple-500/40 text-purple-300"
                    : "bg-muted/40 border-border/40 text-muted-foreground hover:border-border"
                }`}
                onClick={() => toggleJailSelect(name)}
              >
                {on ? "✓ " : ""}{name}
              </button>
            );
          })}
          <button type="button" className="btn btn-sm" onClick={selectAllJails}>Toate</button>
          <button type="button" className="btn btn-sm" onClick={clearJails}>{t("common.none")}</button>
        </div>
        <div className="flex gap-2 flex-wrap items-center">
          <input
            className="form-input w-44"
            placeholder={t("common.ip")}
            value={manualIp}
            onChange={(e) => setManualIp(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && manualIp && banIpMulti(manualIp)}
          />
          <button type="button" className="btn btn-danger" disabled={!manualIp || !selectedJails.length} onClick={() => banIpMulti(manualIp)}>
            <Icon name="ban" size={14} /> Banează ({selectedJails.length})
          </button>
          <button type="button" className="btn btn-success" disabled={!manualIp || !selectedJails.length} onClick={() => unbanIpMulti(manualIp)}>
            Debanează ({selectedJails.length})
          </button>
        </div>
      </div>

      <div className="card">
        <div className="card-header flex-wrap gap-3">
          <h3 className="card-title">{t("f2b.bannedNow", { count: filteredBans.length })}</h3>
          <div className="flex gap-2 flex-wrap items-center">
            <input
              className="form-input w-40"
              placeholder={t("f2b.searchIp")}
              value={banSearch}
              onChange={(e) => setBanSearch(e.target.value)}
            />
            <FormSelect
              className="w-40"
              value={banSort}
              onChange={setBanSort}
              options={[
                { value: "date-desc", label: "Data ↓ recent" },
                { value: "date-asc", label: "Data ↑ vechi" },
                { value: "ip", label: "Sortare IP" },
                { value: "jail", label: "Sortare jail" },
              ]}
            />
            <button type="button" className="btn btn-sm" onClick={load}>
              <Icon name="refresh" size={14} />
            </button>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>IP</th>
                <th>Jail</th>
                <th>Data ban</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {filteredBans.length === 0 ? (
                <tr><td colSpan={4} className="empty-state">{banSearch ? t("f2b.noBannedSearch") : t("f2b.noBanned")}</td></tr>
              ) : filteredBans.map((b) => (
                <tr key={`${b.ip}-${b.jail}`}>
                  <td className="mono font-medium">{b.ip}</td>
                  <td><span className="badge badge-info">{b.jail}</span></td>
                  <td className="text-sm text-muted-foreground">
                    {b.ts ? new Date(b.ts).toLocaleString("ro-RO") : "—"}
                  </td>
                  <td className="whitespace-nowrap">
                    <button type="button" className="btn btn-sm btn-success" onClick={() => unbanIpMulti(b.ip, [b.jail])}>
                      Debanează
                    </button>
                    <button type="button" className="btn btn-sm btn-danger ml-1" onClick={() => banIpMulti(b.ip, [b.jail])} title="Re-ban">
                      <Icon name="ban" size={12} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
