import { useState, useEffect, useCallback } from "react";
import Icon from "../Icons";
import { useTheme } from "../context/ThemeContext";
import { uiTheme } from "../theme";
import { Switch } from "./ui/material-design-3-switch";
import { ToggleSettingRow } from "./ui/toggle-setting-row";

import { useI18n } from "../i18n";

const PORT_LIST_LABELS = {
  TCP_IN: "TCP Inbound (porturi permise)",
  TCP_OUT: "TCP Outbound",
  UDP_IN: "UDP Inbound",
  UDP_OUT: "UDP Outbound",
};

function IpList({ title, ips, listType, onRemove, theme, emptyLabel }) {
  if (!ips?.length) {
    return (
      <div>
        <h4 className="text-sm font-medium mb-2">{title}</h4>
        <p className="text-muted-foreground text-xs">{emptyLabel}</p>
      </div>
    );
  }
  return (
    <div>
      <h4 className="text-sm font-medium mb-2">{title} ({ips.length})</h4>
      <div className="max-h-[200px] overflow-y-auto">
        <table className="data-table">
          <tbody>
            {ips.map((ip) => (
              <tr key={ip}>
                <td className="mono">{ip}</td>
                <td className="w-12">
                  <button type="button" className="btn btn-sm btn-danger" onClick={() => onRemove(ip, listType)}>
                    <Icon name="close" size={14} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default function CsfPage({ authFetch, serverId, server, liveData, showToast }) {
  const { theme: colorTheme } = useTheme();
  const { t } = useI18n();
  const theme = uiTheme(colorTheme === "dark");
  const [csf, setCsf] = useState(null);
  const [pending, setPending] = useState({});
  const [ip, setIp] = useState("");
  const qs = serverId ? `?server_id=${serverId}` : "";

  const load = useCallback(async () => {
    if (!serverId) return;
    try {
      const r = await authFetch(`/api/csf${qs}`);
      const d = await r.json();
      setCsf(d.csf || {});
    } catch {
      showToast(t("csf.loadError"), theme.error);
    }
  }, [authFetch, qs, serverId]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (liveData) setCsf((prev) => ({ ...prev, ...liveData }));
  }, [liveData]);

  const action = async (path, body = {}, pendingKey = null) => {
    if (pendingKey) setPending((p) => ({ ...p, [pendingKey]: true }));
    const r = await authFetch(`/api/csf/${path}${qs}`, { method: "POST", body: JSON.stringify(body) });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      showToast(d.error || t("csf.loadError"), theme.error);
      if (pendingKey) setPending((p) => ({ ...p, [pendingKey]: false }));
      load();
      return;
    }
    showToast(t("csf.cmdSent"));
    setTimeout(load, 2500);
    if (pendingKey) setTimeout(() => setPending((p) => ({ ...p, [pendingKey]: false })), 3000);
  };

  const toggleSetting = (key, enabled) => {
    setCsf((prev) => ({
      ...prev,
      toggles: { ...prev?.toggles, [key]: enabled },
      testing_mode: key === "TESTING" ? enabled : prev?.testing_mode,
    }));
    action("toggle", { key, enabled }, `t:${key}`);
  };

  const togglePort = (listKey, port, enabled) => {
    const pk = `p:${listKey}:${port}`;
    setCsf((prev) => {
      const ports = { ...prev?.ports };
      const block = ports[listKey];
      if (!block) return prev;
      return {
        ...prev,
        ports: {
          ...ports,
          [listKey]: {
            ...block,
            ports: block.ports.map((p) => (p.port === port ? { ...p, enabled } : p)),
          },
        },
      };
    });
    action("port", { list: listKey, port, enabled }, pk);
  };

  const removeIp = (targetIp, listType) => action("remove", { ip: targetIp, list: listType });

  if (!server?.mod_csf) {
    return (
      <div className="card empty-state">
        <p>{t("csf.moduleDisabled")}</p>
      </div>
    );
  }

  if (!csf?.installed && !server?.cap_csf) {
    return (
      <div className="card empty-state">
        <Icon name="shield" size={32} />
        <p className="mt-3">{t("csf.waitingAgent")}</p>
      </div>
    );
  }

  if (!csf?.installed) {
    return (
      <div className="card empty-state">
        <Icon name="shield" size={32} />
        <p className="mt-3">{t("csf.notInstalled")}</p>
      </div>
    );
  }

  const labels = csf.toggle_labels || {};
  const toggles = csf.toggles || {};
  const portBlocks = csf.ports || {};

  return (
    <>
      <div className="mb-3 flex items-center gap-2 text-xs text-muted-foreground">
        <span className={`inline-flex h-2 w-2 rounded-full ${csf.enabled ? "bg-green-500 animate-pulse" : "bg-amber-500"}`} />
        Live CSF — {csf.updated_at ? new Date(csf.updated_at).toLocaleTimeString("ro-RO") : "sync…"}
        {csf.testing_mode && <span className="badge badge-warning ml-2">MOD TEST</span>}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-5">
        <div className="rounded-xl border border-border/40 bg-card/60 p-4 flex items-center justify-between">
          <div>
            <div className="text-sm font-medium">Firewall CSF</div>
            <div className="text-xs text-muted-foreground">{csf.enabled ? "Activ — blochează trafic" : "Oprit"}</div>
          </div>
          <Switch
            size="sm"
            showIcons
            haptic="heavy"
            variant={csf.enabled ? "primary" : "destructive"}
            checked={!!csf.enabled}
            disabled={!!pending.firewall}
            onCheckedChange={(v) => {
              setCsf((p) => ({ ...p, enabled: v }));
              action("firewall", { enabled: v }, "firewall");
            }}
          />
        </div>
        <div className="rounded-xl border border-border/40 bg-card/60 p-4 flex items-center justify-between">
          <div>
            <div className="text-sm font-medium">Mod test</div>
            <div className="text-xs text-muted-foreground">Nu blochează efectiv IP-uri</div>
          </div>
          <Switch
            size="sm"
            showIcons
            haptic="light"
            variant="destructive"
            checked={!!csf.testing_mode}
            disabled={!!pending["t:TESTING"]}
            onCheckedChange={(v) => toggleSetting("TESTING", v)}
          />
        </div>
      </div>

      <div className="metrics-grid">
        <div className="metric-card">
          <div className="metric-card-top"><label>Deny</label></div>
          <div className="value text-red-400">{csf.deny_count ?? 0}</div>
        </div>
        <div className="metric-card">
          <div className="metric-card-top"><label>Allow</label></div>
          <div className="value text-green-400">{csf.allow_count ?? 0}</div>
        </div>
        <div className="metric-card">
          <div className="metric-card-top"><label>Temp deny</label></div>
          <div className="value">{csf.temp_deny?.length ?? 0}</div>
        </div>
        <div className="metric-card">
          <button type="button" className="btn btn-sm w-full" onClick={() => action("restart")}>
            <Icon name="refresh" size={14} /> Restart CSF
          </button>
        </div>
      </div>

      <div className="card mt-5">
        <h3 className="card-title mb-4">{t("csf.functions")}</h3>
        <div className="grid gap-2 md:grid-cols-2">
          {Object.keys(labels).filter((k) => k !== "TESTING").map((key) => (
            <ToggleSettingRow
              key={key}
              label={labels[key]}
              checked={!!toggles[key]}
              pending={pending[`t:${key}`]}
              onCheckedChange={(v) => toggleSetting(key, v)}
            />
          ))}
        </div>
      </div>

      {Object.keys(PORT_LIST_LABELS).map((listKey) => {
        const block = portBlocks[listKey];
        if (!block?.ports?.length) return null;
        return (
          <div key={listKey} className="card mt-5">
            <h3 className="card-title mb-1">{PORT_LIST_LABELS[listKey]}</h3>
            <p className="text-xs text-muted-foreground mb-4">Deschide/închide porturi în {listKey} — aplicare imediată (csf -r)</p>
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {block.ports.map((p) => (
                <ToggleSettingRow
                  key={`${listKey}-${p.port}`}
                  label={`${p.port} — ${p.label}`}
                  checked={!!p.enabled}
                  pending={pending[`p:${listKey}:${p.port}`]}
                  onCheckedChange={(v) => togglePort(listKey, p.port, v)}
                />
              ))}
            </div>
          </div>
        );
      })}

      <div className="card mt-5">
        <h3 className="card-title">{t("csf.ipAllowDeny")}</h3>
        <div className="flex gap-2 flex-wrap items-center mt-3">
          <input className="form-input w-44" placeholder="IP" value={ip} onChange={(e) => setIp(e.target.value)} />
          <button type="button" className="btn btn-danger" disabled={!ip} onClick={() => { action("deny", { ip }); setIp(""); }}>
            <Icon name="ban" size={14} /> Deny
          </button>
          <button type="button" className="btn btn-success" disabled={!ip} onClick={() => { action("allow", { ip }); setIp(""); }}>
            Allow
          </button>
        </div>
      </div>

      <div className="grid-2 mt-5">
        <div className="card">
          <IpList title="Deny permanent" ips={csf.deny} listType="deny" onRemove={removeIp} theme={theme} emptyLabel={t("csf.noIps")} />
        </div>
        <div className="card">
          <IpList title="Allow permanent" ips={csf.allow} listType="allow" onRemove={removeIp} theme={theme} emptyLabel={t("csf.noIps")} />
        </div>
      </div>
    </>
  );
}
