import { useState, useEffect, useRef, useCallback } from "react";
import {
  LineChart, Line, BarChart, Bar,
  XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend,
} from "recharts";
import Layout from "./Layout";
import { countryLabel, uiTheme, threatStyleFor } from "./theme";
import Icon, { IconBox } from "./Icons";
import AttackMap from "./components/AttackMap";
import ProfilePage from "./components/ProfilePage";
import Fail2banPage from "./components/Fail2banPage";
import SecurityPage from "./components/SecurityPage";
import CsfPage from "./components/CsfPage";
import NftablesPage from "./components/NftablesPage";
import { ServerManagementTable, ModuleToggleChip } from "./components/ui/server-management-table";
import { FormSelect } from "./components/ui/form-select";
import { ConfirmDialog } from "./components/ui/confirm-dialog";
import { AppToast } from "./components/ui/app-toast";
import { useTheme } from "./context/ThemeContext";
import { useI18n } from "./i18n";
import { ServerEditModal } from "./components/ui/server-edit-modal";

const EMPTY_INTEL = {
  threat: { level: "LOW", bans_hr: 0, bans_last_min: 0, recommendation: "" },
  top10: [],
  countries: [],
  jail_stats: [],
  timeline: [],
};

function Badge({ type, children }) {
  const map = {
    banned: "badge-error", suspicious: "badge-warning",
    ok: "badge-success", info: "badge-info",
  };
  return <span className={`badge ${map[type] || "badge-default"}`}>{children}</span>;
}

function MetricCard({ icon, label, value, sub, colorClass, trend }) {
  return (
    <div className="metric-card">
      <IconBox name={icon} color={colorClass} />
      <div className="metric-card-top">
        <label>{label}</label>
        {trend && <span className={`metric-trend ${trend.type}`}>{trend.text}</span>}
      </div>
      <div className="value">{value}</div>
      {sub && <div className="sub">{sub}</div>}
    </div>
  );
}

function IpModal({ ip, onClose, authFetch, serverId }) {
  const { theme: colorTheme } = useTheme();
  const { t } = useI18n();
  const theme = uiTheme(colorTheme === "dark");
  const [data, setData] = useState(null);
  useEffect(() => {
    if (!ip || !serverId) return;
    authFetch(`/api/ip/${ip}?server_id=${serverId}`).then((r) => r.json()).then(setData).catch(() => {});
  }, [ip, serverId, authFetch]);

  if (!ip) return null;
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16 }}>
          <span className="mono" style={{ fontSize: "1rem", fontWeight: 600, color: theme.primary }}>{ip}</span>
          <button className="icon-btn" onClick={onClose}><Icon name="close" size={16} /></button>
        </div>
        {!data ? <p style={{ color: theme.textSecondary }}>{t("common.loading")}</p> : (
          <>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
              {[
                [t("dashboard.location"), countryLabel(data.geo?.country_code, `${data.geo?.city || ""}, ${data.geo?.country || ""}`.replace(/^, |, $/g, ""))],
                [t("dashboard.isp"), data.geo?.isp || "—"],
                [t("dashboard.asn"), data.geo?.asn || "—"],
                [t("dashboard.bans"), data.ban_count],
              ].map(([k, v]) => (
                <div key={k}>
                  <div style={{ fontSize: "0.7rem", color: theme.textSecondary, marginBottom: 4 }}>{k}</div>
                  <div style={{ fontSize: "0.85rem" }}>{v}</div>
                </div>
              ))}
            </div>
            {data.abuse?.score != null && (
              <div style={{ marginBottom: 16 }}>
                <Badge type={data.abuse.score > 50 ? "banned" : data.abuse.score > 20 ? "suspicious" : "ok"}>
                  AbuseIPDB: {data.abuse.score}%
                </Badge>
              </div>
            )}
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <a href={`https://www.abuseipdb.com/check/${ip}`} target="_blank" rel="noreferrer" className="btn btn-sm">AbuseIPDB</a>
              <a href={`https://bgp.he.net/ip/${ip}`} target="_blank" rel="noreferrer" className="btn btn-sm">BGP.he.net</a>
            </div>
          </>
        )}
      </div>
    </div>
  );
}


const PANEL_PAGES = new Set([
  "monitor", "intel", "jails", "security", "csf", "nftables", "history", "connections", "servers", "profile",
]);

export default function Dashboard({ token, apiUrl, onLogout }) {
  const { theme: colorTheme } = useTheme();
  const { t } = useI18n();
  const theme = uiTheme(colorTheme === "dark");
  const API = apiUrl || "";

  const [page, setPageState] = useState(() => {
    const saved = localStorage.getItem("neohost_page");
    return PANEL_PAGES.has(saved) ? saved : "monitor";
  });
  const setPage = useCallback((next) => {
    setPageState(next);
    localStorage.setItem("neohost_page", next);
  }, []);
  const [servers, setServers] = useState([]);
  const [serverId, setServerId] = useState(() => {
    const s = localStorage.getItem("neohost_server_id");
    return s ? parseInt(s, 10) : null;
  });
  const [newSrv, setNewSrv] = useState({
    name: "", hostname: "", description: "", latitude: "", longitude: "", location_label: "",
    mod_fail2ban: true, mod_csf: true, mod_nftables: true,
  });
  const [editSrv, setEditSrv] = useState(null);
  const [agentKey, setAgentKey] = useState(null);
  const [jails, setJails] = useState([]);
  const [conns, setConns] = useState([]);
  const [netH, setNetH] = useState([]);
  const [connH, setConnH] = useState([]);
  const [events, setEvents] = useState([]);
  const [banHist, setBanHist] = useState([]);
  const [intel, setIntel] = useState(EMPTY_INTEL);
  const [connected, setConnected] = useState(false);
  const [serverLoading, setServerLoading] = useState(false);
  const [paused, setPaused] = useState(false);
  const [filterIp, setFilterIp] = useState("");
  const [filterSt, setFilterSt] = useState("all");
  const [filterJail, setFilterJail] = useState("all");
  const [manualIp, setManualIp] = useState("");
  const [liveF2b, setLiveF2b] = useState(null);
  const [liveCsf, setLiveCsf] = useState(null);
  const [liveNft, setLiveNft] = useState(null);
  const [toast, setToast] = useState(null);
  const [confirmDlg, setConfirmDlg] = useState(null);
  const [detailIp, setDetailIp] = useState(null);
  const [clock, setClock] = useState("");
  const pausedRef = useRef(false);
  const wsRef = useRef(null);
  const wsReconnectRef = useRef(null);
  const wsAllowReconnectRef = useRef(true);
  const connectedRef = useRef(false);

  const WS = API
    ? (API.startsWith("https") ? API.replace("https", "wss") : API.replace("http", "ws")) + "/ws"
    : (import.meta.env.VITE_WS_URL || (
      typeof window !== "undefined" && window.location?.host
        ? `${window.location.protocol === "https:" ? "wss" : "ws"}://${window.location.host}/ws`
        : "ws://127.0.0.1:5173/ws"
    ));

  const showToast = useCallback((text, colorOrType = "success") => {
    const types = ["success", "error", "warning", "info"];
    const isType = types.includes(colorOrType);
    setToast({
      text,
      type: isType ? colorOrType : "success",
      color: isType ? undefined : colorOrType,
    });
    setTimeout(() => setToast(null), 3200);
  }, []);

  const authFetch = useCallback(
    (path, opts = {}) =>
      fetch(`${API}${path}`, {
        ...opts,
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
          ...opts.headers,
        },
      }),
    [API, token]
  );

  const qs = useCallback(
    (extra = {}) => {
      if (!serverId) return "";
      return `?${new URLSearchParams({ server_id: serverId, ...extra })}`;
    },
    [serverId]
  );

  const loadServers = useCallback(async () => {
    try {
      const r = await authFetch("/api/servers");
      const d = await r.json();
      const list = d.servers || [];
      setServers(list);
      setServerId((prev) => {
        if (prev && list.some((s) => s.id === prev)) return prev;
        if (list.length) {
          localStorage.setItem("neohost_server_id", String(list[0].id));
          return list[0].id;
        }
        return null;
      });
    } catch { /* ignore */ }
  }, [authFetch]);

  const resetServerData = useCallback(() => {
    setJails([]);
    setConns([]);
    setNetH([]);
    setConnH([]);
    setEvents([]);
    setBanHist([]);
    setIntel(EMPTY_INTEL);
    setLiveF2b(null);
    setLiveCsf(null);
    setLiveNft(null);
    setFilterIp("");
    setFilterSt("all");
    setFilterJail("all");
    setDetailIp(null);
  }, []);

  const loadServerSnapshot = useCallback(async () => {
    if (!serverId) return;
    setServerLoading(true);
    try {
      const [jailsR, netR, connR, logR, intelR, bansR] = await Promise.all([
        authFetch(`/api/jails${qs()}`),
        authFetch(`/api/network${qs()}`),
        authFetch(`/api/connections${qs()}`),
        authFetch(`/api/log${qs()}`),
        authFetch(`/api/intelligence${qs()}`),
        authFetch(`/api/ban_history${qs({ limit: 5000 })}`),
      ]);
      const [jailsD, netD, connD, logD, intelD, bansD] = await Promise.all([
        jailsR.json(), netR.json(), connR.json(), logR.json(), intelR.json(), bansR.json(),
      ]);
      setJails(jailsD.jails || []);
      setNetH(netD.history || []);
      setConnH(connD.history || []);
      setConns(connD.connections || []);
      setEvents(logD.events || []);
      setIntel({ ...EMPTY_INTEL, ...intelD });
      setBanHist(bansD.bans || []);
    } catch {
      /* keep cleared state */
    } finally {
      setServerLoading(false);
    }
  }, [authFetch, serverId, qs]);

  const selectServer = (id) => {
    if (id === serverId) return;
    resetServerData();
    setConnected(false);
    wsRef.current?.close();
    setServerId(id);
    localStorage.setItem("neohost_server_id", String(id));
  };

  const loadJails = useCallback(async () => {
    if (!serverId) return;
    try {
      const r = await authFetch(`/api/jails${qs()}`);
      const d = await r.json();
      setJails(d.jails || []);
    } catch { /* ignore */ }
  }, [authFetch, serverId, qs]);

  useEffect(() => {
    const tick = () => setClock(new Date().toLocaleTimeString("ro-RO"));
    tick();
    const ci = setInterval(tick, 1000);
    return () => clearInterval(ci);
  }, []);

  useEffect(() => {
    if (!serverId) return;
    wsAllowReconnectRef.current = true;
    resetServerData();
    loadServerSnapshot();

    function connect() {
      const ws = new WebSocket(WS);
      wsRef.current = ws;
      ws.onopen = () => ws.send(JSON.stringify({ token, server_id: serverId }));
      ws.onmessage = (e) => {
        if (pausedRef.current) return;
        let msg;
        try {
          msg = JSON.parse(e.data);
        } catch {
          return;
        }
        if (msg.type === "error") {
          connectedRef.current = false;
          setConnected(false);
          wsAllowReconnectRef.current = false;
          showToast(msg.message || t("common.error"), theme.error);
          return;
        }
        if (msg.type === "auth") {
          connectedRef.current = true;
          setConnected(true);
        }
        if (msg.type === "history") {
          setNetH(msg.net_history || []);
          setConnH(msg.conn_history || []);
          setEvents(msg.events || []);
          setBanHist(msg.ban_history || []);
          if (msg.intelligence) setIntel(msg.intelligence);
        }
        if (msg.type === "tick") {
          const d = msg.data;
          setConns(d.connections || []);
          setNetH(d.net_history || []);
          setConnH(d.conn_history || []);
          if (d.threat) setIntel((prev) => ({
            ...prev,
            threat: d.threat,
            ...(d.countries ? { countries: d.countries } : {}),
            ...(d.top10 ? { top10: d.top10 } : {}),
          }));
          if (d.fail2ban) {
            setLiveF2b(d.fail2ban);
            setJails(d.fail2ban.jails || []);
          }
          if (d.csf) setLiveCsf(d.csf);
          if (d.nftables) setLiveNft(d.nftables);
        }
        if (msg.type === "log") setEvents((prev) => [msg.data, ...prev].slice(0, 200));
        if (msg.type === "ban_event") setBanHist((prev) => [msg.data, ...prev].slice(0, 5000));
      };
      ws.onclose = () => {
        connectedRef.current = false;
        setConnected(false);
        if (wsAllowReconnectRef.current) {
          wsReconnectRef.current = setTimeout(connect, 3000);
        }
      };
    }
    connect();
    const ji = setInterval(() => {
      if (!connectedRef.current) loadJails();
    }, 15000);
    return () => {
      wsAllowReconnectRef.current = false;
      if (wsReconnectRef.current) clearTimeout(wsReconnectRef.current);
      wsRef.current?.close();
      clearInterval(ji);
    };
  }, [WS, loadJails, loadServerSnapshot, resetServerData, serverId, showToast, t, theme.error, token]);

  useEffect(() => {
    if (!paused && serverId) loadServerSnapshot();
  }, [paused, serverId, loadServerSnapshot]);

  useEffect(() => { loadServers(); }, [loadServers]);

  const banIp = async (ip, jail = "sshd") => {
    const r = await authFetch(`/api/jails/${jail}/ban${qs()}`, { method: "POST", body: JSON.stringify({ ip }) });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      showToast(d.error || t("f2b.cmdError"), theme.error);
      return;
    }
    showToast(t("dashboard.ipBanned", { ip }), theme.error);
    loadJails();
  };
  const unbanIp = async (ip, jail = "sshd") => {
    const r = await authFetch(`/api/jails/${jail}/unban${qs()}`, { method: "POST", body: JSON.stringify({ ip }) });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      showToast(d.error || t("f2b.cmdError"), theme.error);
      return;
    }
    showToast(t("dashboard.ipUnbanned", { ip }), theme.success);
    loadJails();
  };

  const exportData = async (format) => {
    const extra = filterJail !== "all" ? { jail: filterJail } : {};
    try {
      const r = await authFetch(`/api/export/${format}${qs(extra)}`);
      if (!r.ok) throw new Error();
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `ban_history.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      showToast(t("dashboard.exportFailed"), theme.error);
    }
  };

  const updateServerModules = async (s, patch) => {
    const r = await authFetch(`/api/servers/${s.id}`, { method: "PUT", body: JSON.stringify(patch) });
    if (r.ok) {
      loadServers();
    } else {
      const d = await r.json().catch(() => ({}));
      showToast(d.error || t("common.error"), theme.error);
    }
  };

  const addServer = async () => {
    if (!newSrv.name.trim()) return;
    const body = {
      ...newSrv,
      latitude: newSrv.latitude === "" ? null : parseFloat(newSrv.latitude),
      longitude: newSrv.longitude === "" ? null : parseFloat(newSrv.longitude),
    };
    const r = await authFetch("/api/servers", { method: "POST", body: JSON.stringify(body) });
    const d = await r.json();
    if (!r.ok) {
      showToast(d.error || t("common.error"), theme.error);
      return;
    }
    if (d.server) {
      setAgentKey(d.server.agent_key);
      setNewSrv({ name: "", hostname: "", description: "", latitude: "", longitude: "", location_label: "", mod_fail2ban: true, mod_csf: true, mod_nftables: true });
      await loadServers();
      selectServer(d.server.id);
      showToast(t("dashboard.serverAdded", { name: d.server.name }));
    }
  };

  const deleteServer = (id) => {
    const srv = servers.find((s) => s.id === id);
    setConfirmDlg({
      title: t("dashboard.deleteServerTitle"),
      message: t("dashboard.deleteServerMsg", { name: srv?.name || id }),
      confirmLabel: t("common.delete"),
      onConfirm: async () => {
        setConfirmDlg(null);
        await authFetch(`/api/servers/${id}`, { method: "DELETE" });
        if (serverId === id) {
          resetServerData();
          setServerId(null);
          localStorage.removeItem("neohost_server_id");
        }
        loadServers();
        showToast(t("dashboard.serverDeleted"), "success");
      },
    });
  };

  const activeServer = servers.find((s) => s.id === serverId);

  const totalBanned = jails.reduce((s, j) => s + (j.currently_banned || 0), 0);
  const lastNet = netH[netH.length - 1] || {};
  const threat = intel.threat || {};
  const threatStyle = threatStyleFor(threat.level, colorTheme === "dark");
  const gridStroke = colorTheme === "dark" ? "#1f1f23" : "#e3e8ef";
  const jailNames = [...new Set(jails.map((j) => j.name))];
  const bannedIps = new Set(jails.flatMap((j) => j.banned_ips || []));
  const connStatus = (c) => {
    if (bannedIps.has(c.ip)) return "banned";
    if (c.rps > 15) return "suspicious";
    return "ok";
  };
  const filteredConns = conns.filter(
    (c) => c.ip.includes(filterIp) && (filterSt === "all" || connStatus(c) === filterSt)
  );
  const filteredBanHist = banHist.filter(
    (b) => b.ip.includes(filterIp) && (filterJail === "all" || b.jail === filterJail)
  );

  const chartTip = {
    background: colorTheme === "dark" ? "#111116" : "#fff",
    border: `1px solid ${colorTheme === "dark" ? "#27272a" : theme.border}`,
    borderRadius: 8,
    fontSize: 12,
    color: colorTheme === "dark" ? "#ffffff" : theme.text,
  };
  const noServer = !["servers", "profile"].includes(page) && !serverId;

  return (
    <Layout
      page={page} setPage={setPage}
      servers={servers} serverId={serverId} selectServer={selectServer}
      activeServer={activeServer}
      connected={connected} onLogout={onLogout}
      onPause={() => { pausedRef.current = !pausedRef.current; setPaused(pausedRef.current); }}
      paused={paused} onExport={exportData} clock={clock}
    >
      <AppToast toast={toast} />
      <ConfirmDialog
        open={!!confirmDlg}
        title={confirmDlg?.title}
        message={confirmDlg?.message}
        confirmLabel={confirmDlg?.confirmLabel}
        danger
        onConfirm={confirmDlg?.onConfirm}
        onCancel={() => setConfirmDlg(null)}
      />
      {detailIp && (
        <IpModal ip={detailIp} onClose={() => setDetailIp(null)} authFetch={authFetch} serverId={serverId} />
      )}

      {!noServer && activeServer && !["servers", "profile"].includes(page) && (
        <div className="mb-4 flex items-center gap-2 rounded-lg border border-border/30 bg-card px-4 py-2.5 text-sm">
          <span className="text-muted-foreground">{t("layout.activeServer")}</span>
          <span className="font-medium text-purple-400">{activeServer.name}</span>
          {activeServer.hostname && (
            <span className="text-muted-foreground font-mono text-xs">({activeServer.hostname})</span>
          )}
          {serverLoading && (
            <span className="ml-auto text-xs text-muted-foreground">{t("dashboard.loadingData")}</span>
          )}
        </div>
      )}

      {noServer && (
        <div className="card empty-state">
          <p>{t("dashboard.noServer")}</p>
          <button className="btn btn-primary-sm" onClick={() => setPage("servers")}>
            <Icon name="plus" size={14} /> {t("dashboard.addServer")}
          </button>
        </div>
      )}

      {!noServer && page === "monitor" && (
        <>
          <div
            className="threat-banner"
            style={{
              background: threatStyle.bg,
              border: threatStyle.border ? `1px solid ${threatStyle.border}` : "1px solid transparent",
            }}
          >
            <div>
              <div className="threat-level" style={{ color: threatStyle.color }}>{threat.level || "LOW"}</div>
              <div style={{ fontSize: "0.85rem", color: theme.textSecondary, marginTop: 4 }}>{threat.recommendation}</div>
              <div style={{ fontSize: "0.75rem", color: theme.textSecondary, marginTop: 4 }}>
                {t("dashboard.banHourMin", { hr: threat.bans_hr, min: threat.bans_last_min })}
              </div>
            </div>
            <div style={{ display: "flex", gap: 24 }}>
              {[
                [t("dashboard.bannedNow"), totalBanned, theme.error],
                [t("dashboard.history"), banHist.length, theme.warning],
                [t("dashboard.activeJails"), jails.filter((j) => j.active).length, theme.primary],
              ].map(([l, v, c]) => (
                <div key={l} style={{ textAlign: "center" }}>
                  <div style={{ fontSize: "1.25rem", fontWeight: 600, color: c }}>{v}</div>
                  <div style={{ fontSize: "0.7rem", color: theme.textSecondary }}>{l}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="metrics-grid">
            <MetricCard icon="ban" label={t("dashboard.bannedIps")} value={totalBanned} colorClass="red"
              sub={`${threat.bans_hr || 0} ${t("dashboard.lastHour")}`}
              trend={threat.bans_hr > 10 ? { type: "up", text: t("dashboard.trendHigh") } : { type: "neutral", text: t("dashboard.trendNormal") }} />
            <MetricCard icon="link" label={t("dashboard.connections")} value={conns.length} colorClass="blue"
              sub={t("dashboard.sessionsMonitored")} />
            <MetricCard icon="arrowDown" label={t("dashboard.trafficIn")} value={`${lastNet.rx ?? 0} MB/s`} colorClass="green"
              sub={t("dashboard.downloadRate")} />
            <MetricCard icon="arrowUp" label={t("dashboard.trafficOut")} value={`${lastNet.tx ?? 0} MB/s`} colorClass="orange"
              sub={t("dashboard.uploadRate")} />
          </div>

          <div className="grid-2">
            <div className="card">
              <h3 className="card-title">{t("dashboard.networkTraffic")}</h3>
              <ResponsiveContainer width="100%" height={200}>
                <LineChart data={netH}>
                  <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} />
                  <XAxis dataKey="ts" hide />
                  <YAxis tick={{ fontSize: 11, fill: theme.textSecondary }} />
                  <Tooltip contentStyle={chartTip} />
                  <Line type="monotone" dataKey="rx" stroke={theme.success} dot={false} name="IN" />
                  <Line type="monotone" dataKey="tx" stroke={theme.primary} dot={false} name="OUT" />
                  <Legend />
                </LineChart>
              </ResponsiveContainer>
            </div>
            <div className="card">
              <h3 className="card-title">{t("dashboard.activeConnections")}</h3>
              <ResponsiveContainer width="100%" height={200}>
                <LineChart data={connH}>
                  <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} />
                  <XAxis dataKey="ts" hide />
                  <YAxis tick={{ fontSize: 11, fill: theme.textSecondary }} />
                  <Tooltip contentStyle={chartTip} />
                  <Line type="monotone" dataKey="count" stroke={theme.warning} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="card">
            <h3 className="card-title">{t("dashboard.liveEvents")}</h3>
            <div style={{ maxHeight: 180, overflowY: "auto", fontSize: "0.8rem" }}>
              {events.slice(0, 30).map((e, i) => (
                <div key={i} style={{ padding: "6px 0", borderBottom: `1px solid ${theme.border}` }}>
                  <span style={{ color: theme.textSecondary }}>{e.ts}</span>{" "}
                  <Badge type={e.level === "BAN" ? "banned" : e.level === "UNBAN" ? "ok" : "info"}>{e.level}</Badge>{" "}
                  {e.message}
                </div>
              ))}
            </div>
          </div>
        </>
      )}

      {!noServer && page === "intel" && (
        <>
          <AttackMap
            countries={intel.countries || []}
            serverName={activeServer?.name}
            hub={{
              lat: activeServer?.latitude,
              lng: activeServer?.longitude,
              label: activeServer?.location_label || activeServer?.name,
            }}
            onIpClick={setDetailIp}
          />
          <div className="intel-top-tables-row">
            <div className="card">
              <h3 className="card-title">{t("intel.top10ip")}</h3>
              <table className="data-table">
                <thead><tr><th>#</th><th>IP</th><th>{t("intel.country")}</th><th>{t("intel.bans")}</th><th></th></tr></thead>
                <tbody>
                  {(intel.top10 || []).map((row, i) => (
                    <tr key={i}>
                      <td>{i + 1}</td>
                      <td className="mono" onClick={() => setDetailIp(row.ip)}>{row.ip}</td>
                      <td>{countryLabel(row.country_code, row.country)}</td>
                      <td style={{ color: theme.error, fontWeight: 600 }}>{row.count}</td>
                      <td><button className="btn btn-sm btn-danger" onClick={() => banIp(row.ip)}><Icon name="ban" size={14} /> {t("intel.ban")}</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="card">
              <h3 className="card-title">{t("intel.top10countries")}</h3>
              <table className="data-table">
                <thead><tr><th>#</th><th>{t("intel.country")}</th><th>IP</th><th>{t("intel.bans")}</th></tr></thead>
                <tbody>
                  {(intel.countries || []).slice(0, 10).map((c, i) => (
                    <tr key={c.code || i}>
                      <td>{i + 1}</td>
                      <td>{c.country || c.code}{c.code && <span className="country-tag">{c.code}</span>}</td>
                      <td className="text-muted-foreground text-sm">{c.unique_ips ?? "—"}</td>
                      <td style={{ color: theme.error, fontWeight: 600 }}>{c.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          <div className="grid-2-1">
            <div className="card">
              <h3 className="card-title">{t("intel.timeline24h")}</h3>
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={intel.timeline || []}>
                  <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} />
                  <XAxis dataKey="hour" tick={{ fontSize: 10 }} interval={3} />
                  <YAxis tick={{ fontSize: 10 }} />
                  <Tooltip contentStyle={chartTip} />
                  <Bar dataKey="count" fill={theme.primary} radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <div className="card">
              <h3 className="card-title">{t("intel.topCountries")}</h3>
              {(intel.countries || []).slice(0, 10).map((c, i) => {
                const pct = Math.round(c.count / Math.max(...(intel.countries || []).map((x) => x.count), 1) * 100);
                return (
                  <div key={i} style={{ marginBottom: 10 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.8rem", marginBottom: 4 }}>
                      <span>{c.country || c.code}{c.code && <span className="country-tag">{c.code}</span>}</span>
                      <strong style={{ color: theme.error }}>{c.count}</strong>
                    </div>
                    <div className="progress-bar">
                      <div className="progress-fill" style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </>
      )}

      {!noServer && page === "security" && (
        <SecurityPage
          authFetch={authFetch}
          serverId={serverId}
          server={activeServer}
          servers={servers}
          showToast={showToast}
        />
      )}

      {!noServer && page === "jails" && (
        <Fail2banPage
          authFetch={authFetch}
          serverId={serverId}
          server={activeServer}
          liveData={liveF2b}
          showToast={showToast}
          manualIp={manualIp}
          setManualIp={setManualIp}
        />
      )}

      {!noServer && page === "history" && (
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">{t("dashboard.historyTitle", { count: filteredBanHist.length })}</h3>
            <div style={{ display: "flex", gap: 8 }}>
              <input className="form-input" style={{ width: 140 }} placeholder={t("dashboard.filterIp")} value={filterIp} onChange={(e) => setFilterIp(e.target.value)} />
              <FormSelect
                className="w-[140px]"
                value={filterJail}
                onChange={setFilterJail}
                options={[
                  { value: "all", label: "Toate jailurile" },
                  ...jailNames.map((j) => ({ value: j, label: j })),
                ]}
              />
              <button className="btn btn-sm" onClick={() => exportData("csv")}><Icon name="download" size={14} /> CSV</button>
            </div>
          </div>
          <table className="data-table">
            <thead><tr><th>Timp</th><th>IP</th><th>Jail</th><th>Locație</th><th></th></tr></thead>
            <tbody>
              {filteredBanHist.slice(0, 200).map((b, i) => (
                <tr key={i}>
                  <td style={{ color: theme.textSecondary }}>{b.ts?.substring(0, 19) || "—"}</td>
                  <td className="mono" onClick={() => setDetailIp(b.ip)}>{b.ip}</td>
                  <td><Badge type="info">{b.jail}</Badge></td>
                  <td>{countryLabel(b.country_code, b.city || b.country)}</td>
                  <td><button className="btn btn-sm" onClick={() => setDetailIp(b.ip)}><Icon name="info" size={14} /> Info</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {!noServer && page === "connections" && (
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">{t("dashboard.connectionsTitle", { count: filteredConns.length })}</h3>
            <div style={{ display: "flex", gap: 8 }}>
              <input className="form-input" style={{ width: 140 }} placeholder={t("common.ip")} value={filterIp} onChange={(e) => setFilterIp(e.target.value)} />
              <FormSelect
                className="w-[130px]"
                value={filterSt}
                onChange={setFilterSt}
                options={[
                  { value: "all", label: "Toate" },
                  { value: "ok", label: "Normale" },
                  { value: "suspicious", label: "Suspecte" },
                  { value: "banned", label: "Banate" },
                ]}
              />
            </div>
          </div>
          <table className="data-table">
            <thead>
              <tr>{["IP", "Port", "Proto", "Req/s", "Locație", "Status", ""].map((h) => <th key={h}>{h}</th>)}</tr>
            </thead>
            <tbody>
              {filteredConns.length === 0 ? (
                <tr><td colSpan={7} className="empty-state">Nicio conexiune</td></tr>
              ) : filteredConns.map((c, i) => {
                const st = connStatus(c);
                return (
                  <tr key={i}>
                    <td className="mono" onClick={() => setDetailIp(c.ip)}>{c.ip}</td>
                    <td>{c.port}</td>
                    <td>{c.proto}</td>
                    <td style={{ fontWeight: 600, color: c.rps > 10 ? theme.error : theme.text }}>{c.rps}</td>
                    <td>{countryLabel(c.country_code, c.country)}</td>
                    <td><Badge type={st}>{st === "ok" ? "Normal" : st === "suspicious" ? "Suspect" : "Banat"}</Badge></td>
                    <td><button className="btn btn-sm btn-danger" onClick={() => banIp(c.ip)}><Icon name="ban" size={14} /></button></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {page === "profile" && (
        <ProfilePage authFetch={authFetch} showToast={showToast} />
      )}

      {!noServer && page === "csf" && (
        <CsfPage authFetch={authFetch} serverId={serverId} server={activeServer} liveData={liveCsf} showToast={showToast} />
      )}

      {!noServer && page === "nftables" && (
        <NftablesPage authFetch={authFetch} serverId={serverId} server={activeServer} liveData={liveNft} showToast={showToast} />
      )}

      {page === "servers" && (
        <>
          <div className="relative border border-border/30 rounded-2xl p-6 bg-card mb-5">
            <h3 className="text-lg font-medium text-foreground mb-4">{t("servers.addTitle")}</h3>
            <div className="flex flex-wrap gap-3 mb-3">
              <input className="form-input flex-1 min-w-[140px]" placeholder={t("servers.name")} value={newSrv.name} onChange={(e) => setNewSrv((p) => ({ ...p, name: e.target.value }))} />
              <input className="form-input flex-1 min-w-[140px]" placeholder={t("servers.hostname")} value={newSrv.hostname} onChange={(e) => setNewSrv((p) => ({ ...p, hostname: e.target.value }))} />
              <input className="form-input w-28" type="number" step="any" placeholder={t("servers.latitude")} value={newSrv.latitude} onChange={(e) => setNewSrv((p) => ({ ...p, latitude: e.target.value }))} />
              <input className="form-input w-28" type="number" step="any" placeholder={t("servers.longitude")} value={newSrv.longitude} onChange={(e) => setNewSrv((p) => ({ ...p, longitude: e.target.value }))} />
              <button className="btn btn-primary-sm" onClick={addServer}><Icon name="plus" size={14} /> {t("common.add")}</button>
            </div>
            <p className="text-xs text-muted-foreground mb-4">{t("servers.coordsHint")}</p>
            <div className="server-module-row mb-4">
              <ModuleToggleChip
                label="Fail2Ban"
                enabled={newSrv.mod_fail2ban}
                detected={false}
                tone="f2b"
                onChange={(v) => setNewSrv((p) => ({ ...p, mod_fail2ban: v }))}
              />
              <ModuleToggleChip
                label="CSF"
                enabled={newSrv.mod_csf}
                detected={false}
                tone="csf"
                onChange={(v) => setNewSrv((p) => ({ ...p, mod_csf: v }))}
              />
              <ModuleToggleChip
                label="nftables"
                enabled={newSrv.mod_nftables}
                detected={false}
                tone="nft"
                onChange={(v) => setNewSrv((p) => ({ ...p, mod_nftables: v }))}
              />
            </div>
            <p className="text-xs text-muted-foreground mb-4">{t("servers.modulesHint")}</p>
            {agentKey && (
              <div className="agent-key-box rounded-lg border border-border/30 bg-muted/40 p-4 text-sm">
                <strong className="flex items-center gap-2 text-foreground"><Icon name="key" size={14} /> Agent Key</strong>
                <code className="block mt-2 break-all text-purple-400">{agentKey}</code>
              </div>
            )}
          </div>
          <ServerManagementTable
            title={t("servers.serversCount", { count: servers.length })}
            servers={servers}
            selectedId={serverId}
            onSelectServer={(s) => { selectServer(s.id); setPage("monitor"); }}
            onShowKey={async (s) => {
              const r = await authFetch(`/api/servers/${s.id}`);
              const d = await r.json();
              if (d.server) setAgentKey(d.server.agent_key);
            }}
            onUpdateModules={updateServerModules}
            onEdit={(s) => setEditSrv(s)}
            onDelete={deleteServer}
          />
          {editSrv && (
            <ServerEditModal
              server={editSrv}
              t={t}
              onClose={() => setEditSrv(null)}
              onSave={async (body) => {
                const r = await authFetch(`/api/servers/${editSrv.id}`, { method: "PUT", body: JSON.stringify(body) });
                if (r.ok) {
                  await loadServers();
                  setEditSrv(null);
                  showToast(t("common.save"));
                }
              }}
            />
          )}
        </>
      )}
    </Layout>
  );
}
