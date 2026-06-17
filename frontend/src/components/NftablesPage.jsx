import { useState, useEffect, useCallback } from "react";
import Icon from "../Icons";
import { useTheme } from "../context/ThemeContext";
import { uiTheme } from "../theme";
import { Switch } from "./ui/material-design-3-switch";
import { useI18n } from "../i18n";

function IpList({ title, ips, listType, onRemove, emptyLabel }) {
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

const CHAIN_LABELS = {
  input: "input (inbound)",
  forward: "forward",
  output: "output (outbound)",
};

export default function NftablesPage({ authFetch, serverId, server, liveData, showToast }) {
  const { theme: colorTheme } = useTheme();
  const { t } = useI18n();
  const theme = uiTheme(colorTheme === "dark");
  const [nft, setNft] = useState(null);
  const [pending, setPending] = useState({});
  const [ip, setIp] = useState("");
  const [ruleChain, setRuleChain] = useState("input");
  const [ruleExpr, setRuleExpr] = useState("");
  const [expandedTable, setExpandedTable] = useState(null);
  const qs = serverId ? `?server_id=${serverId}` : "";

  const load = useCallback(async () => {
    if (!serverId) return;
    try {
      const r = await authFetch(`/api/nftables${qs}`);
      const d = await r.json();
      setNft(d.nftables || {});
    } catch {
      showToast(t("nft.loadError"), theme.error);
    }
  }, [authFetch, qs, serverId, showToast, t, theme.error]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (liveData) setNft((prev) => ({ ...prev, ...liveData }));
  }, [liveData]);

  const action = async (path, body = {}, pendingKey = null) => {
    if (pendingKey) setPending((p) => ({ ...p, [pendingKey]: true }));
    const r = await authFetch(`/api/nftables/${path}${qs}`, { method: "POST", body: JSON.stringify(body) });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      showToast(d.error || t("nft.loadError"), theme.error);
      if (pendingKey) setPending((p) => ({ ...p, [pendingKey]: false }));
      load();
      return;
    }
    showToast(t("nft.cmdSent"));
    setTimeout(load, 2500);
    if (pendingKey) setTimeout(() => setPending((p) => ({ ...p, [pendingKey]: false })), 3000);
  };

  const setChainPolicy = (chain, policy) => {
    setNft((prev) => ({
      ...prev,
      chains: {
        ...prev?.chains,
        [chain]: { ...prev?.chains?.[chain], policy },
      },
    }));
    action("chain-policy", { chain, policy }, `c:${chain}`);
  };

  const removeIp = (targetIp, listType) => action("remove", { ip: targetIp, list: listType });

  if (!server?.mod_nftables) {
    return (
      <div className="card empty-state">
        <p>{t("nft.moduleDisabled")}</p>
      </div>
    );
  }

  if (!nft?.installed && !server?.cap_nftables) {
    return (
      <div className="card empty-state">
        <Icon name="shield" size={32} />
        <p className="mt-3">{t("nft.waitingAgent")}</p>
      </div>
    );
  }

  if (!nft?.installed) {
    return (
      <div className="card empty-state">
        <Icon name="shield" size={32} />
        <p className="mt-3">{t("nft.notInstalled")}</p>
      </div>
    );
  }

  const stats = nft.stats || {};
  const chains = nft.chains || {};
  const tables = nft.tables || [];

  return (
    <>
      <div className="mb-3 flex items-center gap-2 text-xs text-muted-foreground">
        <span className={`inline-flex h-2 w-2 rounded-full ${nft.running ? "bg-green-500 animate-pulse" : "bg-amber-500"}`} />
        {t("nft.liveLabel")} — {nft.updated_at ? new Date(nft.updated_at).toLocaleTimeString() : "sync…"}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-5">
        <div className="rounded-xl border border-border/40 bg-card/60 p-4 flex items-center justify-between">
          <div>
            <div className="text-sm font-medium">{t("nft.firewall")}</div>
            <div className="text-xs text-muted-foreground">
              {nft.running ? t("nft.running") : t("nft.stopped")}
            </div>
          </div>
          <Switch
            size="sm"
            showIcons
            haptic="heavy"
            variant={nft.running ? "primary" : "destructive"}
            checked={!!nft.running}
            disabled={!!pending.firewall}
            onCheckedChange={(v) => {
              setNft((p) => ({ ...p, running: v }));
              action("firewall", { enabled: v }, "firewall");
            }}
          />
        </div>
        <div className="rounded-xl border border-border/40 bg-card/60 p-4 flex items-center justify-between">
          <div>
            <div className="text-sm font-medium">{t("nft.ruleset")}</div>
            <div className="text-xs text-muted-foreground mono truncate max-w-[200px]">
              {nft.ruleset_source || "—"}
            </div>
          </div>
          <button type="button" className="btn btn-sm" onClick={() => action("reload")} disabled={!!pending.reload}>
            <Icon name="refresh" size={14} /> {t("nft.reload")}
          </button>
        </div>
      </div>

      <div className="metrics-grid">
        <div className="metric-card">
          <div className="metric-card-top"><label>{t("nft.deny")}</label></div>
          <div className="value text-red-400">{nft.deny_count ?? 0}</div>
        </div>
        <div className="metric-card">
          <div className="metric-card-top"><label>{t("nft.allow")}</label></div>
          <div className="value text-green-400">{nft.allow_count ?? 0}</div>
        </div>
        <div className="metric-card">
          <div className="metric-card-top"><label>{t("nft.rules")}</label></div>
          <div className="value">{stats.rule_count ?? 0}</div>
        </div>
        <div className="metric-card">
          <div className="metric-card-top"><label>{t("nft.packets")}</label></div>
          <div className="value text-sm">{(stats.total_packets ?? 0).toLocaleString()}</div>
        </div>
      </div>

      <div className="card mt-5">
        <h3 className="card-title mb-4">{t("nft.chainPolicies")}</h3>
        <div className="grid gap-3 md:grid-cols-3">
          {Object.keys(CHAIN_LABELS).map((chain) => {
            const policy = chains[chain]?.policy || "—";
            const isDrop = policy === "drop";
            return (
              <div key={chain} className="rounded-lg border border-border/30 p-3 flex items-center justify-between gap-2">
                <div>
                  <div className="text-sm font-medium">{CHAIN_LABELS[chain]}</div>
                  <div className="text-xs text-muted-foreground">
                    policy: <span className={isDrop ? "text-red-400" : "text-green-400"}>{policy}</span>
                    {chains[chain]?.rule_count != null && ` · ${chains[chain].rule_count} rules`}
                  </div>
                </div>
                <div className="flex gap-1">
                  <button
                    type="button"
                    className={`btn btn-sm ${isDrop ? "btn-danger" : ""}`}
                    disabled={!!pending[`c:${chain}`]}
                    onClick={() => setChainPolicy(chain, "drop")}
                  >
                    drop
                  </button>
                  <button
                    type="button"
                    className={`btn btn-sm ${!isDrop ? "btn-success" : ""}`}
                    disabled={!!pending[`c:${chain}`]}
                    onClick={() => setChainPolicy(chain, "accept")}
                  >
                    accept
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="card mt-5">
        <h3 className="card-title">{t("nft.ipAllowDeny")}</h3>
        <p className="text-xs text-muted-foreground mt-1 mb-3">
          {t("nft.managedSets")}: {nft.managed_sets?.allow || "neohost_allow"} / {nft.managed_sets?.deny || "neohost_deny"}
        </p>
        <div className="flex gap-2 flex-wrap items-center">
          <input className="form-input w-44" placeholder="IP / CIDR" value={ip} onChange={(e) => setIp(e.target.value)} />
          <button type="button" className="btn btn-danger" disabled={!ip} onClick={() => { action("deny", { ip }); setIp(""); }}>
            <Icon name="ban" size={14} /> {t("nft.deny")}
          </button>
          <button type="button" className="btn btn-success" disabled={!ip} onClick={() => { action("allow", { ip }); setIp(""); }}>
            {t("nft.allow")}
          </button>
        </div>
      </div>

      <div className="grid-2 mt-5">
        <div className="card">
          <IpList title={t("nft.denyList")} ips={nft.deny} listType="deny" onRemove={removeIp} emptyLabel={t("nft.noIps")} />
        </div>
        <div className="card">
          <IpList title={t("nft.allowList")} ips={nft.allow} listType="allow" onRemove={removeIp} emptyLabel={t("nft.noIps")} />
        </div>
      </div>

      <div className="card mt-5">
        <h3 className="card-title mb-4">{t("nft.addRule")}</h3>
        <div className="flex flex-wrap gap-2 items-center">
          <select className="form-input w-28" value={ruleChain} onChange={(e) => setRuleChain(e.target.value)}>
            <option value="input">input</option>
            <option value="forward">forward</option>
            <option value="output">output</option>
          </select>
          <input
            className="form-input flex-1 min-w-[200px]"
            placeholder="tcp dport 8080 accept"
            value={ruleExpr}
            onChange={(e) => setRuleExpr(e.target.value)}
          />
          <button
            type="button"
            className="btn btn-primary-sm"
            disabled={!ruleExpr}
            onClick={() => { action("rule", { chain: ruleChain, expr: ruleExpr }); setRuleExpr(""); }}
          >
            <Icon name="plus" size={14} /> {t("nft.add")}
          </button>
        </div>
      </div>

      <div className="card mt-5">
        <h3 className="card-title mb-4">{t("nft.tablesTitle")} ({tables.length})</h3>
        {!tables.length ? (
          <p className="text-muted-foreground text-sm">{t("nft.noTables")}</p>
        ) : (
          <div className="space-y-3">
            {tables.map((tbl) => {
              const key = `${tbl.family}:${tbl.name}`;
              const open = expandedTable === key;
              return (
                <div key={key} className="rounded-lg border border-border/30 overflow-hidden">
                  <button
                    type="button"
                    className="w-full flex items-center justify-between p-3 text-left hover:bg-muted/30"
                    onClick={() => setExpandedTable(open ? null : key)}
                  >
                    <span className="font-medium mono">{tbl.family} {tbl.name}</span>
                    <span className="text-xs text-muted-foreground">
                      {tbl.chains?.length ?? 0} chains · {tbl.sets?.length ?? 0} sets
                    </span>
                  </button>
                  {open && (
                    <div className="p-3 pt-0 border-t border-border/20">
                      {(tbl.sets || []).length > 0 && (
                        <div className="mb-4">
                          <h4 className="text-xs font-semibold text-muted-foreground mb-2 uppercase">{t("nft.sets")}</h4>
                          <div className="space-y-2">
                            {tbl.sets.map((st) => (
                              <div key={st.name} className="rounded border border-border/20 p-2">
                                <div className="flex justify-between items-center mb-1">
                                  <span className="mono text-sm">{st.name}</span>
                                  <span className="text-xs text-muted-foreground">{st.size ?? st.elements?.length ?? 0} elem</span>
                                </div>
                                {st.elements?.length > 0 && (
                                  <div className="text-xs mono text-muted-foreground truncate">
                                    {st.elements.slice(0, 8).join(", ")}{st.elements.length > 8 ? "…" : ""}
                                  </div>
                                )}
                                <button
                                  type="button"
                                  className="btn btn-sm mt-2"
                                  onClick={() => action("flush", { set: st.name })}
                                >
                                  {t("nft.flushSet")}
                                </button>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      {(tbl.chains || []).map((ch) => (
                        <div key={ch.name} className="mb-3">
                          <h4 className="text-sm font-medium mb-1">
                            {ch.name}
                            <span className="text-xs text-muted-foreground ml-2">
                              {ch.hook && `hook ${ch.hook}`} · policy {ch.policy || "—"}
                            </span>
                          </h4>
                          {!ch.rules?.length ? (
                            <p className="text-xs text-muted-foreground">{t("nft.noRules")}</p>
                          ) : (
                            <div className="overflow-x-auto">
                              <table className="data-table text-xs">
                                <thead>
                                  <tr>
                                    <th>handle</th>
                                    <th>{t("nft.expr")}</th>
                                    <th>pkts</th>
                                    <th></th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {ch.rules.map((rule) => (
                                    <tr key={rule.handle}>
                                      <td className="mono">{rule.handle}</td>
                                      <td className="mono max-w-[320px] truncate" title={rule.expr}>{rule.expr}</td>
                                      <td>{rule.packets ?? 0}</td>
                                      <td>
                                        <button
                                          type="button"
                                          className="btn btn-sm btn-danger"
                                          onClick={() => action("rule", { delete: true, handle: rule.handle, chain: ch.name })}
                                        >
                                          <Icon name="trash" size={12} />
                                        </button>
                                      </td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </>
  );
}
