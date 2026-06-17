
import { motion } from "framer-motion";
import { Key, Trash2 } from "lucide-react";
import { Switch } from "./material-design-3-switch";

function formatSync(ts) {
  if (!ts) return "—";
  return ts.substring(0, 19).replace("T", " ");
}

function StatusBadge({ online }) {
  if (online) {
    return (
      <div className="px-3 py-1.5 rounded-lg bg-green-500/10 border border-green-500/30 flex items-center justify-center">
        <span className="text-green-400 text-sm font-medium">Online</span>
      </div>
    );
  }
  return (
    <div className="px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center justify-center">
      <span className="text-red-400 text-sm font-medium">Offline</span>
    </div>
  );
}

export function ModuleToggleChip({ label, enabled, detected, onChange, tone = "f2b", className = "" }) {
  const status = !enabled ? "OFF" : detected ? "OK" : "ON";
  const statusStyles = !enabled
    ? "text-muted-foreground/70"
    : detected
      ? tone === "csf" ? "text-emerald-400" : tone === "nft" ? "text-cyan-400" : "text-purple-300"
      : tone === "csf" ? "text-emerald-400/80" : tone === "nft" ? "text-cyan-400/80" : "text-purple-400/80";
  const activeStyles =
    tone === "csf"
      ? "border-emerald-500/55 bg-emerald-500/10"
      : tone === "nft"
        ? "border-cyan-500/55 bg-cyan-500/10"
        : "border-purple-500/55 bg-purple-500/10";
  const labelStyles =
    tone === "csf"
      ? enabled ? "text-emerald-400" : "text-muted-foreground"
      : tone === "nft"
        ? enabled ? "text-cyan-400" : "text-muted-foreground"
        : enabled ? "text-purple-400" : "text-muted-foreground";

  return (
    <div
      className={`inline-flex items-center gap-1.5 rounded-lg border px-2 py-1 transition-colors shrink-0 whitespace-nowrap ${className} ${
        enabled ? activeStyles : "border-border/35 bg-muted/25"
      }`}
    >
      <span className={`text-[11px] font-semibold tracking-wide ${labelStyles}`}>{label}</span>
      <span className={`text-[10px] font-bold tracking-wider ${statusStyles}`}>{status}</span>
      {onChange && (
        <Switch size="sm" compact checked={!!enabled} onCheckedChange={onChange} />
      )}
    </div>
  );
}

import { useI18n } from "../../i18n";

export function ServerManagementTable({
  title = "Servere",
  servers = [],
  selectedId,
  onSelectServer,
  onShowKey,
  onUpdateModules,
  onEdit,
  onDelete,
  className = "",
}) {
  const { t } = useI18n();
  const onlineCount = servers.filter((s) => s.online).length;

  return (
    <div className={`w-full ${className}`}>
      <div className="relative border border-border/30 rounded-2xl p-6 bg-card">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
              <h2 className="text-xl font-medium text-foreground">{title}</h2>
            </div>
            <span className="text-sm text-muted-foreground">
              {onlineCount} {t("common.online").toLowerCase()} · {servers.length - onlineCount} {t("common.offline").toLowerCase()}
            </span>
          </div>
        </div>

        <div className="hidden md:grid grid-cols-12 gap-4 px-4 py-2 text-xs font-medium text-muted-foreground uppercase tracking-wider">
          <div className="col-span-1">Nr</div>
          <div className="col-span-5">Nume &amp; module</div>
          <div className="col-span-2">Hostname</div>
          <div className="col-span-2">Status</div>
          <div className="col-span-1">Sync</div>
          <div className="col-span-1 text-right">Acțiuni</div>
        </div>

        <motion.div
          className="space-y-2"
          initial="hidden"
          animate="visible"
          variants={{
            visible: { transition: { staggerChildren: 0.08, delayChildren: 0.05 } },
          }}
        >
          {servers.length === 0 && (
            <div className="text-center py-12 text-muted-foreground text-sm">
              {t("dashboard.noServers")}
            </div>
          )}

          {servers.map((server, index) => {
            const isSelected = selectedId === server.id;
            return (
              <motion.div
                key={server.id}
                variants={{
                  hidden: { opacity: 0, x: -20, scale: 0.97 },
                  visible: {
                    opacity: 1,
                    x: 0,
                    scale: 1,
                    transition: { type: "spring", stiffness: 400, damping: 28, mass: 0.6 },
                  },
                }}
              >
                <motion.div
                  className={`relative bg-muted/50 border rounded-xl p-4 overflow-hidden transition-colors ${
                    isSelected
                      ? "border-purple-500/40 ring-1 ring-purple-500/25"
                      : "border-border/50"
                  }`}
                  whileHover={{ y: -1 }}
                  transition={{ type: "spring", stiffness: 400, damping: 25 }}
                >
                  <div
                    className={`absolute inset-0 bg-gradient-to-l pointer-events-none ${
                      server.online ? "from-green-500/10" : "from-red-500/10"
                    } to-transparent`}
                    style={{
                      backgroundSize: "30% 100%",
                      backgroundPosition: "right",
                      backgroundRepeat: "no-repeat",
                    }}
                  />

                  <div className="relative grid grid-cols-1 md:grid-cols-12 gap-3 md:gap-4 items-center">
                    <div className="col-span-1">
                      <span className="text-2xl font-bold text-muted-foreground">
                        {String(index + 1).padStart(2, "0")}
                      </span>
                    </div>

                    <div className="col-span-5 min-w-0">
                      <div className="server-module-row">
                        <button
                          type="button"
                          onClick={() => onSelectServer?.(server)}
                          className="server-module-name"
                          title={server.name}
                        >
                          {server.name}
                        </button>
                        {onUpdateModules ? (
                          <>
                            <ModuleToggleChip
                              label="Fail2Ban"
                              enabled={!!server.mod_fail2ban}
                              detected={!!server.cap_fail2ban}
                              tone="f2b"
                              onChange={(v) => onUpdateModules(server, { mod_fail2ban: v })}
                            />
                            <ModuleToggleChip
                              label="CSF"
                              enabled={!!server.mod_csf}
                              detected={!!server.cap_csf}
                              tone="csf"
                              onChange={(v) => onUpdateModules(server, { mod_csf: v })}
                            />
                            <ModuleToggleChip
                              label="nftables"
                              enabled={!!server.mod_nftables}
                              detected={!!server.cap_nftables}
                              tone="nft"
                              onChange={(v) => onUpdateModules(server, { mod_nftables: v })}
                            />
                          </>
                        ) : (
                          <>
                            <ModuleToggleChip
                              label="Fail2Ban"
                              enabled={!!server.mod_fail2ban}
                              detected={!!server.cap_fail2ban}
                              tone="f2b"
                            />
                            <ModuleToggleChip
                              label="CSF"
                              enabled={!!server.mod_csf}
                              detected={!!server.cap_csf}
                              tone="csf"
                            />
                            <ModuleToggleChip
                              label="nftables"
                              enabled={!!server.mod_nftables}
                              detected={!!server.cap_nftables}
                              tone="nft"
                            />
                          </>
                        )}
                      </div>
                    </div>

                    <div className="col-span-2 min-w-0">
                      <span className="text-foreground font-mono text-sm">
                        {server.hostname || "—"}
                      </span>
                    </div>

                    <div className="col-span-2">
                      <StatusBadge online={server.online} />
                    </div>

                    <div className="col-span-1">
                      <span className="text-muted-foreground text-sm whitespace-nowrap">
                        {formatSync(server.last_seen)}
                      </span>
                    </div>

                    <div className="col-span-1 flex items-center justify-end gap-1.5">
                      {onEdit && (
                        <button
                          type="button"
                          onClick={(e) => { e.stopPropagation(); onEdit(server); }}
                          className="w-8 h-8 bg-background/80 hover:bg-background rounded-lg flex items-center justify-center border border-border/50 text-muted-foreground hover:text-foreground transition-colors text-xs font-bold"
                          title="Edit"
                        >
                          ✎
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={(e) => { e.stopPropagation(); onShowKey?.(server); }}
                        className="w-8 h-8 bg-background/80 hover:bg-background rounded-lg flex items-center justify-center border border-border/50 text-muted-foreground hover:text-foreground transition-colors"
                        title="Agent Key"
                      >
                        <Key className="w-3.5 h-3.5" />
                      </button>
                      <button
                        type="button"
                        onClick={(e) => { e.stopPropagation(); onDelete?.(server.id); }}
                        className="w-8 h-8 bg-background/80 hover:bg-background rounded-lg flex items-center justify-center border border-border/50 text-muted-foreground hover:text-red-400 hover:border-red-500/30 transition-colors"
                        title={t("common.delete")}
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                </motion.div>
              </motion.div>
            );
          })}
        </motion.div>
      </div>
    </div>
  );
}
