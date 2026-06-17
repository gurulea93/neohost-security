import Icon from "./Icons";
import { FormSelect } from "./components/ui/form-select";
import { useTheme } from "./context/ThemeContext";
import { useBranding } from "./context/BrandingContext";
import { useI18n } from "./i18n";
import { PanelBrand } from "./components/PanelBrand";

const NAV = [
  { sectionKey: "nav.principal" },
  { id: "monitor", icon: "dashboard", labelKey: "nav.monitor" },
  { id: "intel", icon: "globe", labelKey: "nav.intel" },
  { sectionKey: "nav.sectSecurity" },
  { id: "jails", icon: "shield", labelKey: "nav.jails" },
  { id: "security", icon: "activity", labelKey: "nav.security" },
  { id: "csf", icon: "lock", labelKey: "nav.csf" },
  { id: "nftables", icon: "shield", labelKey: "nav.nftables" },
  { id: "history", icon: "history", labelKey: "nav.history" },
  { id: "connections", icon: "link", labelKey: "nav.connections" },
  { sectionKey: "nav.admin" },
  { id: "servers", icon: "server", labelKey: "nav.servers" },
  { id: "profile", icon: "users", labelKey: "nav.profile" },
];

const TITLES = {
  monitor: { titleKey: "nav.monitor", subKey: "pages.monitorSub" },
  intel: { titleKey: "nav.intel", subKey: "pages.intelSub" },
  jails: { titleKey: "nav.jails", subKey: "pages.jailsSub" },
  security: { titleKey: "nav.security", subKey: "pages.securitySub" },
  history: { titleKey: "nav.history", subKey: "pages.historySub" },
  connections: { titleKey: "nav.connections", subKey: "pages.connectionsSub" },
  csf: { titleKey: "nav.csf", subKey: "pages.csfSub" },
  nftables: { titleKey: "nav.nftables", subKey: "pages.nftablesSub" },
  servers: { titleKey: "nav.servers", subKey: "pages.serversSub" },
  profile: { titleKey: "nav.profile", subKey: "pages.profileSub" },
};

export default function Layout({
  page, setPage, children,
  servers, serverId, selectServer, activeServer,
  connected, onLogout, onPause, paused,
  onExport, clock,
}) {
  const { theme, toggleTheme } = useTheme();
  const { branding } = useBranding();
  const { t, lang, setLang, languages } = useI18n();
  const meta = TITLES[page] || TITLES.monitor;

  const navItems = NAV.filter((item) => {
    if (!item.id) return true;
    if (item.id === "jails") return !activeServer || activeServer.mod_fail2ban;
    if (item.id === "security") return !!activeServer;
    if (item.id === "csf") return !activeServer || activeServer.mod_csf;
    if (item.id === "nftables") return !activeServer || activeServer.mod_nftables;
    return true;
  });

  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="sidebar-logo">
          <PanelBrand branding={branding} />
        </div>
        <nav className="sidebar-nav">
          {navItems.map((item, i) =>
            item.sectionKey ? (
              <div key={i} className="nav-section">{t(item.sectionKey)}</div>
            ) : (
              <button
                key={item.id}
                className={`nav-item${page === item.id ? " active" : ""}`}
                onClick={() => setPage(item.id)}
              >
                <Icon name={item.icon} size={18} />
                {t(item.labelKey)}
              </button>
            )
          )}
        </nav>
        <div className="sidebar-footer">
          <button className="nav-item danger" onClick={onLogout}>
            <Icon name="logout" size={18} />
            {t("nav.logout")}
          </button>
        </div>
      </aside>

      <div className="main-area">
        <header className="topbar">
          <div className="topbar-title">
            <h1>{t(meta.titleKey)}</h1>
            <p>{t(meta.subKey)}</p>
          </div>
          <div className="topbar-actions">
            <FormSelect
              className="w-[110px]"
              value={lang}
              onChange={setLang}
              options={languages.map((l) => ({ value: l, label: t(`lang.${l}`) }))}
            />
            {page !== "servers" && page !== "profile" && servers.length > 0 && (
              <FormSelect
                className="w-[200px]"
                value={serverId || ""}
                onChange={(v) => selectServer(parseInt(v, 10))}
                options={servers.map((s) => ({
                  value: s.id,
                  label: `${s.online ? t("common.online") : t("common.offline")} — ${s.name}`,
                }))}
              />
            )}
            <span className="status-pill">
              <span className={`status-dot ${connected ? "live" : "off"}`} />
              {connected ? t("layout.live") : t("common.offline")}
            </span>
            <span className="clock-label">{clock}</span>
            <button className="icon-btn" onClick={toggleTheme} title={theme === "dark" ? t("layout.themeLight") : t("layout.themeDark")}>
              <Icon name={theme === "dark" ? "sun" : "moon"} size={16} />
            </button>
            <button className="icon-btn" onClick={onPause} title={paused ? t("layout.resume") : t("layout.pause")}>
              <Icon name={paused ? "play" : "pause"} size={16} />
            </button>
            <button className="icon-btn" onClick={() => onExport("csv")} title={t("layout.exportCsv")}>
              <Icon name="download" size={16} />
            </button>
            <div className="avatar" onClick={() => setPage("profile")} title={t("nav.profile")}>NH</div>
          </div>
        </header>
        <main className="content">{children}</main>
      </div>
    </div>
  );
}

export { TITLES };
