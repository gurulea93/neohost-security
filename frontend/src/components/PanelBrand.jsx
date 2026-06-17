import Icon from "../Icons";

export function PanelBrand({ branding, iconSize = 20, className = "" }) {
  const name = branding?.panel_name || "NeoHost";
  const mode = branding?.logo_mode || "both";
  const logo = branding?.logo_data;

  const showLogo = (mode === "logo" || mode === "both") && logo;
  const showText = mode === "text" || mode === "both";

  return (
    <div className={`sidebar-logo-inner ${className}`.trim()}>
      {showLogo ? (
        <img src={logo} alt="" className="panel-brand-logo" />
      ) : (
        <div className="sidebar-logo-icon">
          <Icon name="shield" size={iconSize} />
        </div>
      )}
      {showText && <span className="panel-brand-text">{name}</span>}
    </div>
  );
}
