import { useMemo, useState, useRef, useEffect, useCallback } from "react";
import {
  Map,
  MapArc,
  MapMarker,
  MarkerContent,
  MarkerLabel,
  MapControls,
} from "@/components/ui/mapcn-map-cluster-layer";
import { useTheme } from "../context/ThemeContext";
import { useI18n } from "../i18n";

const SERVER_HUB = { name: "Server", lng: 26.1025, lat: 44.4268 };

function countryFlag(code) {
  if (!code || code.length !== 2 || code === "XX") return "🌐";
  const a = 0x1f1e6 - 65;
  return String.fromCodePoint(...[...code.toUpperCase()].map((c) => a + c.charCodeAt(0)));
}

function severityColor(count, max) {
  const ratio = max > 0 ? (count || 0) / max : 0;
  if (ratio >= 0.66) return { fill: "#ef4444", ring: "rgba(239,68,68,0.45)", glow: "rgba(239,68,68,0.55)" };
  if (ratio >= 0.33) return { fill: "#f97316", ring: "rgba(249,115,22,0.4)", glow: "rgba(249,115,22,0.45)" };
  return { fill: "#fb923c", ring: "rgba(251,146,60,0.35)", glow: "rgba(251,146,60,0.35)" };
}

function markerSize(count, max) {
  const ratio = max > 0 ? Math.sqrt((count || 1) / max) : 0.5;
  return Math.max(8, Math.min(20, 8 + ratio * 12));
}

function CountryDetailPanel({ country, mode, maxCount, onIpClick, onPin, pinned, t }) {
  if (!country) {
    return (
      <div className="attack-map-detail-empty">
        <p className="text-xs text-muted-foreground leading-relaxed">
          {t("intel.hoverHint")}
        </p>
        <div className="attack-map-legend mt-4">
          <span className="attack-map-legend-item"><i className="dot dot-low" /> {t("intel.legendLow")}</span>
          <span className="attack-map-legend-item"><i className="dot dot-mid" /> {t("intel.legendMid")}</span>
          <span className="attack-map-legend-item"><i className="dot dot-high" /> {t("intel.legendHigh")}</span>
          <span className="attack-map-legend-item"><i className="dot dot-server" /> {t("intel.serverHub")}</span>
        </div>
      </div>
    );
  }

  const sev = severityColor(country.count, maxCount);
  const ips = country.ips || [];
  const showAll = mode === "pinned";
  const visibleIps = showAll ? ips : ips.slice(0, 6);

  return (
    <div className="attack-map-detail-body">
      <div className="attack-map-detail-header">
        <div>
          <div className="attack-map-detail-country">
            <span className="text-lg" aria-hidden>{countryFlag(country.code)}</span>
            <span>{country.country || country.code || t("intel.unknown")}</span>
            {country.code && <span className="text-muted-foreground text-xs font-normal">({country.code})</span>}
          </div>
          <p className="text-[11px] text-muted-foreground mt-0.5">
            {mode === "pinned" ? t("intel.pinned") : t("intel.preview")}
          </p>
        </div>
        {mode === "hover" && (
          <button type="button" className="btn btn-sm btn-primary-sm text-[11px] px-2 py-1" onClick={() => onPin?.(country)}>
            {t("intel.pin")}
          </button>
        )}
        {mode === "pinned" && pinned && (
          <button type="button" className="btn btn-sm text-[11px] px-2 py-1" onClick={() => onPin?.(null)}>
            {t("common.close")}
          </button>
        )}
      </div>

      <div className="attack-map-detail-stats">
        <div className="attack-map-stat" style={{ borderColor: sev.ring }}>
          <label>{t("intel.bans")}</label>
          <strong style={{ color: sev.fill }}>{country.count}</strong>
        </div>
        <div className="attack-map-stat">
          <label>{t("intel.uniqueIps")}</label>
          <strong>{country.unique_ips ?? ips.length}</strong>
        </div>
      </div>

      {(country.jails || []).length > 0 && (
        <div className="attack-map-detail-section">
          <h4>{t("intel.affectedJails")}</h4>
          <div className="attack-map-tags">
            {country.jails.map((j) => (
              <span key={j.name} className="attack-map-tag">{j.name} <em>{j.count}</em></span>
            ))}
          </div>
        </div>
      )}

      {(country.isps || []).length > 0 && (
        <div className="attack-map-detail-section">
          <h4>{t("intel.isps")}</h4>
          <ul className="attack-map-mini-list">
            {country.isps.map((isp) => (
              <li key={isp.name}>
                <span className="truncate">{isp.name}</span>
                <span className="mono text-muted-foreground">{isp.count}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="attack-map-detail-section attack-map-detail-section-ips">
        <h4>{t("intel.blockedIps")} {ips.length > 0 && <span className="text-muted-foreground font-normal">({ips.length})</span>}</h4>
        {ips.length === 0 ? (
          <p className="text-xs text-muted-foreground">{t("intel.noIpsCountry")}</p>
        ) : (
          <div className="attack-map-ip-scroll">
            <ul className="attack-map-ip-list">
              {visibleIps.map((row) => (
                <li key={row.ip}>
                  <button
                    type="button"
                    className="attack-map-ip-btn"
                    onClick={() => onIpClick?.(row.ip)}
                    title={t("intel.ipDetails")}
                  >
                    <span className="mono">{row.ip}</span>
                    <span className="attack-map-ip-count">{row.count}×</span>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        )}
        {!showAll && ips.length > visibleIps.length && (
          <p className="text-[11px] text-purple-400 mt-2 shrink-0">{t("intel.moreIps", { count: ips.length - visibleIps.length })}</p>
        )}
      </div>
    </div>
  );
}

/** Hartă atacuri — glob + panou detalii */
export default function AttackMap({ countries = [], serverName, hub, onIpClick }) {
  const { theme } = useTheme();
  const { t } = useI18n();
  const [pinned, setPinned] = useState(null);
  const [hovered, setHovered] = useState(null);
  const shellRef = useRef(null);
  const mapRef = useRef(null);
  const hoverTimer = useRef(null);

  useEffect(() => {
    const el = shellRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => mapRef.current?.resize?.());
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    setPinned(null);
    setHovered(null);
  }, [countries]);

  const serverHub = useMemo(() => {
    const lat = hub?.lat ?? hub?.latitude;
    const lng = hub?.lng ?? hub?.longitude;
    if (lat != null && lng != null && (lat !== 0 || lng !== 0)) {
      const label = hub?.label || hub?.location_label || serverName || "Server";
      return { lat, lng, name: label };
    }
    return {
      lat: SERVER_HUB.lat,
      lng: SERVER_HUB.lng,
      name: serverName ? `${serverName}` : SERVER_HUB.name,
    };
  }, [hub, serverName]);

  const points = useMemo(
    () =>
      [...countries]
        .filter((c) => c.lat != null && c.lon != null && (c.lat !== 0 || c.lon !== 0))
        .sort((a, b) => (b.count || 0) - (a.count || 0))
        .slice(0, 32),
    [countries],
  );

  const maxCount = useMemo(
    () => Math.max(...points.map((p) => p.count || 0), 1),
    [points],
  );

  const arcs = useMemo(
    () =>
      points.map((c) => ({
        id: c.code || c.country || `${c.lon}-${c.lat}`,
        from: [c.lon, c.lat],
        to: [serverHub.lng, serverHub.lat],
        count: c.count,
      })),
    [points, serverHub],
  );

  const hubName = serverHub.name;

  const selectCountry = useCallback((c) => {
    setPinned(c);
    setHovered(null);
  }, []);

  const hoverCountry = useCallback((c) => {
    if (hoverTimer.current) clearTimeout(hoverTimer.current);
    setHovered(c);
  }, []);

  const leaveCountry = useCallback(() => {
    if (hoverTimer.current) clearTimeout(hoverTimer.current);
    hoverTimer.current = setTimeout(() => {
      setHovered(null);
    }, 120);
  }, []);

  const activeCountry = hovered || pinned;
  const sameAsPinned = pinned && hovered
    && (pinned.code === hovered.code || pinned.country === hovered.country);
  const panelMode = pinned && (!hovered || sameAsPinned)
    ? "pinned"
    : hovered
      ? "hover"
      : "idle";

  return (
    <div className="intel-map-block">
      <div className="card intel-map-main-card intel-map-full">
        <h3 className="card-title">{t("intel.attackMap")}</h3>
        <div className="attack-map-shell flex-1 min-h-0">
          {points.length === 0 ? (
            <div className="attack-map-empty col-span-full">{t("intel.noGeo")}</div>
          ) : (
            <>
              <div ref={shellRef} className="attack-map-container attack-map-globe min-h-0">
                <Map
              ref={mapRef}
              theme={theme}
              center={[serverHub.lng, serverHub.lat]}
              zoom={1.35}
              fadeDuration={0}
              projection={{ type: "globe" }}
              className="h-full w-full attack-map-canvas"
            >
              <MapArc
                data={arcs}
                paint={{
                  "line-color": [
                    "interpolate", ["linear"], ["get", "count"],
                    1, "#a855f7",
                    maxCount * 0.5, "#e879f9",
                    maxCount, "#ef4444",
                  ],
                  "line-width": 1.8,
                  "line-opacity": 0.55,
                }}
                curvature={0.35}
                interactive={false}
              />
              <MapMarker longitude={serverHub.lng} latitude={serverHub.lat}>
                <MarkerContent>
                  <div className="attack-map-server-marker">
                    <div className="attack-map-server-core" />
                    <div className="attack-map-server-pulse" />
                  </div>
                  <MarkerLabel position="top" className="attack-map-server-label">
                    {hubName}
                  </MarkerLabel>
                </MarkerContent>
              </MapMarker>
              {points.map((c) => {
                const key = c.code || c.country || `${c.lon}-${c.lat}`;
                const isActive = activeCountry && (activeCountry.code === c.code || activeCountry.country === c.country);
                const sev = severityColor(c.count, maxCount);
                const size = markerSize(c.count, maxCount);
                return (
                  <MapMarker
                    key={key}
                    longitude={c.lon}
                    latitude={c.lat}
                    onClick={() => selectCountry(c)}
                    onMouseEnter={() => hoverCountry(c)}
                    onMouseLeave={leaveCountry}
                  >
                    <MarkerContent>
                      <div
                        className={`attack-map-attack-marker ${isActive ? "attack-map-attack-marker-active" : ""}`}
                        style={{
                          width: size,
                          height: size,
                          background: sev.fill,
                          boxShadow: `0 0 ${isActive ? 14 : 8}px ${sev.glow}`,
                          outlineColor: sev.ring,
                        }}
                        title={`${c.country || c.code}: ${c.count} bannuri`}
                      />
                    </MarkerContent>
                  </MapMarker>
                );
              })}
              <MapControls showCompass />
            </Map>
          </div>

          <div
            className="attack-map-detail-inner"
            onMouseEnter={() => hoverTimer.current && clearTimeout(hoverTimer.current)}
            onMouseLeave={leaveCountry}
          >
            <h4 className="attack-map-detail-heading">{t("intel.detailsTitle")}</h4>
            <CountryDetailPanel
              country={activeCountry}
              mode={panelMode}
              maxCount={maxCount}
              onIpClick={onIpClick}
              onPin={(c) => (c ? selectCountry(c) : setPinned(null))}
              pinned={pinned}
              t={t}
            />
          </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
