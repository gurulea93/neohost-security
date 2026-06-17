import { createContext, useCallback, useContext, useEffect, useState } from "react";

const DEFAULTS = {
  panel_name: "NeoHost",
  panel_tagline: "Security Monitor",
  logo_mode: "both",
  logo_data: "",
  favicon_data: "",
  accent_color: "#9333ea",
  accent_preset: "purple",
};

const BrandingContext = createContext({
  branding: DEFAULTS,
  loading: true,
  refreshBranding: async () => {},
  applyBranding: () => {},
});

function applyFavicon(dataUrl) {
  let link = document.querySelector("link[rel~='icon']");
  if (!link) {
    link = document.createElement("link");
    link.rel = "icon";
    document.head.appendChild(link);
  }
  if (dataUrl) {
    link.href = dataUrl;
  } else {
    link.removeAttribute("href");
  }
}

function applyDocumentTitle(branding) {
  const name = branding?.panel_name || DEFAULTS.panel_name;
  const tag = branding?.panel_tagline || DEFAULTS.panel_tagline;
  document.title = tag ? `${name} — ${tag}` : name;
}

function applyAccentColor(hex) {
  if (!hex || !/^#[0-9a-fA-F]{6}$/i.test(hex)) return;
  document.documentElement.style.setProperty("--accent-hex", hex);
}

export function applyBrandingToDocument(branding) {
  applyFavicon(branding?.favicon_data);
  applyDocumentTitle(branding);
  applyAccentColor(branding?.accent_color);
}

export function BrandingProvider({ children, apiUrl }) {
  const [branding, setBranding] = useState(DEFAULTS);
  const [loading, setLoading] = useState(true);

  const refreshBranding = useCallback(async (base) => {
    const url = (base || apiUrl || "").replace(/\/$/, "");
    if (!url) {
      setLoading(false);
      return DEFAULTS;
    }
    try {
      const r = await fetch(`${url}/api/branding`);
      if (!r.ok) throw new Error("branding fetch failed");
      const d = await r.json();
      const next = { ...DEFAULTS, ...d };
      setBranding(next);
      applyBrandingToDocument(next);
      return next;
    } catch {
      return null;
    } finally {
      setLoading(false);
    }
  }, [apiUrl]);

  useEffect(() => {
    refreshBranding();
  }, [refreshBranding]);

  const applyBranding = useCallback((next) => {
    const merged = { ...DEFAULTS, ...next };
    setBranding(merged);
    applyBrandingToDocument(merged);
  }, []);

  return (
    <BrandingContext.Provider value={{ branding, loading, refreshBranding, applyBranding }}>
      {children}
    </BrandingContext.Provider>
  );
}

export function useBranding() {
  return useContext(BrandingContext);
}
