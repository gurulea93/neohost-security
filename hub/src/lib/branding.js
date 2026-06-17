import { exec, queryAll } from "../db/index.js";
import { getSetting, setSetting } from "./security.js";

const LOGO_MODES = new Set(["text", "logo", "both"]);
const ACCENT_PRESETS = {
  purple: "#9333ea",
  blue: "#3758F9",
  green: "#22AD5C",
  orange: "#f97316",
  red: "#ef4444",
  cyan: "#06b6d4",
  pink: "#ec4899"
};

function hex(v) {
  return /^#[0-9a-fA-F]{6}$/.test(v || "");
}

function brandingForHistory(b) {
  const { logo_data: logo, favicon_data: fav, ...rest } = b;
  return {
    ...rest,
    logo_data: logo ? `[${logo.length} chars]` : "",
    favicon_data: fav ? `[${fav.length} chars]` : ""
  };
}

export async function getBranding() {
  const logoMode = LOGO_MODES.has(await getSetting("branding_logo_mode", "both")) ? await getSetting("branding_logo_mode", "both") : "both";
  const preset = await getSetting("branding_accent_preset", "purple");
  const custom = await getSetting("branding_accent_color", "");
  const accent = custom && hex(custom) ? custom : (ACCENT_PRESETS[preset] || "#9333ea");
  return {
    panel_name: (await getSetting("branding_panel_name", "NeoHost")) || "NeoHost",
    panel_tagline: (await getSetting("branding_panel_tagline", "Security Monitor")) || "Security Monitor",
    logo_mode: logoMode,
    logo_data: await getSetting("branding_logo_data", ""),
    favicon_data: await getSetting("branding_favicon_data", ""),
    accent_color: accent,
    accent_preset: preset in ACCENT_PRESETS ? preset : "purple",
    accent_presets: ACCENT_PRESETS
  };
}

export async function updateBranding(data, user = null) {
  const before = await getBranding();
  const out = { ...before };
  if ("panel_name" in data) {
    const name = String(data.panel_name || "").trim();
    if (!name || name.length > 80) throw new Error("Denumirea panoului trebuie să aibă 1–80 caractere");
    await setSetting("branding_panel_name", name);
    out.panel_name = name;
  }
  if ("panel_tagline" in data) {
    const t = String(data.panel_tagline || "").trim();
    if (t.length > 120) throw new Error("Subtitlul poate avea maxim 120 caractere");
    await setSetting("branding_panel_tagline", t);
    out.panel_tagline = t;
  }
  if ("logo_mode" in data) {
    const m = String(data.logo_mode || "").trim();
    if (!LOGO_MODES.has(m)) throw new Error("Mod logo invalid (text, logo, both)");
    await setSetting("branding_logo_mode", m);
    out.logo_mode = m;
  }
  if ("logo_data" in data) {
    await setSetting("branding_logo_data", String(data.logo_data || ""));
    out.logo_data = String(data.logo_data || "");
  }
  if ("favicon_data" in data) {
    await setSetting("branding_favicon_data", String(data.favicon_data || ""));
    out.favicon_data = String(data.favicon_data || "");
  }
  if (data.clear_logo) {
    await setSetting("branding_logo_data", "");
    out.logo_data = "";
  }
  if (data.clear_favicon) {
    await setSetting("branding_favicon_data", "");
    out.favicon_data = "";
  }
  if ("accent_preset" in data) {
    const preset = String(data.accent_preset || "");
    if (!(preset in ACCENT_PRESETS) && preset !== "custom") throw new Error("Preset accent invalid");
    await setSetting("branding_accent_preset", preset);
    if (preset in ACCENT_PRESETS) {
      await setSetting("branding_accent_color", ACCENT_PRESETS[preset]);
      out.accent_color = ACCENT_PRESETS[preset];
    }
    out.accent_preset = preset;
  }
  if ("accent_color" in data) {
    const c = String(data.accent_color || "").trim();
    if (c && !hex(c)) throw new Error("Culoare accent invalidă (#RRGGBB)");
    if (c) {
      await setSetting("branding_accent_color", c);
      await setSetting("branding_accent_preset", "custom");
      out.accent_color = c;
      out.accent_preset = "custom";
    }
  }
  await exec(
    "INSERT INTO branding_history (user_id, username, changes, snapshot, created_at) VALUES (?, ?, ?, ?, ?)",
    [
      user?.id || null,
      user?.username || "system",
      JSON.stringify({ from: brandingForHistory(before), to: brandingForHistory(out) }),
      JSON.stringify(brandingForHistory(out)),
      new Date().toISOString()
    ]
  );
  return out;
}

export async function listBrandingHistory(limit = 50) {
  const rows = await queryAll("SELECT * FROM branding_history ORDER BY created_at DESC LIMIT ?", [Math.min(limit, 100)]);
  return rows.map((r) => ({
    id: r.id,
    username: r.username || "",
    changes: JSON.parse(r.changes || "{}"),
    snapshot: JSON.parse(r.snapshot || "{}"),
    created_at: r.created_at || null
  }));
}
