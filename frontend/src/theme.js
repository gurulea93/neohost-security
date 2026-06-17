export const theme = {
  primary: "#3758F9",
  primaryHover: "#2d47d8",
  primaryLight: "#EEF2FF",
  secondary: "#637381",
  success: "#22AD5C",
  successLight: "#DAF8E6",
  warning: "#F59E0B",
  warningLight: "#FEF3C7",
  error: "#F23030",
  errorLight: "#FEEBEB",
  info: "#0BA5EC",
  bg: "#F9FAFB",
  paper: "#FFFFFF",
  text: "#111928",
  textSecondary: "#637381",
  textMuted: "#9CA3AF",
  border: "#E5E7EB",
  sidebar: "#FFFFFF",
  sidebarHover: "#F3F4F6",
  sidebarActive: "#EEF2FF",
  shadow: "0px 1px 3px 0px rgba(166, 175, 195, 0.4)",
  shadowMd: "0px 4px 12px 0px rgba(13, 10, 44, 0.06)",
  radius: 8,
  radiusLg: 12,
  font: "'Inter', system-ui, sans-serif",
};

/** Sonata-inspired palette for dark mode (sonata.tariqdev.xyz) */
export const themeSonata = {
  ...theme,
  primary: "#9333ea",
  primaryHover: "#a855f7",
  primaryLight: "rgba(147, 51, 234, 0.12)",
  bg: "#08080a",
  paper: "#111116",
  text: "#ffffff",
  textSecondary: "#a1a1aa",
  textMuted: "#71717a",
  border: "#27272a",
  sidebar: "#0d0d11",
  sidebarHover: "#1a1a1f",
  sidebarActive: "rgba(147, 51, 234, 0.12)",
};

export const uiTheme = (isDark) => (isDark ? themeSonata : theme);

export const THREAT = {
  LOW: { color: "#22AD5C", bg: "#DAF8E6" },
  MEDIUM: { color: "#F59E0B", bg: "#FEF3C7" },
  HIGH: { color: "#F23030", bg: "#FEEBEB" },
  CRITICAL: { color: "#7C3AED", bg: "#EDE9FE" },
};

export const THREAT_DARK = {
  LOW: { color: "#10b981", bg: "rgba(16, 185, 129, 0.1)", border: "rgba(16, 185, 129, 0.18)" },
  MEDIUM: { color: "#f97316", bg: "rgba(249, 115, 22, 0.1)", border: "rgba(249, 115, 22, 0.18)" },
  HIGH: { color: "#ef4444", bg: "rgba(239, 68, 68, 0.1)", border: "rgba(239, 68, 68, 0.18)" },
  CRITICAL: { color: "#c084fc", bg: "rgba(147, 51, 234, 0.12)", border: "rgba(147, 51, 234, 0.22)" },
};

export const threatStyleFor = (level, isDark) => {
  const palette = isDark ? THREAT_DARK : THREAT;
  return palette[level] || palette.LOW;
};

export const countryLabel = (code, name) => {
  if (!code && !name) return "—";
  return name ? `${code || ""} ${name}`.trim() : code;
};
