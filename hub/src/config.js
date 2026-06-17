import path from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const HUB_ROOT = path.resolve(__dirname, "..");

dotenv.config({ path: path.join(HUB_ROOT, ".env") });
dotenv.config();

export const config = {
  host: process.env.HOST || "127.0.0.1",
  port: Number(process.env.PORT || 7654),
  nodeEnv: process.env.NODE_ENV || "development",
  serveStatic: process.env.SERVE_STATIC === "1" || process.env.NODE_ENV === "production",
  databaseUrl: process.env.DATABASE_URL || `sqlite:///${path.join(HUB_ROOT, "data", "neohost.db").replace(/\\/g, "/")}`,
  securityApiToken: process.env.SECURITY_API_TOKEN || "schimba-acest-token-secret",
  abuseIpdbKey: process.env.ABUSEIPDB_API_KEY || "",
  metricRetentionHours: Number(process.env.METRIC_RETENTION_HOURS || 48),
  panelSessionHours: Number(process.env.PANEL_SESSION_HOURS || 24),
  panelTotpIssuer: process.env.PANEL_TOTP_ISSUER || "NeoHost Security",
  panelAdminUsername: process.env.PANEL_ADMIN_USERNAME || "admin",
  panelAdminPassword: process.env.PANEL_ADMIN_PASSWORD || "admin",
  telegramBotToken: process.env.TELEGRAM_BOT_TOKEN || "",
  telegramWebAppUrl: (process.env.TELEGRAM_WEBAPP_URL || "").replace(/\/+$/, ""),
  panelAllowLocalhost: process.env.PANEL_ALLOW_LOCALHOST === "1",
  hubRoot: HUB_ROOT
};

export function isProductionLike() {
  return config.serveStatic;
}
