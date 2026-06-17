import { config } from "../config.js";
import { clientIpFromRequest, checkIpWhitelist, getTelegramWebSession } from "../lib/security.js";
import { getPanelSession, getPrimaryPanelUser } from "../lib/panelAuth.js";

export function getBearerToken(req) {
  const auth = String(req.headers.authorization || "");
  if (!auth.startsWith("Bearer ")) return "";
  return auth.slice(7);
}

export async function requireAuth(req, res, next) {
  const token = getBearerToken(req);
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  const clientIp = clientIpFromRequest(req);
  if (token === config.securityApiToken) {
    if (!(await checkIpWhitelist(clientIp))) {
      return res.status(403).json({ error: "IP neautorizat pentru panou", code: "ip_not_whitelisted", client_ip: clientIp });
    }
    req.authType = "legacy_token";
    req.accountUser = await getPrimaryPanelUser();
    return next();
  }
  const panelUser = await getPanelSession(token);
  if (panelUser) {
    if (!(await checkIpWhitelist(clientIp))) {
      return res.status(403).json({ error: "IP neautorizat pentru panou", code: "ip_not_whitelisted", client_ip: clientIp });
    }
    req.authType = "panel";
    req.panelUser = panelUser;
    req.panelToken = token;
    req.accountUser = panelUser;
    return next();
  }
  const tgUser = await getTelegramWebSession(token);
  if (tgUser) {
    req.authType = "telegram";
    req.telegramUser = tgUser;
    return next();
  }
  return res.status(401).json({ error: "Unauthorized" });
}

export async function requireAgent(req, res, next) {
  const key = String(req.headers["x-agent-key"] || "");
  if (!key) return res.status(401).json({ error: "X-Agent-Key lipsă" });
  const { queryOne } = await import("../db/index.js");
  const server = await queryOne("SELECT * FROM servers WHERE agent_key = ? AND is_active = 1", [key]);
  if (!server) return res.status(401).json({ error: "Agent key invalid" });
  req.server = server;
  return next();
}
