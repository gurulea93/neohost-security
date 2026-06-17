import { clientIpFromRequest, checkIpWhitelist } from "../lib/security.js";

const BYPASS_PREFIXES = ["/api/agent/", "/api/status"];

export async function enforcePanelIpWhitelist(req, res, next) {
  if (BYPASS_PREFIXES.some((p) => req.path.startsWith(p))) return next();
  const clientIp = clientIpFromRequest(req);
  if (await checkIpWhitelist(clientIp)) return next();
  if (req.path.startsWith("/api/")) {
    return res.status(403).json({
      error: "IP neautorizat pentru panou",
      code: "ip_not_whitelisted",
      client_ip: clientIp
    });
  }
  return res.status(403).type("text/plain").send(`Acces interzis. IP-ul ${clientIp} nu este autorizat pentru panou.`);
}
