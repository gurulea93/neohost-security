import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import express from "express";
import cors from "cors";
import { WebSocketServer } from "ws";
import { fileURLToPath } from "node:url";
import { config } from "./config.js";
import { initDb, queryAll, queryOne, exec } from "./db/index.js";
import createRoutes from "./routes/index.js";
import { ensureDefaultAdmin } from "./lib/panelAuth.js";
import { ensureBuiltinTemplates } from "./lib/securityTemplates.js";
import { getPanelSession } from "./lib/panelAuth.js";
import { getTelegramBotToken, getTelegramWebAppUrl, setSetting } from "./lib/security.js";
import { cacheTelegramBotUsername, startTelegramBot } from "./services/telegram.js";
import { enforcePanelIpWhitelist } from "./middleware/panelIp.js";
import { clientIpFromRequest, checkIpWhitelist } from "./lib/security.js";

const app = express();
app.set("trust proxy", true);
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: "12mb" }));

const wsClients = new Map();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function safeJson(data) {
  return JSON.stringify(data, (_k, v) => (v instanceof Date ? v.toISOString() : v));
}

function broadcastWs(serverId, payload) {
  const msg = safeJson(payload);
  for (const [ws, sid] of wsClients.entries()) {
    if (sid !== serverId) continue;
    try {
      ws.send(msg);
    } catch {
      wsClients.delete(ws);
    }
  }
}

app.use(enforcePanelIpWhitelist);
app.use(createRoutes({ broadcastWs }));

if (config.serveStatic) {
  const staticDir = path.resolve(__dirname, "..", "..", "frontend", "dist");
  if (fs.existsSync(staticDir)) {
    app.use(express.static(staticDir));
    app.get("*", (_req, res) => res.sendFile(path.join(staticDir, "index.html")));
  }
}

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: "/ws" });

async function wsTokenOk(token) {
  if (token === config.securityApiToken) return true;
  return !!(await getPanelSession(token));
}

async function loadBans(serverId, limit = 100) {
  const rows = await queryAll("SELECT * FROM ban_records WHERE server_id = ? ORDER BY ts DESC LIMIT ?", [serverId, limit]);
  return rows.map((b) => ({
    ts: b.ts, ip: b.ip, jail: b.jail, country: b.country || "", country_code: b.country_code || "",
    city: b.city || "", isp: b.isp || "", lat: b.lat || 0, lon: b.lon || 0
  }));
}

async function loadIntel(serverId) {
  const { computeThreatLevel, computeTopAttackers, computeCountryStats, computeJailStats, computeBanTimeline } = await import("./lib/intelligence.js");
  const bans = await loadBans(serverId, 5000);
  return {
    threat: computeThreatLevel(bans.map((b) => b.ts)),
    top10: computeTopAttackers(bans, 10),
    countries: computeCountryStats(bans),
    jail_stats: computeJailStats(bans),
    timeline: computeBanTimeline(bans),
    total_bans: bans.length
  };
}

wss.on("connection", async (ws, req) => {
  const clientIp = clientIpFromRequest(req);
  if (!(await checkIpWhitelist(clientIp))) {
    try {
      ws.send(safeJson({ type: "error", message: "IP neautorizat pentru panou" }));
      ws.close();
    } catch { /* noop */ }
    return;
  }
  let serverId = null;
  const timer = setTimeout(() => { try { ws.close(); } catch { /* noop */ } }, 5000);

  ws.on("message", async (buf) => {
    try {
      const msg = JSON.parse(String(buf || ""));
      if (!serverId) {
        if (!(await wsTokenOk(msg.token || ""))) {
          ws.send(safeJson({ type: "error", message: "Unauthorized" }));
          ws.close();
          return;
        }
        if (!msg.server_id) {
          ws.send(safeJson({ type: "error", message: "server_id obligatoriu" }));
          ws.close();
          return;
        }
        const s = await queryOne("SELECT * FROM servers WHERE id = ?", [Number(msg.server_id)]);
        if (!s) {
          ws.send(safeJson({ type: "error", message: "Server negăsit" }));
          ws.close();
          return;
        }
        serverId = Number(msg.server_id);
        clearTimeout(timer);
        wsClients.set(ws, serverId);
        ws.send(safeJson({ type: "auth", message: "ok" }));
        const netRows = await queryAll("SELECT * FROM network_metrics WHERE server_id = ? ORDER BY ts DESC LIMIT 120", [serverId]);
        const connRows = await queryAll("SELECT * FROM connection_metrics WHERE server_id = ? ORDER BY ts DESC LIMIT 120", [serverId]);
        const events = await queryAll("SELECT * FROM event_logs WHERE server_id = ? ORDER BY ts DESC LIMIT 30", [serverId]);
        ws.send(safeJson({
          type: "history",
          net_history: netRows.reverse().map((r) => ({ ts: new Date(r.ts).toTimeString().slice(0, 8), rx: r.rx_mbps, tx: r.tx_mbps })),
          conn_history: connRows.reverse().map((r) => ({ ts: new Date(r.ts).toTimeString().slice(0, 8), count: r.count })),
          events: events.map((e) => ({ ts: new Date(e.ts).toTimeString().slice(0, 8), level: e.level, message: e.message, ip: e.ip, jail: e.jail })),
          ban_history: await loadBans(serverId, 100),
          intelligence: await loadIntel(serverId)
        }));
      }
    } catch {
      // ignore malformed message
    }
  });
  ws.on("close", () => wsClients.delete(ws));
  ws.on("error", () => wsClients.delete(ws));
});

async function cleanupOldMetrics() {
  try {
    const cutoff = new Date(Date.now() - config.metricRetentionHours * 3600 * 1000).toISOString();
    await exec("DELETE FROM network_metrics WHERE ts < ?", [cutoff]);
    await exec("DELETE FROM connection_metrics WHERE ts < ?", [cutoff]);
  } catch {
    // ignore
  }
}

async function startup() {
  await initDb();
  await ensureDefaultAdmin();
  await ensureBuiltinTemplates();
  try {
    await cacheTelegramBotUsername();
    const token = await getTelegramBotToken();
    const web = await getTelegramWebAppUrl();
    if (token && web) {
      try {
        await fetch(`https://api.telegram.org/bot${token}/setChatMenuButton`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            menu_button: { type: "web_app", text: "Panou NeoHost", web_app: { url: web } }
          })
        });
      } catch {
        // ignore
      }
    }
    await startTelegramBot();
  } catch (err) {
    console.warn("[NeoHost] Telegram bot dezactivat:", err.message || err);
  }
  setInterval(cleanupOldMetrics, 3600 * 1000).unref();
  if (config.securityApiToken === "schimba-acest-token-secret") {
    console.log("[NeoHost] ATENȚIE: token implicit activ! Setați SECURITY_API_TOKEN.");
  }
  console.log(`[NeoHost] Security Hub v3 pe ${config.host}:${config.port}`);
  server.listen(config.port, config.host);
}

startup().catch((err) => {
  console.error("[NeoHost] Startup error:", err);
  process.exit(1);
});
