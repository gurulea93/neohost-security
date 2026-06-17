import { Router } from "express";
import { requireAgent, requireAuth, getBearerToken } from "../middleware/auth.js";
import { exec, queryAll, queryOne, isDbExpired } from "../db/index.js";
import { config } from "../config.js";
import { newAgentKey } from "../db/schema.js";
import {
  computeBanTimeline,
  computeCountryStats,
  computeJailStats,
  computeThreatLevel,
  computeTopAttackers
} from "../lib/intelligence.js";
import { ensureBuiltinTemplates, newUserSlug, templateToDict } from "../lib/securityTemplates.js";
import { runSecurityAudit } from "../lib/securityAudit.js";
import { lookupIpGeo, resolveServerLocation } from "../lib/geo.js";
import {
  cleanupExpiredAuth,
  create2faChallenge,
  createPanelSession,
  generateTotpSetup,
  getPrimaryPanelUser,
  hashPassword,
  listUserSessions,
  loginRequires2fa,
  revokeOtherSessions,
  revokePanelSession,
  revokeSessionToken,
  sessionResponse,
  verify2faChallenge,
  verifyPassword,
  verifyTotpCode
} from "../lib/panelAuth.js";
import {
  checkIpWhitelist,
  clientIpFromRequest,
  createTelegramWebSession,
  generateLinkCode,
  getSetting,
  getTelegramBotToken,
  getTelegramWebAppUrl,
  isWhitelistEnabled,
  maskToken,
  setSetting,
  validateTelegramInitData
} from "../lib/security.js";
import { getBranding, listBrandingHistory, updateBranding } from "../lib/branding.js";
import { getNotificationSettings, notifyNewBans, notifyThreatChange, updateNotificationSettings } from "../lib/notifications.js";
import { reloadTelegramBot, sendTelegramText } from "../services/telegram.js";

const ipGeoCache = new Map();

function serverToDict(s, includeKey = false) {
  const online = s.last_seen ? (Date.now() - new Date(s.last_seen).getTime()) < 90000 : false;
  const d = {
    id: s.id, name: s.name, hostname: s.hostname || "", description: s.description || "",
    is_active: !!s.is_active, last_seen: s.last_seen || null, online, created_at: s.created_at || null,
    mod_fail2ban: !!s.mod_fail2ban, mod_csf: !!s.mod_csf, mod_nftables: !!s.mod_nftables,
    cap_fail2ban: !!s.cap_fail2ban, cap_csf: !!s.cap_csf, cap_nftables: !!s.cap_nftables,
    latitude: s.latitude, longitude: s.longitude, location_label: s.location_label || ""
  };
  if (includeKey) d.agent_key = s.agent_key;
  return d;
}

function eventToDict(e) {
  return {
    ts: new Date(e.ts).toTimeString().slice(0, 8),
    level: e.level,
    message: e.message,
    ip: e.ip,
    jail: e.jail
  };
}

function banToDict(b) {
  return {
    ts: b.ts,
    ip: b.ip,
    jail: b.jail,
    country: b.country || "",
    country_code: b.country_code || "",
    city: b.city || "",
    isp: b.isp || "",
    lat: b.lat || 0,
    lon: b.lon || 0
  };
}

async function getGeo(ip) {
  if (ipGeoCache.has(ip)) return ipGeoCache.get(ip);
  const geo = await lookupIpGeo(ip);
  const out = geo
    ? { country: geo.country, country_code: geo.country_code, region: geo.region, city: geo.city, isp: geo.isp, org: "", asn: "", rdns: "", lat: geo.lat || 0, lon: geo.lon || 0 }
    : { country: "Unknown", country_code: "", isp: "", org: "", asn: "", rdns: "", lat: 0, lon: 0, region: "", city: "" };
  ipGeoCache.set(ip, out);
  return out;
}

async function applyServerLocation(server, { hostname = "", ip = "", latitude, longitude, location_label } = {}) {
  const loc = await resolveServerLocation({
    hostname: hostname || server.hostname,
    ip,
    latitude: latitude ?? server.latitude,
    longitude: longitude ?? server.longitude,
    location_label: location_label ?? server.location_label
  });
  const host = String(hostname || "").trim();
  const fields = [loc.latitude, loc.longitude, loc.location_label];
  if (host) {
    await exec("UPDATE servers SET latitude = ?, longitude = ?, location_label = ?, hostname = ? WHERE id = ?", [...fields, host, server.id]);
  } else {
    await exec("UPDATE servers SET latitude = ?, longitude = ?, location_label = ? WHERE id = ?", [...fields, server.id]);
  }
  return loc;
}

async function getAbuseScore(ip) {
  if (!config.abuseIpdbKey) return { score: null, reports: null, url: `https://www.abuseipdb.com/check/${ip}` };
  try {
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`;
    const res = await fetch(url, { headers: { Key: config.abuseIpdbKey, Accept: "application/json" }, signal: AbortSignal.timeout(5000) });
    const data = await res.json();
    return { score: data?.data?.abuseConfidenceScore || 0, reports: data?.data?.totalReports || 0, url: `https://www.abuseipdb.com/check/${ip}` };
  } catch {
    return { score: null, reports: null, url: `https://www.abuseipdb.com/check/${ip}` };
  }
}

async function loadBans(serverId, jail = null, limit = 5000) {
  const rows = jail
    ? await queryAll("SELECT * FROM ban_records WHERE server_id = ? AND jail = ? ORDER BY ts DESC LIMIT ?", [serverId, jail, limit])
    : await queryAll("SELECT * FROM ban_records WHERE server_id = ? ORDER BY ts DESC LIMIT ?", [serverId, limit]);
  return rows.map(banToDict);
}

async function loadNetHistory(serverId, limit = 120) {
  const rows = await queryAll("SELECT * FROM network_metrics WHERE server_id = ? ORDER BY ts DESC LIMIT ?", [serverId, limit]);
  return rows.reverse().map((r) => ({ ts: new Date(r.ts).toTimeString().slice(0, 8), rx: Number(r.rx_mbps || 0), tx: Number(r.tx_mbps || 0) }));
}

async function loadConnHistory(serverId, limit = 120) {
  const rows = await queryAll("SELECT * FROM connection_metrics WHERE server_id = ? ORDER BY ts DESC LIMIT ?", [serverId, limit]);
  return rows.reverse().map((r) => ({ ts: new Date(r.ts).toTimeString().slice(0, 8), count: Number(r.count || 0) }));
}

async function loadIntel(serverId, jail = null) {
  const bans = await loadBans(serverId, jail);
  const banTimesRows = await queryAll("SELECT ts FROM ban_records WHERE server_id = ? ORDER BY ts DESC LIMIT 5000", [serverId]);
  const banTimes = banTimesRows.map((r) => r.ts);
  return {
    threat: computeThreatLevel(banTimes),
    top10: computeTopAttackers(bans, 10),
    countries: computeCountryStats(bans),
    jail_stats: computeJailStats(bans),
    timeline: computeBanTimeline(bans),
    total_bans: bans.length
  };
}

async function queueCommand(serverId, action, payload = {}) {
  await exec("INSERT INTO agent_commands (server_id, action, payload, status, created_at) VALUES (?, ?, ?, 'pending', ?)", [
    serverId, action, JSON.stringify(payload), new Date().toISOString()
  ]);
}

async function upsertSnapshot(table, serverId, updatedAt, data) {
  const existing = await queryOne(`SELECT server_id FROM ${table} WHERE server_id = ?`, [serverId]);
  if (existing) {
    await exec(`UPDATE ${table} SET updated_at = ?, data = ? WHERE server_id = ?`, [updatedAt, data, serverId]);
  } else {
    await exec(`INSERT INTO ${table} (server_id, updated_at, data) VALUES (?, ?, ?)`, [serverId, updatedAt, data]);
  }
}

async function loadFail2ban(serverId) {
  const snap = await queryOne("SELECT * FROM jail_snapshots WHERE server_id = ?", [serverId]);
  if (!snap?.data) return { installed: false, running: false, jails: [] };
  const raw = JSON.parse(snap.data || "[]");
  return Array.isArray(raw) ? { installed: true, running: !!raw.length, jails: raw } : raw;
}

async function loadCsf(serverId) {
  const snap = await queryOne("SELECT * FROM csf_snapshots WHERE server_id = ?", [serverId]);
  if (!snap?.data) return {};
  try { return JSON.parse(snap.data || "{}"); } catch { return {}; }
}

async function loadNft(serverId) {
  const snap = await queryOne("SELECT * FROM nftables_snapshots WHERE server_id = ?", [serverId]);
  if (!snap?.data) return {};
  try { return JSON.parse(snap.data || "{}"); } catch { return {}; }
}

async function sidRequired(req, res) {
  const sid = Number(req.query.server_id || req.body?.server_id || 0);
  if (!sid) {
    res.status(400).json({ error: "server_id obligatoriu" });
    return null;
  }
  const server = await queryOne("SELECT * FROM servers WHERE id = ? AND is_active = 1", [sid]);
  if (!server) {
    res.status(404).json({ error: "Server negăsit" });
    return null;
  }
  return server;
}

export default function createRoutes({ broadcastWs }) {
  const r = Router();
  r.use((req, _res, next) => { req.body = req.body || {}; next(); });

  r.get("/api/servers", requireAuth, async (_req, res) => {
    const servers = await queryAll("SELECT * FROM servers ORDER BY name", []);
    res.json({ servers: servers.map((s) => serverToDict(s)) });
  });
  r.post("/api/servers", requireAuth, async (req, res) => {
    const name = String(req.body.name || "").trim();
    if (!name) return res.status(400).json({ error: "Numele serverului este obligatoriu" });
    const hostname = String(req.body.hostname || "").trim();
    const loc = await resolveServerLocation({
      hostname,
      latitude: req.body.latitude ?? null,
      longitude: req.body.longitude ?? null,
      location_label: String(req.body.location_label || "").trim()
    });
    const key = newAgentKey();
    await exec(
      "INSERT INTO servers (name, hostname, description, agent_key, is_active, created_at, mod_fail2ban, mod_csf, mod_nftables, cap_fail2ban, cap_csf, cap_nftables, latitude, longitude, location_label) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, 0, 0, 0, ?, ?, ?)",
      [
        name, hostname, String(req.body.description || "").trim(), key, new Date().toISOString(),
        req.body.mod_fail2ban !== false ? 1 : 0, req.body.mod_csf !== false ? 1 : 0, req.body.mod_nftables !== false ? 1 : 0,
        loc.latitude, loc.longitude, loc.location_label
      ]
    );
    const server = await queryOne("SELECT * FROM servers WHERE agent_key = ?", [key]);
    res.status(201).json({ server: serverToDict(server, true) });
  });
  r.get("/api/servers/:sid", requireAuth, async (req, res) => {
    const s = await queryOne("SELECT * FROM servers WHERE id = ?", [Number(req.params.sid)]);
    if (!s) return res.status(404).json({ error: "Server negăsit" });
    res.json({ server: serverToDict(s, true) });
  });
  r.put("/api/servers/:sid", requireAuth, async (req, res) => {
    const s = await queryOne("SELECT * FROM servers WHERE id = ?", [Number(req.params.sid)]);
    if (!s) return res.status(404).json({ error: "Server negăsit" });
    const patch = {
      name: req.body.name ?? s.name, hostname: req.body.hostname ?? s.hostname, description: req.body.description ?? s.description,
      is_active: "is_active" in req.body ? (req.body.is_active ? 1 : 0) : s.is_active,
      mod_fail2ban: "mod_fail2ban" in req.body ? (req.body.mod_fail2ban ? 1 : 0) : s.mod_fail2ban,
      mod_csf: "mod_csf" in req.body ? (req.body.mod_csf ? 1 : 0) : s.mod_csf,
      mod_nftables: "mod_nftables" in req.body ? (req.body.mod_nftables ? 1 : 0) : s.mod_nftables,
      latitude: "latitude" in req.body ? req.body.latitude : s.latitude,
      longitude: "longitude" in req.body ? req.body.longitude : s.longitude,
      location_label: "location_label" in req.body ? String(req.body.location_label || "").trim().slice(0, 128) : s.location_label
    };
    const hostnameChanged = "hostname" in req.body && String(req.body.hostname || "").trim() !== String(s.hostname || "").trim();
    const coordsMissing = patch.latitude == null || patch.longitude == null;
    if (hostnameChanged || coordsMissing) {
      const loc = await resolveServerLocation({
        hostname: patch.hostname,
        latitude: patch.latitude,
        longitude: patch.longitude,
        location_label: patch.location_label
      });
      patch.latitude = loc.latitude;
      patch.longitude = loc.longitude;
      if (!patch.location_label && loc.location_label) patch.location_label = loc.location_label;
    }
    await exec("UPDATE servers SET name = ?, hostname = ?, description = ?, is_active = ?, mod_fail2ban = ?, mod_csf = ?, mod_nftables = ?, latitude = ?, longitude = ?, location_label = ? WHERE id = ?", [
      patch.name, patch.hostname, patch.description, patch.is_active, patch.mod_fail2ban, patch.mod_csf, patch.mod_nftables, patch.latitude, patch.longitude, patch.location_label, s.id
    ]);
    res.json({ server: serverToDict(await queryOne("SELECT * FROM servers WHERE id = ?", [s.id])) });
  });
  r.delete("/api/servers/:sid", requireAuth, async (req, res) => {
    await exec("DELETE FROM servers WHERE id = ?", [Number(req.params.sid)]);
    res.json({ success: true });
  });
  r.post("/api/servers/:sid/regenerate-key", requireAuth, async (req, res) => {
    const key = newAgentKey();
    await exec("UPDATE servers SET agent_key = ? WHERE id = ?", [key, Number(req.params.sid)]);
    const s = await queryOne("SELECT * FROM servers WHERE id = ?", [Number(req.params.sid)]);
    if (!s) return res.status(404).json({ error: "Server negăsit" });
    res.json({ server: serverToDict(s, true) });
  });

  r.post("/api/agent/report", requireAgent, async (req, res) => {
    const server = req.server;
    const now = new Date().toISOString();
    const agentHost = String(req.body.hostname || "").trim();
    const agentIp = clientIpFromRequest(req);
    const needsCoords = server.latitude == null || server.longitude == null;
    if (needsCoords || agentHost) {
      await applyServerLocation(server, {
        hostname: agentHost || server.hostname,
        ip: needsCoords ? agentIp : "",
        latitude: server.latitude,
        longitude: server.longitude,
        location_label: server.location_label
      });
    }
    await exec("UPDATE servers SET last_seen = ?, cap_fail2ban = ?, cap_csf = ?, cap_nftables = ? WHERE id = ?", [
      now, req.body.capabilities?.fail2ban ? 1 : 0, req.body.capabilities?.csf ? 1 : 0, req.body.capabilities?.nftables ? 1 : 0, server.id
    ]);
    if ("jails" in req.body && server.mod_fail2ban) {
      const payload = req.body.fail2ban || { jails: req.body.jails };
      await upsertSnapshot("jail_snapshots", server.id, now, JSON.stringify(payload));
    }
    if ("connections" in req.body) {
      await upsertSnapshot("connection_snapshots", server.id, now, JSON.stringify(req.body.connections || []));
      await exec("INSERT INTO connection_metrics (server_id, ts, `count`) VALUES (?, ?, ?)", [server.id, now, (req.body.connections || []).length]);
    }
    if ("csf" in req.body && server.mod_csf) await upsertSnapshot("csf_snapshots", server.id, now, JSON.stringify(req.body.csf || {}));
    if ("nftables" in req.body && server.mod_nftables) await upsertSnapshot("nftables_snapshots", server.id, now, JSON.stringify(req.body.nftables || {}));
    if (req.body.net) await exec("INSERT INTO network_metrics (server_id, ts, rx_mbps, tx_mbps) VALUES (?, ?, ?, ?)", [server.id, now, req.body.net.rx_mbps || 0, req.body.net.tx_mbps || 0]);

    for (const ev of req.body.events || []) {
      const ts = ev?.ts ? new Date(ev.ts).toISOString() : now;
      await exec("INSERT INTO event_logs (server_id, ts, level, message, ip, jail) VALUES (?, ?, ?, ?, ?, ?)", [server.id, ts, ev.level || "INFO", ev.message || "", ev.ip || null, ev.jail || null]);
    }
    const newBans = [];
    for (const ban of req.body.bans || []) {
      const ip = ban.ip || "";
      const jail = ban.jail || "unknown";
      const recent = await queryOne("SELECT id FROM ban_records WHERE server_id = ? AND ip = ? AND jail = ? AND ts >= ? LIMIT 1", [server.id, ip, jail, new Date(Date.now() - 10 * 60000).toISOString()]);
      if (recent) continue;
      const geo = ban.country ? ban : await getGeo(ip);
      const ts = ban.ts ? new Date(ban.ts).toISOString() : now;
      await exec(
        "INSERT INTO ban_records (server_id, ts, ip, jail, country, country_code, city, isp, lat, lon) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [server.id, ts, ip, jail, geo.country || "", geo.country_code || "", geo.city || "", geo.isp || "", geo.lat || 0, geo.lon || 0]
      );
      newBans.push({ ip, jail, country: geo.country || "", country_code: geo.country_code || "" });
    }
    if (newBans.length) await notifyNewBans(server, newBans);
    const intel = await loadIntel(server.id);
    await notifyThreatChange(server, intel.threat);
    const f2b = server.mod_fail2ban ? await loadFail2ban(server.id) : null;
    const csf = server.mod_csf ? await loadCsf(server.id) : null;
    const nft = server.mod_nftables ? await loadNft(server.id) : null;
    broadcastWs(server.id, { type: "tick", data: { ts: new Date().toTimeString().slice(0, 8), net: req.body.net || {}, connections: req.body.connections || [], net_history: await loadNetHistory(server.id), conn_history: await loadConnHistory(server.id), threat: intel.threat, countries: intel.countries, top10: intel.top10, fail2ban: f2b, csf, nftables: nft } });
    res.json({ success: true, server_id: server.id });
  });

  r.get("/api/agent/commands", requireAgent, async (req, res) => {
    const rows = await queryAll("SELECT * FROM agent_commands WHERE server_id = ? AND status = 'pending' ORDER BY created_at ASC LIMIT 20", [req.server.id]);
    res.json({ commands: rows.map((c) => ({ id: c.id, action: c.action, payload: JSON.parse(c.payload || "{}") })) });
  });
  r.post("/api/agent/commands/:cid/done", requireAgent, async (req, res) => {
    await exec("UPDATE agent_commands SET status = ?, completed_at = ? WHERE id = ? AND server_id = ?", [req.body.success === false ? "failed" : "done", new Date().toISOString(), Number(req.params.cid), req.server.id]);
    res.json({ success: true });
  });

  const queueRoutes = [
    ["/api/fail2ban/jail", "post", "f2b_add_jail", "config", "Fail2Ban dezactivat"],
    ["/api/fail2ban/jail/:jail", "delete", "f2b_remove_jail", "jail_name", "Fail2Ban dezactivat"],
    ["/api/reload", "post", "reload", null, null]
  ];
  for (const [path, method, action, key, failErr] of queueRoutes) {
    r[method](path, requireAuth, async (req, res) => {
      const server = await sidRequired(req, res); if (!server) return;
      if (path.startsWith("/api/fail2ban") && !server.mod_fail2ban) return res.status(400).json({ error: failErr });
      let payload = {};
      if (key === "config") payload = { config: req.body.config || {} };
      if (key === "jail_name") payload = { jail_name: req.params.jail };
      await queueCommand(server.id, action, payload);
      res.json({ success: true, queued: true, ...(path.includes("jail/:jail") ? { note: "Se șterg doar jailuri create din panou (neohost-*.conf)" } : {}) });
    });
  }

  r.get("/api/security/templates", requireAuth, async (req, res) => {
    await ensureBuiltinTemplates();
    const kind = String(req.query.kind || "");
    const rows = kind
      ? await queryAll("SELECT * FROM security_templates WHERE kind = ? ORDER BY is_builtin DESC, critical DESC, name ASC", [kind])
      : await queryAll("SELECT * FROM security_templates ORDER BY is_builtin DESC, critical DESC, name ASC", []);
    res.json({ templates: rows.map(templateToDict) });
  });
  r.post("/api/security/templates", requireAuth, async (req, res) => {
    const kind = String(req.body.kind || "").trim();
    const name = String(req.body.name || "").trim();
    if (!["fail2ban_jail", "csf_preset", "nftables_preset"].includes(kind) || !name) return res.status(400).json({ error: "kind și name obligatorii" });
    const payload = req.body.payload || {};
    if (kind === "fail2ban_jail" && !payload.jail_name) return res.status(400).json({ error: "payload.jail_name obligatoriu pentru Fail2Ban" });
    await exec("INSERT INTO security_templates (kind, slug, name, description, instructions, critical, payload, is_builtin, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)", [
      kind, newUserSlug(), name, String(req.body.description || "").trim(), String(req.body.instructions || "").trim(), req.body.critical ? 1 : 0, JSON.stringify(payload), new Date().toISOString()
    ]);
    const row = await queryOne("SELECT * FROM security_templates ORDER BY id DESC LIMIT 1", []);
    res.status(201).json({ template: templateToDict(row) });
  });
  r.put("/api/security/templates/:tid", requireAuth, async (req, res) => {
    const tpl = await queryOne("SELECT * FROM security_templates WHERE id = ?", [Number(req.params.tid)]);
    if (!tpl) return res.status(404).json({ error: "Șablon negăsit" });
    if (tpl.is_builtin) return res.status(403).json({ error: "Șabloanele predefinite nu pot fi modificate. Folosiți «Duplică» pentru o copie editabilă." });
    const payload = "payload" in req.body ? req.body.payload : JSON.parse(tpl.payload || "{}");
    if (tpl.kind === "fail2ban_jail" && !payload.jail_name) return res.status(400).json({ error: "payload.jail_name obligatoriu pentru Fail2Ban" });
    await exec("UPDATE security_templates SET name = ?, description = ?, instructions = ?, critical = ?, payload = ? WHERE id = ?", [
      String(req.body.name || tpl.name).trim(), "description" in req.body ? String(req.body.description || "").trim() : tpl.description, "instructions" in req.body ? String(req.body.instructions || "").trim() : tpl.instructions, "critical" in req.body ? (req.body.critical ? 1 : 0) : tpl.critical, JSON.stringify(payload), tpl.id
    ]);
    res.json({ template: templateToDict(await queryOne("SELECT * FROM security_templates WHERE id = ?", [tpl.id])) });
  });
  r.delete("/api/security/templates/:tid", requireAuth, async (req, res) => {
    const tpl = await queryOne("SELECT * FROM security_templates WHERE id = ?", [Number(req.params.tid)]);
    if (!tpl) return res.status(404).json({ error: "Șablon negăsit" });
    if (tpl.is_builtin) return res.status(403).json({ error: "Șabloanele predefinite nu pot fi șterse" });
    await exec("DELETE FROM security_templates WHERE id = ?", [tpl.id]);
    res.json({ success: true });
  });
  r.post("/api/security/templates/:tid/apply", requireAuth, async (req, res) => {
    const server = await sidRequired(req, res); if (!server) return;
    const tpl = await queryOne("SELECT * FROM security_templates WHERE id = ?", [Number(req.params.tid)]);
    if (!tpl) return res.status(404).json({ error: "Șablon negăsit" });
    const payload = JSON.parse(tpl.payload || "{}");
    if (tpl.kind === "fail2ban_jail") { if (!server.mod_fail2ban) return res.status(400).json({ error: "Fail2Ban dezactivat" }); await queueCommand(server.id, "f2b_add_jail", { config: payload }); }
    else if (tpl.kind === "csf_preset") { if (!server.mod_csf) return res.status(400).json({ error: "CSF dezactivat" }); await queueCommand(server.id, "csf_apply_preset", { preset: payload }); }
    else if (tpl.kind === "nftables_preset") { if (!server.mod_nftables) return res.status(400).json({ error: "nftables dezactivat" }); await queueCommand(server.id, "nft_apply_preset", { preset: payload }); }
    else return res.status(400).json({ error: "Tip șablon necunoscut" });
    res.json({ success: true, queued: true, template: templateToDict(tpl) });
  });
  r.post("/api/security/templates/:tid/apply-bulk", requireAuth, async (req, res) => {
    const tpl = await queryOne("SELECT * FROM security_templates WHERE id = ?", [Number(req.params.tid)]);
    if (!tpl) return res.status(404).json({ error: "Șablon negăsit" });
    const serverIds = req.body.server_ids || [];
    if (!serverIds.length) return res.status(400).json({ error: "server_ids obligatoriu" });
    const payload = JSON.parse(tpl.payload || "{}");
    let queued = 0;
    for (const sid of serverIds) {
      const s = await queryOne("SELECT * FROM servers WHERE id = ? AND is_active = 1", [Number(sid)]);
      if (!s) continue;
      if (tpl.kind === "fail2ban_jail" && s.mod_fail2ban) { await queueCommand(s.id, "f2b_add_jail", { config: payload }); queued += 1; }
      if (tpl.kind === "csf_preset" && s.mod_csf) { await queueCommand(s.id, "csf_apply_preset", { preset: payload }); queued += 1; }
      if (tpl.kind === "nftables_preset" && s.mod_nftables) { await queueCommand(s.id, "nft_apply_preset", { preset: payload }); queued += 1; }
    }
    res.json({ success: true, queued });
  });
  r.get("/api/security/audit", requireAuth, async (req, res) => {
    const s = await sidRequired(req, res); if (!s) return;
    const f2b = s.mod_fail2ban ? await loadFail2ban(s.id) : {};
    const csf = s.mod_csf ? await loadCsf(s.id) : {};
    const nft = s.mod_nftables ? await loadNft(s.id) : {};
    const intel = await loadIntel(s.id);
    res.json(runSecurityAudit(s, f2b, csf, intel, nft));
  });

  r.get("/api/jails", requireAuth, async (req, res) => {
    const s = await sidRequired(req, res); if (!s) return;
    if (!s.mod_fail2ban) return res.json({ jails: [], fail2ban: { installed: false } });
    const f2b = await loadFail2ban(s.id);
    res.json({ jails: f2b.jails || [], fail2ban: f2b });
  });
  r.get("/api/fail2ban", requireAuth, async (req, res) => {
    const s = await sidRequired(req, res); if (!s) return;
    if (!s.mod_fail2ban) return res.json({ fail2ban: { installed: false, mod_enabled: false } });
    const f2b = await loadFail2ban(s.id);
    const snap = await queryOne("SELECT updated_at FROM jail_snapshots WHERE server_id = ?", [s.id]);
    f2b.updated_at = snap?.updated_at || null;
    f2b.mod_enabled = true;
    f2b.cap_detected = !!s.cap_fail2ban;
    res.json({ fail2ban: f2b });
  });
  r.post("/api/fail2ban/jail", requireAuth, async (req, res) => {
    const s = await sidRequired(req, res); if (!s) return;
    if (!s.mod_fail2ban) return res.status(400).json({ error: "Fail2Ban dezactivat" });
    let config = req.body.config || {};
    if (req.body.template_id) {
      const tpl = await queryOne("SELECT * FROM security_templates WHERE id = ?", [Number(req.body.template_id)]);
      if (!tpl || tpl.kind !== "fail2ban_jail") return res.status(400).json({ error: "Șablon invalid" });
      config = JSON.parse(tpl.payload || "{}");
    }
    if (!config.jail_name) return res.status(400).json({ error: "jail_name obligatoriu" });
    await queueCommand(s.id, "f2b_add_jail", { config });
    res.json({ success: true, queued: true });
  });
  r.delete("/api/fail2ban/jail/:jail", requireAuth, async (req, res) => {
    const s = await sidRequired(req, res); if (!s) return;
    if (!s.mod_fail2ban) return res.status(400).json({ error: "Fail2Ban dezactivat" });
    await queueCommand(s.id, "f2b_remove_jail", { jail_name: req.params.jail });
    res.json({ success: true, queued: true, note: "Se șterg doar jailuri create din panou (neohost-*.conf)" });
  });
  r.post("/api/fail2ban/jail/:jail/toggle", requireAuth, async (req, res) => {
    const s = await sidRequired(req, res); if (!s) return;
    if (!s.mod_fail2ban) return res.status(400).json({ error: "Fail2Ban dezactivat" });
    await queueCommand(s.id, req.body.enabled ? "start" : "stop", { jail: req.params.jail });
    res.json({ success: true, queued: true });
  });
  r.post("/api/jails/ban", requireAuth, async (req, res) => {
    const s = await sidRequired(req, res); if (!s) return;
    if (!s.mod_fail2ban) return res.status(400).json({ error: "Fail2Ban dezactivat pentru acest server" });
    const ip = String(req.body.ip || "").trim();
    const jails = req.body.jails || (req.body.jail ? [req.body.jail] : []);
    if (!ip) return res.status(400).json({ error: "IP lipsă" });
    if (!jails.length) return res.status(400).json({ error: "Selectați cel puțin un jail" });
    for (const jail of jails) await queueCommand(s.id, "ban", { ip, jail: String(jail).trim() });
    res.json({ success: true, queued: true, ip, jails });
  });
  r.post("/api/jails/unban", requireAuth, async (req, res) => {
    const s = await sidRequired(req, res); if (!s) return;
    if (!s.mod_fail2ban) return res.status(400).json({ error: "Fail2Ban dezactivat pentru acest server" });
    const ip = String(req.body.ip || "").trim();
    const jails = req.body.jails || (req.body.jail ? [req.body.jail] : []);
    if (!ip) return res.status(400).json({ error: "IP lipsă" });
    if (!jails.length) return res.status(400).json({ error: "Selectați cel puțin un jail" });
    for (const jail of jails) await queueCommand(s.id, "unban", { ip, jail: String(jail).trim() });
    res.json({ success: true, queued: true, ip, jails });
  });
  r.get("/api/fail2ban/active-bans", requireAuth, async (req, res) => {
    const s = await sidRequired(req, res); if (!s) return;
    if (!s.mod_fail2ban) return res.json({ bans: [] });
    const f2b = await loadFail2ban(s.id);
    const history = await loadBans(s.id, null, 5000);
    const latest = new Map(history.map((b) => [`${b.ip}|${b.jail}`, b.ts]));
    const rows = [];
    for (const j of f2b.jails || []) {
      for (const ip of j.banned_ips || []) rows.push({ ip, jail: j.name, ts: latest.get(`${ip}|${j.name}`), active: true });
    }
    res.json({ bans: rows });
  });
  r.post("/api/jails/:jail/ban", requireAuth, async (req, res) => {
    const s = await sidRequired(req, res); if (!s) return;
    if (!s.mod_fail2ban) return res.status(400).json({ error: "Fail2Ban dezactivat pentru acest server" });
    const ip = String(req.body.ip || "").trim();
    if (!ip) return res.status(400).json({ error: "IP lipsă" });
    await queueCommand(s.id, "ban", { ip, jail: req.params.jail });
    res.json({ success: true, queued: true, ip, jail: req.params.jail });
  });
  r.post("/api/jails/:jail/unban", requireAuth, async (req, res) => {
    const s = await sidRequired(req, res); if (!s) return;
    const ip = String(req.body.ip || "").trim();
    if (!ip) return res.status(400).json({ error: "IP lipsă" });
    await queueCommand(s.id, "unban", { ip, jail: req.params.jail });
    res.json({ success: true, queued: true });
  });
  r.post("/api/jails/:jail/start", requireAuth, async (req, res) => { const s = await sidRequired(req, res); if (!s) return; await queueCommand(s.id, "start", { jail: req.params.jail }); res.json({ success: true, queued: true }); });
  r.post("/api/jails/:jail/stop", requireAuth, async (req, res) => { const s = await sidRequired(req, res); if (!s) return; await queueCommand(s.id, "stop", { jail: req.params.jail }); res.json({ success: true, queued: true }); });
  r.post("/api/reload", requireAuth, async (req, res) => { const s = await sidRequired(req, res); if (!s) return; await queueCommand(s.id, "reload", {}); res.json({ success: true, queued: true }); });

  r.get("/api/intelligence", requireAuth, async (req, res) => { const s = await sidRequired(req, res); if (!s) return; res.json(await loadIntel(s.id, req.query.jail || null)); });
  r.get("/api/ip/:ip", requireAuth, async (req, res) => {
    const s = await sidRequired(req, res); if (!s) return;
    const geo = await getGeo(req.params.ip);
    const abuse = await getAbuseScore(req.params.ip);
    const history = (await loadBans(s.id)).filter((b) => b.ip === req.params.ip);
    res.json({ ip: req.params.ip, geo, abuse, ban_count: history.length, ban_history: history.slice(0, 20), abuseipdb_url: `https://www.abuseipdb.com/check/${req.params.ip}` });
  });
  r.get("/api/ban_history", requireAuth, async (req, res) => {
    const s = await sidRequired(req, res); if (!s) return;
    const limit = Math.min(Number(req.query.limit || 200), 5000);
    const bans = await loadBans(s.id, req.query.jail || null, limit);
    res.json({ bans, total: bans.length });
  });
  r.get("/api/export/csv", requireAuth, async (req, res) => {
    const s = await sidRequired(req, res); if (!s) return;
    const data = await loadBans(s.id, req.query.jail || null, 5000);
    const header = "ts,ip,jail,country,country_code,city,isp,lat,lon\n";
    const body = data.map((b) => [b.ts, b.ip, b.jail, b.country, b.country_code, b.city, b.isp, b.lat, b.lon].map((v) => `"${String(v ?? "").replaceAll("\"", "\"\"")}"`).join(",")).join("\n");
    res.setHeader("Content-Disposition", "attachment; filename=ban_history.csv");
    res.type("text/csv").send(`${header}${body}`);
  });
  r.get("/api/export/json", requireAuth, async (req, res) => {
    const s = await sidRequired(req, res); if (!s) return;
    const data = await loadBans(s.id, req.query.jail || null, 5000);
    res.setHeader("Content-Disposition", "attachment; filename=ban_history.json");
    res.type("application/json").send(JSON.stringify({ exported: new Date().toISOString(), bans: data }, null, 2));
  });
  r.get("/api/network", requireAuth, async (req, res) => {
    const s = await sidRequired(req, res); if (!s) return;
    const history = await loadNetHistory(s.id);
    const current = history.at(-1) || { rx: 0, tx: 0 };
    res.json({ current: { rx_mbps: current.rx || 0, tx_mbps: current.tx || 0 }, history });
  });
  r.get("/api/connections", requireAuth, async (req, res) => {
    const s = await sidRequired(req, res); if (!s) return;
    const snap = await queryOne("SELECT * FROM connection_snapshots WHERE server_id = ?", [s.id]);
    res.json({ connections: snap?.data ? JSON.parse(snap.data || "[]") : [], history: await loadConnHistory(s.id) });
  });
  r.get("/api/log", requireAuth, async (req, res) => {
    const s = await sidRequired(req, res); if (!s) return;
    const events = await queryAll("SELECT * FROM event_logs WHERE server_id = ? ORDER BY ts DESC LIMIT 200", [s.id]);
    res.json({ events: events.map(eventToDict) });
  });

  r.post("/api/auth/login", async (req, res) => {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");
    if (!username || !password) return res.status(400).json({ error: "Utilizator și parolă obligatorii" });
    const user = await queryOne("SELECT * FROM panel_users WHERE username = ? AND is_active = 1", [username]);
    if (!user || !verifyPassword(user, password)) return res.status(401).json({ error: "Utilizator sau parolă incorectă" });
    const clientIp = clientIpFromRequest(req);
    if (!(await checkIpWhitelist(clientIp))) return res.status(403).json({ error: "IP neautorizat pentru panou", code: "ip_not_whitelisted", client_ip: clientIp });
    if (!loginRequires2fa(user)) {
      const ip = clientIpFromRequest(req);
      const ua = String(req.headers["user-agent"] || "").slice(0, 512);
      const session = await createPanelSession(user.id, ip, ua);
      return res.json(sessionResponse(user, session.token, session.expires));
    }
    const c = await create2faChallenge(user, user.two_fa_method, "login");
    if (user.two_fa_method === "telegram") {
      if (!user.telegram_id) return res.status(500).json({ error: "2FA Telegram neconfigurat" });
      const sent = await sendTelegramText(user.telegram_id, `<b>NeoHost Security</b>\nCod autentificare: <code>${c.code}</code>\nValabil 5 minute.`);
      if (!sent) return res.status(503).json({ error: "Nu am putut trimite codul pe Telegram" });
      return res.json({ requires_2fa: true, challenge_token: c.token, method: "telegram", expires_at: c.expires, message: "Cod trimis pe Telegram" });
    }
    return res.json({ requires_2fa: true, challenge_token: c.token, method: "totp", expires_at: c.expires, message: "Introduceți codul din Google Authenticator" });
  });
  r.post("/api/auth/verify-2fa", async (req, res) => {
    const token = String(req.body.challenge_token || "").trim();
    const code = String(req.body.code || "").trim();
    if (!token || !code) return res.status(400).json({ error: "Cod 2FA obligatoriu" });
    const row = await queryOne("SELECT * FROM two_fa_challenges WHERE token = ? AND purpose = 'login'", [token]);
    if (!row || isDbExpired(row.expires_at)) return res.status(401).json({ error: "Sesiune 2FA expirată" });
    const user = await queryOne("SELECT * FROM panel_users WHERE id = ? AND is_active = 1", [row.user_id]);
    if (!user) return res.status(401).json({ error: "Utilizator negăsit" });
    const method = String(req.body.method || "").trim() || row.method;
    if (!(await verify2faChallenge(token, user, code, method))) return res.status(401).json({ error: "Cod 2FA invalid" });
    const clientIp = clientIpFromRequest(req);
    if (!(await checkIpWhitelist(clientIp))) return res.status(403).json({ error: "IP neautorizat pentru panou", code: "ip_not_whitelisted", client_ip: clientIp });
    const session = await createPanelSession(user.id, clientIp, String(req.headers["user-agent"] || "").slice(0, 512));
    res.json(sessionResponse(user, session.token, session.expires));
  });
  r.post("/api/auth/logout", requireAuth, async (req, res) => { const t = getBearerToken(req); if (t) await revokePanelSession(t); res.json({ success: true }); });

  r.get("/api/profile", requireAuth, async (req, res) => {
    const telegramUsers = await queryAll("SELECT * FROM telegram_users WHERE is_active = 1", []);
    const whitelist = await queryAll("SELECT * FROM ip_whitelist ORDER BY created_at DESC", []);
    const tgToken = await getTelegramBotToken();
    res.json({
      client_ip: clientIpFromRequest(req),
      account: req.accountUser ? { id: req.accountUser.id, username: req.accountUser.username, two_fa_method: req.accountUser.two_fa_method || "none", totp_configured: !!req.accountUser.totp_secret, telegram_2fa_id: req.accountUser.telegram_id } : null,
      settings: {
        ip_whitelist_enabled: await isWhitelistEnabled(),
        telegram_configured: !!tgToken,
        telegram_bot_username: await getSetting("telegram_bot_username", ""),
        telegram_token_hint: maskToken(tgToken),
        telegram_webapp_url: await getTelegramWebAppUrl(),
        telegram_token_from_env: !!config.telegramBotToken
      },
      telegram_users: telegramUsers.map((u) => ({ id: u.id, telegram_id: u.telegram_id, username: u.username || "", first_name: u.first_name || "", linked_at: u.linked_at || null, is_active: !!u.is_active })),
      whitelist: whitelist.map((w) => ({ id: w.id, ip: w.ip, label: w.label || "", created_at: w.created_at || null }))
    });
  });
  r.put("/api/profile/settings", requireAuth, async (req, res) => {
    if ("ip_whitelist_enabled" in req.body) {
      const enabled = !!req.body.ip_whitelist_enabled;
      if (enabled) {
        const entries = await queryAll("SELECT id FROM ip_whitelist LIMIT 1", []);
        if (!entries.length) {
          return res.status(400).json({ error: "Adăugați cel puțin un IP în listă înainte de activare" });
        }
      }
      await setSetting("ip_whitelist_enabled", enabled ? "1" : "0");
    }
    res.json({ success: true });
  });
  r.get("/api/branding", async (_req, res) => { res.json(await getBranding()); });
  r.put("/api/profile/branding", requireAuth, async (req, res) => { try { res.json({ success: true, branding: await updateBranding(req.body || {}, req.accountUser) }); } catch (e) { res.status(400).json({ error: e.message }); } });
  r.get("/api/profile/branding/history", requireAuth, async (req, res) => { res.json({ history: await listBrandingHistory(Number(req.query.limit || 30)) }); });
  r.get("/api/profile/notifications", requireAuth, async (_req, res) => { res.json({ settings: await getNotificationSettings() }); });
  r.put("/api/profile/notifications", requireAuth, async (req, res) => { res.json({ success: true, settings: await updateNotificationSettings(req.body || {}) }); });
  r.get("/api/profile/sessions", requireAuth, async (req, res) => {
    if (!req.accountUser) return res.status(403).json({ error: "Cont panou indisponibil" });
    const rows = await listUserSessions(req.accountUser.id);
    const sessions = rows.map((s) => ({ token: s.token.length > 12 ? `${s.token.slice(0, 8)}…${s.token.slice(-4)}` : s.token, token_full: null, user_id: s.user_id, expires_at: s.expires_at, created_at: s.created_at, ip_address: s.ip_address || "", user_agent: s.user_agent || "", current: !!(req.panelToken && s.token === req.panelToken), token_id: s.token.slice(0, 16) }));
    res.json({ sessions });
  });
  r.delete("/api/profile/sessions/:token_id", requireAuth, async (req, res) => {
    if (!req.accountUser) return res.status(403).json({ error: "Cont panou indisponibil" });
    const rows = await listUserSessions(req.accountUser.id);
    const target = rows.find((s) => s.token.startsWith(req.params.token_id) || s.token === req.params.token_id);
    if (!target) return res.status(404).json({ error: "Sesiune negăsită" });
    await revokeSessionToken(req.accountUser.id, target.token);
    res.json({ success: true });
  });
  r.post("/api/profile/sessions/revoke-others", requireAuth, async (req, res) => {
    if (!req.accountUser) return res.status(403).json({ error: "Cont panou indisponibil" });
    res.json({ success: true, revoked: await revokeOtherSessions(req.accountUser.id, req.panelToken || null) });
  });
  r.put("/api/profile/account", requireAuth, async (req, res) => {
    const user = req.accountUser;
    if (!user) return res.status(403).json({ error: "Cont panou indisponibil" });
    const currentPassword = req.body.current_password || "";
    if (!currentPassword) return res.status(400).json({ error: "Parola curentă obligatorie" });
    if (!verifyPassword(user, currentPassword)) return res.status(401).json({ error: "Parola curentă incorectă" });
    let username = user.username;
    if (req.body.new_username && req.body.new_username !== user.username) {
      const taken = await queryOne("SELECT id FROM panel_users WHERE username = ?", [req.body.new_username]);
      if (taken && taken.id !== user.id) return res.status(400).json({ error: "Utilizatorul există deja" });
      username = req.body.new_username.trim();
    }
    let passwordHash = user.password_hash;
    if (req.body.new_password) {
      if (req.body.new_password !== req.body.confirm_password) return res.status(400).json({ error: "Parolele noi nu coincid" });
      if (String(req.body.new_password).length < 6) return res.status(400).json({ error: "Parola nouă: minim 6 caractere" });
      passwordHash = hashPassword(req.body.new_password);
    }
    await exec("UPDATE panel_users SET username = ?, password_hash = ?, updated_at = ? WHERE id = ?", [username, passwordHash, new Date().toISOString(), user.id]);
    res.json({ success: true, username });
  });
  r.post("/api/profile/2fa/totp/setup", requireAuth, async (req, res) => {
    if (!req.accountUser) return res.status(403).json({ error: "Cont panou indisponibil" });
    if (!verifyPassword(req.accountUser, req.body.current_password || "")) return res.status(401).json({ error: "Parola curentă incorectă" });
    const t = generateTotpSetup(req.accountUser);
    await exec("UPDATE panel_users SET totp_secret = ?, updated_at = ? WHERE id = ?", [t.secret, new Date().toISOString(), req.accountUser.id]);
    res.json({ secret: t.secret, uri: t.uri });
  });
  r.post("/api/profile/2fa/totp/enable", requireAuth, async (req, res) => {
    const code = String(req.body.code || "").trim();
    if (!code) return res.status(400).json({ error: "Cod obligatoriu" });
    const user = await queryOne("SELECT * FROM panel_users WHERE id = ?", [req.accountUser?.id || 0]);
    if (!user?.totp_secret) return res.status(400).json({ error: "Configurați mai întâi TOTP" });
    if (!verifyTotpCode(user, code)) return res.status(400).json({ error: "Cod TOTP invalid" });
    await exec("UPDATE panel_users SET two_fa_method = 'totp', updated_at = ? WHERE id = ?", [new Date().toISOString(), user.id]);
    res.json({ success: true, two_fa_method: "totp" });
  });
  r.post("/api/profile/2fa/telegram/send", requireAuth, async (req, res) => {
    const user = req.accountUser;
    if (!user) return res.status(403).json({ error: "Cont panou indisponibil" });
    if (!req.body.current_password || !req.body.telegram_user_id) return res.status(400).json({ error: "Parolă și cont Telegram obligatorii" });
    if (!verifyPassword(user, req.body.current_password)) return res.status(401).json({ error: "Parola curentă incorectă" });
    const tg = await queryOne("SELECT * FROM telegram_users WHERE id = ? AND is_active = 1", [Number(req.body.telegram_user_id)]);
    if (!tg) return res.status(404).json({ error: "Cont Telegram negăsit" });
    const c = await create2faChallenge(user, "telegram", "enable_telegram");
    const sent = await sendTelegramText(tg.telegram_id, `<b>NeoHost Security</b>\nCod activare 2FA: <code>${c.code}</code>`);
    if (!sent) return res.status(503).json({ error: "Nu am putut trimite codul pe Telegram" });
    res.json({ challenge_token: c.token, telegram_user_id: tg.id, expires_at: c.expires });
  });
  r.post("/api/profile/2fa/telegram/enable", requireAuth, async (req, res) => {
    const user = req.accountUser;
    if (!user) return res.status(403).json({ error: "Cont panou indisponibil" });
    if (!req.body.challenge_token || !req.body.code || !req.body.telegram_user_id) return res.status(400).json({ error: "Date incomplete" });
    if (!(await verify2faChallenge(req.body.challenge_token, user, req.body.code, "telegram"))) return res.status(400).json({ error: "Cod invalid sau expirat" });
    const tg = await queryOne("SELECT * FROM telegram_users WHERE id = ? AND is_active = 1", [Number(req.body.telegram_user_id)]);
    if (!tg) return res.status(404).json({ error: "Cont Telegram negăsit" });
    await exec("UPDATE panel_users SET telegram_id = ?, two_fa_method = 'telegram', updated_at = ? WHERE id = ?", [tg.telegram_id, new Date().toISOString(), user.id]);
    res.json({ success: true, two_fa_method: "telegram" });
  });
  r.post("/api/profile/2fa/disable", requireAuth, async (req, res) => {
    const user = await queryOne("SELECT * FROM panel_users WHERE id = ?", [req.accountUser?.id || 0]);
    if (!user) return res.status(403).json({ error: "Cont panou indisponibil" });
    if (!req.body.current_password) return res.status(400).json({ error: "Parola curentă obligatorie" });
    if (!verifyPassword(user, req.body.current_password)) return res.status(401).json({ error: "Parola curentă incorectă" });
    const method = user.two_fa_method || "none";
    if (method === "none") return res.status(400).json({ error: "2FA nu este activ" });
    if (method === "totp") {
      if (!req.body.code || !verifyTotpCode(user, req.body.code)) return res.status(400).json({ error: "Cod Google Authenticator obligatoriu" });
    } else if (method === "telegram") {
      if (!req.body.challenge_token) {
        if (!user.telegram_id) return res.status(400).json({ error: "Telegram 2FA neconfigurat" });
        const c = await create2faChallenge(user, "telegram", "disable");
        await sendTelegramText(user.telegram_id, `<b>NeoHost Security</b>\nCod dezactivare 2FA: <code>${c.code}</code>`);
        return res.json({ requires_code: true, challenge_token: c.token, expires_at: c.expires });
      }
      if (!req.body.code || !(await verify2faChallenge(req.body.challenge_token, user, req.body.code, "telegram"))) return res.status(400).json({ error: "Cod Telegram invalid" });
    }
    await exec("UPDATE panel_users SET two_fa_method = 'none', totp_secret = NULL, telegram_id = NULL, updated_at = ? WHERE id = ?", [new Date().toISOString(), user.id]);
    res.json({ success: true, two_fa_method: "none" });
  });
  r.put("/api/profile/telegram/config", requireAuth, async (req, res) => {
    if ("bot_token" in req.body) {
      const token = String(req.body.bot_token || "").trim();
      if (token) await setSetting("telegram_bot_token", token);
      else await exec("DELETE FROM hub_settings WHERE `key` = 'telegram_bot_token'", []);
    }
    if ("webapp_url" in req.body) {
      const url = String(req.body.webapp_url || "").trim().replace(/\/+$/, "");
      if (url) await setSetting("telegram_webapp_url", url);
      else await exec("DELETE FROM hub_settings WHERE `key` = 'telegram_webapp_url'", []);
    }
    const token = await getTelegramBotToken();
    const web = await getTelegramWebAppUrl();
    let username = "";
    if (token) {
      try {
        const me = await (await fetch(`https://api.telegram.org/bot${token}/getMe`, { signal: AbortSignal.timeout(10000) })).json();
        username = me?.result?.username || "";
        if (username) await setSetting("telegram_bot_username", username);
      } catch {
        // ignore
      }
    }
    await reloadTelegramBot(token, web);
    res.json({ success: true, telegram_configured: !!token, telegram_bot_username: username, telegram_token_hint: maskToken(token), telegram_webapp_url: web });
  });
  r.post("/api/profile/telegram/code", requireAuth, async (_req, res) => {
    const c = await generateLinkCode();
    res.json({ code: c.code, expires_at: c.expires, bot_username: await getSetting("telegram_bot_username", "") });
  });
  r.delete("/api/profile/telegram/:uid", requireAuth, async (req, res) => { await exec("UPDATE telegram_users SET is_active = 0 WHERE id = ?", [Number(req.params.uid)]); res.json({ success: true }); });
  r.get("/api/profile/whitelist", requireAuth, async (_req, res) => { const rows = await queryAll("SELECT * FROM ip_whitelist ORDER BY created_at DESC", []); res.json({ whitelist: rows.map((w) => ({ id: w.id, ip: w.ip, label: w.label || "", created_at: w.created_at || null })) }); });
  r.post("/api/profile/whitelist", requireAuth, async (req, res) => {
    const ip = String(req.body.ip || "").trim();
    if (!ip) return res.status(400).json({ error: "IP obligatoriu" });
    const ex = await queryOne("SELECT id FROM ip_whitelist WHERE ip = ?", [ip]);
    if (ex) return res.status(409).json({ error: "IP deja în listă" });
    await exec("INSERT INTO ip_whitelist (ip, label, created_at) VALUES (?, ?, ?)", [ip, String(req.body.label || "").trim(), new Date().toISOString()]);
    const row = await queryOne("SELECT * FROM ip_whitelist WHERE ip = ? ORDER BY id DESC LIMIT 1", [ip]);
    res.status(201).json({ entry: { id: row.id, ip: row.ip, label: row.label || "", created_at: row.created_at || null } });
  });
  r.delete("/api/profile/whitelist/:wid", requireAuth, async (req, res) => { await exec("DELETE FROM ip_whitelist WHERE id = ?", [Number(req.params.wid)]); res.json({ success: true }); });

  r.get("/api/csf", requireAuth, async (req, res) => { const s = await sidRequired(req, res); if (!s) return; const snap = await queryOne("SELECT * FROM csf_snapshots WHERE server_id = ?", [s.id]); const data = snap?.data ? JSON.parse(snap.data || "{}") : { installed: false }; data.updated_at = snap?.updated_at || null; data.mod_enabled = !!s.mod_csf; res.json({ csf: data }); });
  r.get("/api/nftables", requireAuth, async (req, res) => { const s = await sidRequired(req, res); if (!s) return; const snap = await queryOne("SELECT * FROM nftables_snapshots WHERE server_id = ?", [s.id]); const data = snap?.data ? JSON.parse(snap.data || "{}") : { installed: false }; data.updated_at = snap?.updated_at || null; data.mod_enabled = !!s.mod_nftables; res.json({ nftables: data }); });

  const commandMappings = [
    ["/api/csf/deny", "csf_deny", "CSF"], ["/api/csf/allow", "csf_allow", "CSF"], ["/api/csf/restart", "csf_restart", "CSF"],
    ["/api/csf/toggle", "csf_toggle", "CSF"], ["/api/csf/firewall", "csf_firewall", "CSF"], ["/api/csf/port", "csf_port", "CSF"], ["/api/csf/remove", "csf_remove", "CSF"],
    ["/api/nftables/deny", "nft_deny", "nftables"], ["/api/nftables/allow", "nft_allow", "nftables"], ["/api/nftables/remove", "nft_remove", "nftables"],
    ["/api/nftables/reload", "nft_reload", "nftables"], ["/api/nftables/firewall", "nft_firewall", "nftables"], ["/api/nftables/chain-policy", "nft_chain_policy", "nftables"],
    ["/api/nftables/set", "nft_set", "nftables"], ["/api/nftables/flush", "nft_flush", "nftables"], ["/api/nftables/rule", "nft_rule", "nftables"]
  ];
  for (const [path, action, mod] of commandMappings) {
    r.post(path, requireAuth, async (req, res) => {
      const s = await sidRequired(req, res); if (!s) return;
      if (mod === "CSF" && !s.mod_csf) return res.status(400).json({ error: "CSF dezactivat pentru acest server" });
      if (mod === "nftables" && !s.mod_nftables) return res.status(400).json({ error: "nftables dezactivat pentru acest server" });
      const ip = String(req.body.ip || "").trim();
      if (["csf_deny", "csf_allow", "nft_deny", "nft_allow"].includes(action) && !ip) return res.status(400).json({ error: "IP lipsă" });
      const payload = { ...req.body };
      if (path === "/api/csf/remove") payload.list = req.body.list || "deny";
      if (path === "/api/csf/firewall") await queueCommand(s.id, req.body.enabled ? "csf_enable" : "csf_disable", {});
      else if (path === "/api/nftables/firewall") await queueCommand(s.id, req.body.enabled ? "nft_enable" : "nft_disable", {});
      else if (path === "/api/nftables/rule" && req.body.delete) await queueCommand(s.id, "nft_delete_rule", { handle: req.body.handle, chain: req.body.chain || "input" });
      else if (path === "/api/nftables/rule") await queueCommand(s.id, "nft_add_rule", { chain: req.body.chain || "input", expr: req.body.expr || "" });
      else if (path === "/api/csf/remove") await queueCommand(s.id, req.body.list === "allow" ? "csf_remove_allow" : "csf_remove_deny", { ip });
      else if (path === "/api/csf/toggle") await queueCommand(s.id, "csf_toggle", { key: req.body.key || "", enabled: !!req.body.enabled });
      else if (path === "/api/csf/port") await queueCommand(s.id, "csf_port", { list: req.body.list || "TCP_IN", port: String(req.body.port || ""), enabled: !!req.body.enabled });
      else if (path === "/api/nftables/chain-policy") await queueCommand(s.id, "nft_chain_policy", { chain: req.body.chain || "input", policy: req.body.policy || "drop" });
      else if (path === "/api/nftables/set") await queueCommand(s.id, "nft_set", { set: req.body.set || "", ip, remove: !!req.body.remove });
      else if (path === "/api/nftables/flush") await queueCommand(s.id, "nft_flush", { set: req.body.set || "" });
      else await queueCommand(s.id, action, { ip });
      res.json({ success: true, queued: true });
    });
  }

  r.post("/api/telegram/webapp-auth", async (req, res) => {
    const botToken = await getTelegramBotToken();
    if (!botToken) return res.status(503).json({ error: "Bot Telegram neconfigurat" });
    const tgUser = validateTelegramInitData(req.body.init_data || "", botToken);
    if (!tgUser) return res.status(401).json({ error: "init_data invalid" });
    const linked = await queryOne("SELECT * FROM telegram_users WHERE telegram_id = ? AND is_active = 1", [tgUser.id]);
    if (!linked) return res.status(403).json({ error: "Cont Telegram neconectat. Folosiți /link în bot." });
    const web = await createTelegramWebSession(tgUser.id);
    const servers = await queryAll("SELECT * FROM servers WHERE is_active = 1 ORDER BY name", []);
    res.json({ access_token: web.token, expires_at: web.expires, user: { id: linked.id, telegram_id: linked.telegram_id, username: linked.username || "", first_name: linked.first_name || "", linked_at: linked.linked_at || null, is_active: !!linked.is_active }, servers: servers.map((s) => serverToDict(s)) });
  });
  r.get("/api/status", async (_req, res) => {
    const c = await queryOne("SELECT COUNT(*) AS n FROM servers", []);
    res.json({ status: "ok", ts: new Date().toISOString(), version: "3.0", mode: "hub", servers: Number(c?.n || c?.["COUNT(*)"] || 0) });
  });

  return r;
}
