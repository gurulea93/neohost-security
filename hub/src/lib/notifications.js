import { queryAll } from "../db/index.js";
import { getSetting, setSetting } from "./security.js";
import { sendTelegramText } from "../services/telegram.js";

const sent = new Map();
const threatCache = new Map();

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function rateOk(key, minSec) {
  const now = nowSec();
  const last = sent.get(key) || 0;
  if (now - last < minSec) return false;
  sent.set(key, now);
  return true;
}

export async function getNotificationSettings() {
  const intervalRaw = await getSetting("notify_min_interval_sec", "60");
  const interval = Math.max(15, Math.min(3600, Number(intervalRaw) || 60));
  return {
    notify_bans_enabled: ["1", "true", "True", "yes"].includes(await getSetting("notify_bans_enabled", "1")),
    notify_threat_enabled: ["1", "true", "True", "yes"].includes(await getSetting("notify_threat_enabled", "1")),
    notify_offline_enabled: ["1", "true", "True", "yes"].includes(await getSetting("notify_offline_enabled", "1")),
    notify_min_interval_sec: interval
  };
}

export async function updateNotificationSettings(data) {
  if ("notify_bans_enabled" in data) await setSetting("notify_bans_enabled", data.notify_bans_enabled ? "1" : "0");
  if ("notify_threat_enabled" in data) await setSetting("notify_threat_enabled", data.notify_threat_enabled ? "1" : "0");
  if ("notify_offline_enabled" in data) await setSetting("notify_offline_enabled", data.notify_offline_enabled ? "1" : "0");
  if ("notify_min_interval_sec" in data) {
    const sec = Math.max(15, Math.min(3600, Number(data.notify_min_interval_sec) || 60));
    await setSetting("notify_min_interval_sec", String(sec));
  }
  return getNotificationSettings();
}

async function broadcast(text, rateKey, minSec) {
  if (!rateOk(rateKey, minSec)) return 0;
  const users = await queryAll("SELECT * FROM telegram_users WHERE is_active = 1", []);
  let n = 0;
  for (const u of users) {
    if (await sendTelegramText(u.telegram_id, text)) n += 1;
  }
  return n;
}

export async function notifyNewBans(server, bans) {
  if (!bans?.length) return;
  const s = await getNotificationSettings();
  if (!s.notify_bans_enabled) return;
  const lines = bans.slice(0, 8).map((b) => {
    const cc = b.country_code ? ` (${b.country_code})` : "";
    return `• <code>${b.ip || "?"}</code> — ${b.jail || "?"}${cc}`;
  });
  const extra = bans.length > 8 ? `\n… și încă ${bans.length - 8} bannuri` : "";
  await broadcast(`<b>🛡 NeoHost — Bannuri noi</b>\nServer: <b>${server.name}</b>\n\n${lines.join("\n")}${extra}`, `ban:${server.id}`, s.notify_min_interval_sec);
}

export async function notifyThreatChange(server, threat = {}) {
  const s = await getNotificationSettings();
  if (!s.notify_threat_enabled) return;
  const level = (threat.level || "low").toLowerCase();
  const prev = threatCache.get(server.id);
  threatCache.set(server.id, level);
  if (prev === level) return;
  const labels = { low: "Scăzut", medium: "Mediu", high: "Ridicat", critical: "Critic" };
  await broadcast(
    `<b>⚠️ NeoHost — Nivel amenințare</b>\nServer: <b>${server.name}</b>\nNivel: <b>${labels[level] || level}</b> (scor ${threat.score || 0})`,
    `threat:${server.id}:${level}`,
    s.notify_min_interval_sec
  );
}
