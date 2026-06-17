import crypto from "node:crypto";
import { randomBytes } from "node:crypto";
import { exec, queryAll, queryOne } from "../db/index.js";
import { config } from "../config.js";

export async function getSetting(key, defaultValue = "") {
  const row = await queryOne("SELECT value FROM hub_settings WHERE key = ?", [key]);
  return row ? row.value : defaultValue;
}

export async function setSetting(key, value) {
  const row = await queryOne("SELECT key FROM hub_settings WHERE key = ?", [key]);
  if (row) await exec("UPDATE hub_settings SET value = ? WHERE key = ?", [String(value), key]);
  else await exec("INSERT INTO hub_settings (key, value) VALUES (?, ?)", [key, String(value)]);
}

export function maskToken(token) {
  if (!token) return "";
  if (token.length <= 8) return "••••";
  return `••••${token.slice(-6)}`;
}

export function clientIpFromRequest(req) {
  const xff = req.headers["x-forwarded-for"];
  if (xff) return String(xff).split(",")[0].trim();
  const xr = req.headers["x-real-ip"];
  if (xr) return String(xr).trim();
  return req.ip || req.socket?.remoteAddress || "";
}

function isLocalIp(ip) {
  return ["127.0.0.1", "::1", "localhost", "::ffff:127.0.0.1"].includes(ip);
}

function ipMatch(allowed, client) {
  if (!allowed || !client) return false;
  if (allowed.includes("/")) return client.startsWith(allowed.split("/")[0]);
  return allowed === client;
}

export async function isWhitelistEnabled() {
  return (await getSetting("ip_whitelist_enabled", "0")) === "1";
}

export async function checkIpWhitelist(clientIp) {
  if (isLocalIp(clientIp)) return true;
  if (!(await isWhitelistEnabled())) return true;
  const entries = await queryAll("SELECT ip FROM ip_whitelist", []);
  if (!entries.length) return true;
  return entries.some((e) => ipMatch(e.ip, clientIp));
}

export async function generateLinkCode(ttlMinutes = 10) {
  await exec("DELETE FROM telegram_link_codes WHERE expires_at < ?", [new Date().toISOString()]);
  let code = "";
  for (let i = 0; i < 10; i += 1) {
    code = randomBytes(3).toString("hex").toUpperCase().slice(0, 6);
    const row = await queryOne("SELECT code FROM telegram_link_codes WHERE code = ? AND used = 0", [code]);
    if (!row) break;
  }
  const expires = new Date(Date.now() + ttlMinutes * 60 * 1000).toISOString();
  await exec("INSERT INTO telegram_link_codes (code, created_at, expires_at, used) VALUES (?, ?, ?, 0)", [code, new Date().toISOString(), expires]);
  return { code, expires };
}

export function validateTelegramInitData(initData, botToken) {
  if (!initData || !botToken) return null;
  const params = new URLSearchParams(initData);
  const receivedHash = params.get("hash");
  if (!receivedHash) return null;
  params.delete("hash");
  const entries = [...params.entries()].sort(([a], [b]) => a.localeCompare(b));
  const dataCheck = entries.map(([k, v]) => `${k}=${v}`).join("\n");
  const secret = crypto.createHmac("sha256", "WebAppData").update(botToken).digest();
  const calc = crypto.createHmac("sha256", secret).update(dataCheck).digest("hex");
  if (calc !== receivedHash) return null;
  try {
    return JSON.parse(params.get("user") || "");
  } catch {
    return null;
  }
}

export async function createTelegramWebSession(telegramId, hours = 24) {
  await exec("DELETE FROM telegram_web_sessions WHERE expires_at < ?", [new Date().toISOString()]);
  const token = randomBytes(32).toString("base64url");
  const expires = new Date(Date.now() + hours * 3600 * 1000).toISOString();
  await exec("INSERT INTO telegram_web_sessions (token, telegram_id, expires_at, created_at) VALUES (?, ?, ?, ?)", [
    token, telegramId, expires, new Date().toISOString()
  ]);
  return { token, expires };
}

export async function getTelegramWebSession(token) {
  const row = await queryOne("SELECT * FROM telegram_web_sessions WHERE token = ? AND expires_at >= ?", [token, new Date().toISOString()]);
  if (!row) return null;
  return queryOne("SELECT * FROM telegram_users WHERE telegram_id = ? AND is_active = 1", [row.telegram_id]);
}

export async function getTelegramBotToken() {
  return (await getSetting("telegram_bot_token", "")) || config.telegramBotToken;
}

export async function getTelegramWebAppUrl() {
  const v = (await getSetting("telegram_webapp_url", "")) || config.telegramWebAppUrl;
  return String(v).replace(/\/+$/, "");
}
