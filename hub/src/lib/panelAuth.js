import { randomBytes } from "node:crypto";
import bcrypt from "bcryptjs";
import { authenticator } from "otplib";
import { config } from "../config.js";
import { exec, queryAll, queryOne, getDb, nowIso } from "../db/index.js";

export const CHALLENGE_MINUTES = 10;

function isoAfterHours(h) {
  return new Date(Date.now() + h * 3600 * 1000).toISOString();
}

function isoAfterMinutes(m) {
  return new Date(Date.now() + m * 60 * 1000).toISOString();
}

export function hashPassword(password) {
  return bcrypt.hashSync(String(password), 10);
}

export function verifyPassword(user, password) {
  return bcrypt.compareSync(String(password), user.password_hash || "");
}

export async function ensureDefaultAdmin() {
  const first = await queryOne("SELECT id FROM panel_users LIMIT 1");
  if (first) return;
  await exec(
    "INSERT INTO panel_users (username, password_hash, two_fa_method, is_active, created_at, updated_at) VALUES (?, ?, 'none', 1, ?, ?)",
    [config.panelAdminUsername, hashPassword(config.panelAdminPassword), new Date().toISOString(), new Date().toISOString()]
  );
}

export async function cleanupExpiredAuth() {
  const db = getDb();
  if (db.dialect === "mysql") {
    await exec("DELETE FROM panel_sessions WHERE expires_at < NOW()", []);
    await exec("DELETE FROM two_fa_challenges WHERE expires_at < NOW()", []);
    return;
  }
  const now = nowIso();
  await exec("DELETE FROM panel_sessions WHERE expires_at < ?", [now]);
  await exec("DELETE FROM two_fa_challenges WHERE expires_at < ?", [now]);
}

export async function createPanelSession(userId, ip = "", userAgent = "") {
  await cleanupExpiredAuth();
  const token = randomBytes(32).toString("base64url");
  const db = getDb();
  if (db.dialect === "mysql") {
    await exec(
      "INSERT INTO panel_sessions (token, user_id, expires_at, created_at, ip_address, user_agent) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL ? HOUR), NOW(), ?, ?)",
      [token, userId, config.panelSessionHours, String(ip || "").slice(0, 45), String(userAgent || "").slice(0, 512)]
    );
    const row = await queryOne("SELECT expires_at FROM panel_sessions WHERE token = ?", [token]);
    return { token, expires: row?.expires_at };
  }
  const expires = isoAfterHours(config.panelSessionHours);
  await exec(
    "INSERT INTO panel_sessions (token, user_id, expires_at, created_at, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)",
    [token, userId, expires, nowIso(), String(ip || "").slice(0, 45), String(userAgent || "").slice(0, 512)]
  );
  return { token, expires };
}

export async function getPanelSession(token) {
  if (!token) return null;
  const db = getDb();
  const row = db.dialect === "mysql"
    ? await queryOne(
      "SELECT u.* FROM panel_sessions s JOIN panel_users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at >= NOW() AND u.is_active = 1",
      [token]
    )
    : await queryOne(
      "SELECT u.* FROM panel_sessions s JOIN panel_users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at >= ? AND u.is_active = 1",
      [token, new Date().toISOString()]
    );
  return row || null;
}

export async function revokePanelSession(token) {
  if (!token) return;
  await exec("DELETE FROM panel_sessions WHERE token = ?", [token]);
}

export async function listUserSessions(userId) {
  await cleanupExpiredAuth();
  const db = getDb();
  if (db.dialect === "mysql") {
    return queryAll("SELECT * FROM panel_sessions WHERE user_id = ? AND expires_at >= NOW() ORDER BY created_at DESC", [userId]);
  }
  return queryAll("SELECT * FROM panel_sessions WHERE user_id = ? AND expires_at >= ? ORDER BY created_at DESC", [userId, new Date().toISOString()]);
}

export async function revokeSessionToken(userId, token) {
  const r = await exec("DELETE FROM panel_sessions WHERE user_id = ? AND token = ?", [userId, token]);
  return r.changes > 0;
}

export async function revokeOtherSessions(userId, keepToken) {
  const r = keepToken
    ? await exec("DELETE FROM panel_sessions WHERE user_id = ? AND token <> ?", [userId, keepToken])
    : await exec("DELETE FROM panel_sessions WHERE user_id = ?", [userId]);
  return r.changes;
}

export async function getPrimaryPanelUser() {
  return queryOne("SELECT * FROM panel_users WHERE is_active = 1 ORDER BY id LIMIT 1", []);
}

export async function create2faChallenge(user, method, purpose = "login", code = "") {
  await cleanupExpiredAuth();
  const token = randomBytes(24).toString("base64url");
  const finalCode = method === "telegram" && !code ? String(Math.floor(100000 + Math.random() * 900000)) : String(code || "");
  const db = getDb();
  if (db.dialect === "mysql") {
    await exec(
      "INSERT INTO two_fa_challenges (token, user_id, code, method, purpose, expires_at, created_at) VALUES (?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? MINUTE), NOW())",
      [token, user.id, finalCode, method, purpose, CHALLENGE_MINUTES]
    );
    const row = await queryOne("SELECT expires_at FROM two_fa_challenges WHERE token = ?", [token]);
    return { token, code: finalCode, expires: row?.expires_at };
  }
  const expires = isoAfterMinutes(CHALLENGE_MINUTES);
  await exec(
    "INSERT INTO two_fa_challenges (token, user_id, code, method, purpose, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [token, user.id, finalCode, method, purpose, expires, nowIso()]
  );
  return { token, code: finalCode, expires };
}

export async function find2faChallenge(challengeToken, userId, purpose = null) {
  const db = getDb();
  const params = [challengeToken, userId];
  let sql = "SELECT * FROM two_fa_challenges WHERE token = ? AND user_id = ?";
  if (purpose) {
    sql += " AND purpose = ?";
    params.push(purpose);
  }
  if (db.dialect === "mysql") {
    sql += " AND expires_at >= NOW()";
  } else {
    sql += " AND expires_at >= ?";
    params.push(new Date().toISOString());
  }
  return queryOne(sql, params);
}

export async function verify2faChallenge(challengeToken, user, code, method = null, purpose = null) {
  const row = await find2faChallenge(challengeToken, user.id, purpose);
  if (!row) return false;
  const useMethod = method || row.method;
  if (row.method !== useMethod) return false;
  const entered = String(code || "").trim().replaceAll(" ", "");
  let ok = false;
  if (useMethod === "telegram") ok = row.code === entered;
  if (useMethod === "totp" && user.totp_secret) ok = authenticator.check(entered, user.totp_secret);
  if (ok) await exec("DELETE FROM two_fa_challenges WHERE token = ?", [challengeToken]);
  return ok;
}

export function generateTotpSetup(user) {
  const secret = authenticator.generateSecret();
  const uri = authenticator.keyuri(user.username, config.panelTotpIssuer, secret);
  return { secret, uri };
}

export function verifyTotpCode(user, code) {
  if (!user?.totp_secret) return false;
  return authenticator.check(String(code || "").trim().replaceAll(" ", ""), user.totp_secret);
}

export function loginRequires2fa(user) {
  return ["totp", "telegram"].includes((user.two_fa_method || "none").toLowerCase());
}

export function sessionResponse(user, token, expires) {
  return { access_token: token, expires_at: expires, user: { id: user.id, username: user.username }, auth_type: "panel" };
}
