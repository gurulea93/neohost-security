import { queryAll, queryOne, exec } from "../db/index.js";
import { computeThreatLevel } from "../lib/intelligence.js";
import { getTelegramBotToken, getTelegramWebAppUrl, setSetting } from "../lib/security.js";

let stopFlag = false;
let running = false;

async function tgApi(token, method, data = undefined) {
  const res = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: data ? "POST" : "GET",
    headers: data ? { "Content-Type": "application/json" } : undefined,
    body: data ? JSON.stringify(data) : undefined
  });
  if (!res.ok) throw new Error(`Telegram API ${res.status}`);
  return res.json();
}

async function send(token, chatId, text, replyMarkup = null) {
  try {
    await tgApi(token, "sendMessage", {
      chat_id: chatId,
      text,
      parse_mode: "HTML",
      disable_web_page_preview: true,
      ...(replyMarkup ? { reply_markup: replyMarkup } : {})
    });
    return true;
  } catch {
    return false;
  }
}

export async function sendTelegramText(chatId, text) {
  const token = await getTelegramBotToken();
  if (!token) return false;
  return send(token, chatId, text);
}

function mainKeyboard(webAppUrl) {
  const rows = [
    [{ text: "Servere", callback_data: "menu:servers" }, { text: "Status", callback_data: "menu:status" }],
    [{ text: "Jailuri F2B", callback_data: "menu:jails" }, { text: "CSF", callback_data: "menu:csf" }, { text: "nftables", callback_data: "menu:nft" }],
    [{ text: "Conexiuni", callback_data: "menu:connections" }, { text: "Ajutor", callback_data: "menu:help" }]
  ];
  if (webAppUrl) rows.unshift([{ text: "Panou Web App", web_app: { url: webAppUrl } }]);
  rows.push([{ text: "Meniu principal", callback_data: "menu:home" }]);
  return { inline_keyboard: rows };
}

async function queue(serverId, action, payload) {
  await exec("INSERT INTO agent_commands (server_id, action, payload, status, created_at) VALUES (?, ?, ?, 'pending', ?)", [
    serverId, action, JSON.stringify(payload || {}), new Date().toISOString()
  ]);
}

async function linkedUser(telegramId) {
  return queryOne("SELECT * FROM telegram_users WHERE telegram_id = ? AND is_active = 1", [telegramId]);
}

async function handleLink(dbToken, chatId, tgUser, code, webAppUrl) {
  if (!code) {
    await send(dbToken, chatId, "Trimiteți: <code>/link COD</code>", mainKeyboard(webAppUrl));
    return;
  }
  const row = await queryOne("SELECT * FROM telegram_link_codes WHERE code = ? AND used = 0", [code.toUpperCase()]);
  if (!row || new Date(row.expires_at).getTime() < Date.now()) {
    await send(dbToken, chatId, "Cod invalid sau expirat.");
    return;
  }
  const ex = await queryOne("SELECT * FROM telegram_users WHERE telegram_id = ?", [tgUser.id]);
  if (ex) {
    await exec("UPDATE telegram_users SET username = ?, first_name = ?, is_active = 1, linked_at = ? WHERE telegram_id = ?", [
      tgUser.username || "", tgUser.first_name || "", new Date().toISOString(), tgUser.id
    ]);
  } else {
    await exec("INSERT INTO telegram_users (telegram_id, username, first_name, linked_at, is_active) VALUES (?, ?, ?, ?, 1)", [
      tgUser.id, tgUser.username || "", tgUser.first_name || "", new Date().toISOString()
    ]);
  }
  await exec("UPDATE telegram_link_codes SET used = 1 WHERE code = ?", [code.toUpperCase()]);
  await send(dbToken, chatId, "Cont conectat! Folosiți butoanele de mai jos:", mainKeyboard(webAppUrl));
}

async function processCommand(token, msg, webAppUrl) {
  const text = String(msg.text || "");
  const chatId = msg.chat.id;
  const from = msg.from || {};
  const [cmdRaw, ...args] = text.trim().split(/\s+/);
  const cmd = cmdRaw.toLowerCase().split("@")[0];

  if (["/start", "/help", "/menu"].includes(cmd)) {
    const linked = await linkedUser(from.id);
    if (linked) await send(token, chatId, "<b>NeoHost Security</b>\nPanou unificat Fail2Ban + CSF + nftables:", mainKeyboard(webAppUrl));
    else await send(token, chatId, "Bun venit! Conectați contul: <code>/link COD</code> (cod din Profil → Telegram)");
    return;
  }
  if (cmd === "/link") {
    await handleLink(token, chatId, from, args[0] || "", webAppUrl);
    return;
  }
  const linked = await linkedUser(from.id);
  if (!linked) {
    await send(token, chatId, "Cont neconectat. /link COD");
    return;
  }
  if (cmd === "/servers") {
    const servers = await queryAll("SELECT * FROM servers WHERE is_active = 1 ORDER BY name", []);
    const lines = ["<b>Servere</b>", ...servers.map((s) => `#${s.id} <b>${s.name}</b>`)];
    await send(token, chatId, lines.join("\n"), mainKeyboard(webAppUrl));
    return;
  }
  if ((cmd === "/ban" || cmd === "/unban") && args[0]) {
    const ip = args[0];
    const jail = args.find((a) => !/^\d+$/.test(a)) || "sshd";
    const sid = Number(args.find((a) => /^\d+$/.test(a)) || 0);
    const server = sid ? await queryOne("SELECT * FROM servers WHERE id = ? AND is_active = 1", [sid]) : await queryOne("SELECT * FROM servers WHERE is_active = 1 ORDER BY name LIMIT 1", []);
    if (server) {
      await queue(server.id, cmd === "/ban" ? "ban" : "unban", { ip, jail });
      await send(token, chatId, `${cmd === "/ban" ? "Ban" : "Unban"} trimis: ${ip}`, mainKeyboard(webAppUrl));
    }
    return;
  }
  await send(token, chatId, "Folosiți butoanele sau /menu", mainKeyboard(webAppUrl));
}

async function processCallback(token, cb, webAppUrl) {
  const data = cb.data || "";
  const chatId = cb.message?.chat?.id;
  if (!chatId) return;
  if (data === "menu:home") {
    await send(token, chatId, "<b>NeoHost Security</b>\nAlegeți o acțiune:", mainKeyboard(webAppUrl));
    return;
  }
  if (data === "menu:servers") {
    const servers = await queryAll("SELECT * FROM servers WHERE is_active = 1 ORDER BY name", []);
    await send(token, chatId, ["<b>Servere</b>", ...servers.map((s) => `#${s.id} <b>${s.name}</b>`)].join("\n"), mainKeyboard(webAppUrl));
  }
}

async function pollLoop(token, webAppUrl) {
  let offset = 0;
  while (!stopFlag) {
    try {
      const data = await tgApi(token, "getUpdates", { offset, timeout: 20 });
      for (const upd of data.result || []) {
        offset = upd.update_id + 1;
        if (upd.callback_query) await processCallback(token, upd.callback_query, webAppUrl);
        const msg = upd.message || upd.edited_message;
        if (msg?.text) await processCommand(token, msg, webAppUrl);
      }
    } catch {
      await new Promise((r) => setTimeout(r, 5000));
    }
  }
}

export async function reloadTelegramBot(token, webAppUrl = "") {
  stopFlag = true;
  running = false;
  await new Promise((r) => setTimeout(r, 50));
  if (!token) {
    console.log("[Telegram] Bot oprit (fără token)");
    return;
  }
  try {
    const me = await tgApi(token, "getMe");
    console.log(`[Telegram] Bot pornit: @${me?.result?.username || "?"}`);
  } catch (e) {
    console.log(`[Telegram] Eroare token: ${e.message}`);
    return;
  }
  stopFlag = false;
  running = true;
  pollLoop(token, webAppUrl);
}

export async function startTelegramBot() {
  const token = await getTelegramBotToken();
  const web = await getTelegramWebAppUrl();
  if (token && !running) await reloadTelegramBot(token, web);
}

export async function cacheTelegramBotUsername() {
  const token = await getTelegramBotToken();
  if (!token) return;
  try {
    const me = await tgApi(token, "getMe");
    const username = me?.result?.username || "";
    if (username) await setSetting("telegram_bot_username", username);
  } catch {
    // ignore
  }
}
