import fs from "node:fs";
import path from "node:path";
import mysql from "mysql2/promise";
import pg from "pg";
import { config } from "../config.js";
import { getSchemaSql } from "./schema.js";

const { Pool } = pg;

let state = null;

function toMysqlDatetime(value) {
  if (value == null) return value;
  if (value instanceof Date) {
    return value.toISOString().slice(0, 19).replace("T", " ");
  }
  if (typeof value === "string" && /^\d{4}-\d{2}-\d{2}T/.test(value)) {
    return value.slice(0, 19).replace("T", " ");
  }
  return value;
}

function normalizeParams(params, dialect) {
  if (dialect !== "mysql") return params;
  return params.map(toMysqlDatetime);
}

function resolveDbUrl(input) {
  let url = input || "";
  if (!url) {
    url = `sqlite:///${path.join(config.hubRoot, "data", "neohost.db").replace(/\\/g, "/")}`;
  }
  if (url.startsWith("mariadb://")) {
    url = url.replace("mariadb://", "mysql://");
  }
  if (url.startsWith("mysql+pymysql://")) {
    url = url.replace("mysql+pymysql://", "mysql://");
  }
  return url;
}

function pgSql(sql, params) {
  let i = 0;
  return { sql: sql.replace(/\?/g, () => `$${++i}`), params };
}

async function runSchema(db) {
  for (const stmt of getSchemaSql(db.dialect)) {
    await db.run(stmt, []);
  }
}

export async function initDb() {
  const url = resolveDbUrl(config.databaseUrl);
  if (url.startsWith("sqlite://")) {
    const { DatabaseSync } = await import("node:sqlite");
    const filePath = url.replace("sqlite:///", "");
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const sqlite = new DatabaseSync(filePath);
    state = {
      dialect: "sqlite",
      client: sqlite,
      async run(sql, params = []) {
        const stmt = sqlite.prepare(sql);
        const head = sql.trim().split(/\s+/)[0].toUpperCase();
        if (head === "SELECT" || head === "PRAGMA" || head === "WITH") {
          return { rows: stmt.all(...params) };
        }
        stmt.run(...params);
        return { rows: [] };
      },
      async exec(sql, params = []) {
        const info = sqlite.prepare(sql).run(...params);
        return { insertId: Number(info.lastInsertRowid || 0), changes: info.changes || 0 };
      }
    };
  } else if (url.startsWith("mysql://") || url.startsWith("mysql2://")) {
    const pool = mysql.createPool(url);
    state = {
      dialect: "mysql",
      client: pool,
      async run(sql, params = []) {
        const [rows] = await pool.query(sql, normalizeParams(params, "mysql"));
        return { rows };
      },
      async exec(sql, params = []) {
        const [r] = await pool.execute(sql, normalizeParams(params, "mysql"));
        return { insertId: Number(r.insertId || 0), changes: Number(r.affectedRows || 0) };
      }
    };
  } else if (url.startsWith("postgres://") || url.startsWith("postgresql://")) {
    const pool = new Pool({ connectionString: url, connectionTimeoutMillis: 10000 });
    state = {
      dialect: "postgres",
      client: pool,
      async run(sql, params = []) {
        const q = pgSql(sql, params);
        const r = await pool.query(q.sql, q.params);
        return { rows: r.rows || [] };
      },
      async exec(sql, params = []) {
        const q = pgSql(sql, params);
        const r = await pool.query(q.sql, q.params);
        return { insertId: 0, changes: Number(r.rowCount || 0) };
      }
    };
  } else {
    throw new Error(`DATABASE_URL invalid: ${url}`);
  }
  await runSchema(state);
  return state;
}

export function getDb() {
  if (!state) throw new Error("DB not initialized");
  return state;
}

export async function queryAll(sql, params = []) {
  return (await getDb().run(sql, params)).rows;
}

export async function queryOne(sql, params = []) {
  const rows = await queryAll(sql, params);
  return rows[0] || null;
}

export async function exec(sql, params = []) {
  return getDb().exec(sql, params);
}

export function nowIso() {
  const d = new Date();
  if (state?.dialect === "mysql") {
    return d.toISOString().slice(0, 19).replace("T", " ");
  }
  return d.toISOString();
}
