import { randomBytes } from "node:crypto";

export function newAgentKey() {
  return randomBytes(32).toString("hex");
}

function sqliteTables() {
  return [
    `CREATE TABLE IF NOT EXISTS servers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      hostname TEXT DEFAULT '',
      description TEXT DEFAULT '',
      agent_key TEXT UNIQUE NOT NULL,
      is_active INTEGER DEFAULT 1,
      last_seen TEXT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      mod_fail2ban INTEGER DEFAULT 1,
      mod_csf INTEGER DEFAULT 1,
      mod_nftables INTEGER DEFAULT 1,
      cap_fail2ban INTEGER DEFAULT 0,
      cap_csf INTEGER DEFAULT 0,
      cap_nftables INTEGER DEFAULT 0,
      latitude REAL NULL,
      longitude REAL NULL,
      location_label TEXT DEFAULT ''
    )`,
    `CREATE TABLE IF NOT EXISTS ban_records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      server_id INTEGER NOT NULL,
      ts TEXT NOT NULL,
      ip TEXT NOT NULL,
      jail TEXT NOT NULL,
      country TEXT DEFAULT '',
      country_code TEXT DEFAULT '',
      city TEXT DEFAULT '',
      isp TEXT DEFAULT '',
      lat REAL DEFAULT 0,
      lon REAL DEFAULT 0
    )`,
    `CREATE TABLE IF NOT EXISTS event_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      server_id INTEGER NOT NULL,
      ts TEXT NOT NULL,
      level TEXT NOT NULL,
      message TEXT NOT NULL,
      ip TEXT NULL,
      jail TEXT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS network_metrics (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      server_id INTEGER NOT NULL,
      ts TEXT NOT NULL,
      rx_mbps REAL DEFAULT 0,
      tx_mbps REAL DEFAULT 0
    )`,
    `CREATE TABLE IF NOT EXISTS connection_metrics (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      server_id INTEGER NOT NULL,
      ts TEXT NOT NULL,
      count INTEGER DEFAULT 0
    )`,
    `CREATE TABLE IF NOT EXISTS jail_snapshots (
      server_id INTEGER PRIMARY KEY,
      updated_at TEXT,
      data TEXT DEFAULT '[]'
    )`,
    `CREATE TABLE IF NOT EXISTS connection_snapshots (
      server_id INTEGER PRIMARY KEY,
      updated_at TEXT,
      data TEXT DEFAULT '[]'
    )`,
    `CREATE TABLE IF NOT EXISTS agent_commands (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      server_id INTEGER NOT NULL,
      action TEXT NOT NULL,
      payload TEXT DEFAULT '{}',
      status TEXT DEFAULT 'pending',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      completed_at TEXT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS csf_snapshots (
      server_id INTEGER PRIMARY KEY,
      updated_at TEXT,
      data TEXT DEFAULT '{}'
    )`,
    `CREATE TABLE IF NOT EXISTS nftables_snapshots (
      server_id INTEGER PRIMARY KEY,
      updated_at TEXT,
      data TEXT DEFAULT '{}'
    )`,
    `CREATE TABLE IF NOT EXISTS hub_settings (
      key TEXT PRIMARY KEY,
      value TEXT DEFAULT ''
    )`,
    `CREATE TABLE IF NOT EXISTS telegram_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      telegram_id INTEGER UNIQUE NOT NULL,
      username TEXT DEFAULT '',
      first_name TEXT DEFAULT '',
      linked_at TEXT DEFAULT CURRENT_TIMESTAMP,
      is_active INTEGER DEFAULT 1
    )`,
    `CREATE TABLE IF NOT EXISTS telegram_link_codes (
      code TEXT PRIMARY KEY,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      expires_at TEXT NOT NULL,
      used INTEGER DEFAULT 0
    )`,
    `CREATE TABLE IF NOT EXISTS ip_whitelist (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT NOT NULL,
      label TEXT DEFAULT '',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS telegram_web_sessions (
      token TEXT PRIMARY KEY,
      telegram_id INTEGER NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS panel_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      totp_secret TEXT NULL,
      two_fa_method TEXT DEFAULT 'none',
      telegram_id INTEGER NULL,
      is_active INTEGER DEFAULT 1,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS panel_sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      ip_address TEXT DEFAULT '',
      user_agent TEXT DEFAULT ''
    )`,
    `CREATE TABLE IF NOT EXISTS two_fa_challenges (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      code TEXT DEFAULT '',
      method TEXT NOT NULL,
      purpose TEXT DEFAULT 'login',
      expires_at TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS branding_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NULL,
      username TEXT DEFAULT '',
      changes TEXT DEFAULT '{}',
      snapshot TEXT DEFAULT '{}',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS security_templates (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      kind TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      instructions TEXT DEFAULT '',
      critical INTEGER DEFAULT 0,
      payload TEXT DEFAULT '{}',
      is_builtin INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`,
    "CREATE INDEX IF NOT EXISTS ix_ban_server_ts ON ban_records (server_id, ts)",
    "CREATE INDEX IF NOT EXISTS ix_event_server_ts ON event_logs (server_id, ts)",
    "CREATE INDEX IF NOT EXISTS ix_net_server_ts ON network_metrics (server_id, ts)",
    "CREATE INDEX IF NOT EXISTS ix_conn_server_ts ON connection_metrics (server_id, ts)"
  ];
}

function mysqlTables() {
  return sqliteTables().map((sql) =>
    sql
      .replaceAll("INTEGER PRIMARY KEY AUTOINCREMENT", "INT AUTO_INCREMENT PRIMARY KEY")
      .replaceAll("INTEGER PRIMARY KEY", "INT PRIMARY KEY")
      .replaceAll("INTEGER ", "INT ")
      .replaceAll(" REAL ", " DOUBLE ")
      .replaceAll(" TEXT ", " VARCHAR(4096) ")
      .replaceAll(" DEFAULT CURRENT_TIMESTAMP", " DEFAULT CURRENT_TIMESTAMP")
  );
}

function pgTables() {
  return sqliteTables().map((sql) =>
    sql
      .replaceAll("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
      .replaceAll("INTEGER PRIMARY KEY", "INTEGER PRIMARY KEY")
      .replaceAll("INTEGER ", "INTEGER ")
      .replaceAll(" REAL ", " DOUBLE PRECISION ")
      .replaceAll(" TEXT ", " TEXT ")
      .replaceAll("AUTOINCREMENT", "")
  );
}

export function getSchemaSql(dialect) {
  if (dialect === "mysql") return mysqlTables();
  if (dialect === "postgres") return pgTables();
  return sqliteTables();
}
