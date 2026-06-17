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
  return [
    `CREATE TABLE IF NOT EXISTS servers (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(128) NOT NULL,
      hostname VARCHAR(255) DEFAULT '',
      description VARCHAR(512) DEFAULT '',
      agent_key VARCHAR(64) UNIQUE NOT NULL,
      is_active TINYINT(1) DEFAULT 1,
      last_seen DATETIME NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      mod_fail2ban TINYINT(1) DEFAULT 1,
      mod_csf TINYINT(1) DEFAULT 1,
      mod_nftables TINYINT(1) DEFAULT 1,
      cap_fail2ban TINYINT(1) DEFAULT 0,
      cap_csf TINYINT(1) DEFAULT 0,
      cap_nftables TINYINT(1) DEFAULT 0,
      latitude DOUBLE NULL,
      longitude DOUBLE NULL,
      location_label VARCHAR(128) DEFAULT ''
    )`,
    `CREATE TABLE IF NOT EXISTS ban_records (
      id INT AUTO_INCREMENT PRIMARY KEY,
      server_id INT NOT NULL,
      ts DATETIME NOT NULL,
      ip VARCHAR(45) NOT NULL,
      jail VARCHAR(64) NOT NULL,
      country VARCHAR(128) DEFAULT '',
      country_code VARCHAR(8) DEFAULT '',
      city VARCHAR(128) DEFAULT '',
      isp VARCHAR(255) DEFAULT '',
      lat DOUBLE DEFAULT 0,
      lon DOUBLE DEFAULT 0,
      INDEX ix_ban_server_ts (server_id, ts)
    )`,
    `CREATE TABLE IF NOT EXISTS event_logs (
      id INT AUTO_INCREMENT PRIMARY KEY,
      server_id INT NOT NULL,
      ts DATETIME NOT NULL,
      level VARCHAR(16) NOT NULL,
      message TEXT NOT NULL,
      ip VARCHAR(45) NULL,
      jail VARCHAR(64) NULL,
      INDEX ix_event_server_ts (server_id, ts)
    )`,
    `CREATE TABLE IF NOT EXISTS network_metrics (
      id INT AUTO_INCREMENT PRIMARY KEY,
      server_id INT NOT NULL,
      ts DATETIME NOT NULL,
      rx_mbps DOUBLE DEFAULT 0,
      tx_mbps DOUBLE DEFAULT 0,
      INDEX ix_net_server_ts (server_id, ts)
    )`,
    `CREATE TABLE IF NOT EXISTS connection_metrics (
      id INT AUTO_INCREMENT PRIMARY KEY,
      server_id INT NOT NULL,
      ts DATETIME NOT NULL,
      count INT DEFAULT 0,
      INDEX ix_conn_server_ts (server_id, ts)
    )`,
    `CREATE TABLE IF NOT EXISTS jail_snapshots (
      server_id INT PRIMARY KEY,
      updated_at DATETIME NULL,
      data LONGTEXT
    )`,
    `CREATE TABLE IF NOT EXISTS connection_snapshots (
      server_id INT PRIMARY KEY,
      updated_at DATETIME NULL,
      data LONGTEXT
    )`,
    `CREATE TABLE IF NOT EXISTS agent_commands (
      id INT AUTO_INCREMENT PRIMARY KEY,
      server_id INT NOT NULL,
      action VARCHAR(32) NOT NULL,
      payload TEXT,
      status VARCHAR(16) DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      completed_at DATETIME NULL
    )`,
    `CREATE TABLE IF NOT EXISTS csf_snapshots (
      server_id INT PRIMARY KEY,
      updated_at DATETIME NULL,
      data LONGTEXT
    )`,
    `CREATE TABLE IF NOT EXISTS nftables_snapshots (
      server_id INT PRIMARY KEY,
      updated_at DATETIME NULL,
      data LONGTEXT
    )`,
    `CREATE TABLE IF NOT EXISTS hub_settings (
      \`key\` VARCHAR(64) PRIMARY KEY,
      value LONGTEXT
    )`,
    `CREATE TABLE IF NOT EXISTS telegram_users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      telegram_id BIGINT UNIQUE NOT NULL,
      username VARCHAR(128) DEFAULT '',
      first_name VARCHAR(128) DEFAULT '',
      linked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      is_active TINYINT(1) DEFAULT 1
    )`,
    `CREATE TABLE IF NOT EXISTS telegram_link_codes (
      code VARCHAR(8) PRIMARY KEY,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME NOT NULL,
      used TINYINT(1) DEFAULT 0
    )`,
    `CREATE TABLE IF NOT EXISTS ip_whitelist (
      id INT AUTO_INCREMENT PRIMARY KEY,
      ip VARCHAR(64) NOT NULL,
      label VARCHAR(128) DEFAULT '',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS telegram_web_sessions (
      token VARCHAR(64) PRIMARY KEY,
      telegram_id BIGINT NOT NULL,
      expires_at DATETIME NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS panel_users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(64) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      totp_secret VARCHAR(64) NULL,
      two_fa_method VARCHAR(16) DEFAULT 'none',
      telegram_id BIGINT NULL,
      is_active TINYINT(1) DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS panel_sessions (
      token VARCHAR(64) PRIMARY KEY,
      user_id INT NOT NULL,
      expires_at DATETIME NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      ip_address VARCHAR(45) DEFAULT '',
      user_agent VARCHAR(512) DEFAULT ''
    )`,
    `CREATE TABLE IF NOT EXISTS two_fa_challenges (
      token VARCHAR(64) PRIMARY KEY,
      user_id INT NOT NULL,
      code VARCHAR(16) DEFAULT '',
      method VARCHAR(16) NOT NULL,
      purpose VARCHAR(32) DEFAULT 'login',
      expires_at DATETIME NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS branding_history (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NULL,
      username VARCHAR(64) DEFAULT '',
      changes LONGTEXT,
      snapshot LONGTEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS security_templates (
      id INT AUTO_INCREMENT PRIMARY KEY,
      kind VARCHAR(32) NOT NULL,
      slug VARCHAR(64) UNIQUE NOT NULL,
      name VARCHAR(128) NOT NULL,
      description TEXT,
      instructions TEXT,
      critical TINYINT(1) DEFAULT 0,
      payload TEXT,
      is_builtin TINYINT(1) DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`
  ];
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
