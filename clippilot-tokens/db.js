const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

// Store the database inside a local "data" folder so it survives restarts
// and is created automatically the first time the server runs.
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, 'clippilot.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS gmails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    gmail TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    gmail_id INTEGER NOT NULL,
    channel_handler TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (gmail_id) REFERENCES gmails(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_channels_gmail_id ON channels(gmail_id);
`);

module.exports = db;
