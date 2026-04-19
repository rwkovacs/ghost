const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'ghost.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS subs (
    name TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sub TEXT NOT NULL REFERENCES subs(name) ON DELETE CASCADE,
    title TEXT NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    url TEXT,
    created_at INTEGER NOT NULL,
    ip_hash TEXT NOT NULL,
    removed INTEGER NOT NULL DEFAULT 0,
    score INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_posts_sub ON posts(sub, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at DESC);

  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    parent_id INTEGER REFERENCES comments(id) ON DELETE CASCADE,
    body TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    ip_hash TEXT NOT NULL,
    removed INTEGER NOT NULL DEFAULT 0,
    score INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id, created_at);

  CREATE TABLE IF NOT EXISTS votes (
    ip_hash TEXT NOT NULL,
    kind TEXT NOT NULL,
    target_id INTEGER NOT NULL,
    value INTEGER NOT NULL,
    PRIMARY KEY (ip_hash, kind, target_id)
  );

  CREATE TABLE IF NOT EXISTS bans (
    ip_hash TEXT PRIMARY KEY,
    reason TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
  );
`);

module.exports = db;
