CREATE TABLE IF NOT EXISTS users (
  id          TEXT PRIMARY KEY,
  email       TEXT NOT NULL UNIQUE,
  name        TEXT,
  created_at  INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);

CREATE TABLE IF NOT EXISTS links (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  domain      TEXT NOT NULL,
  slug        TEXT NOT NULL,
  url         TEXT NOT NULL,
  title       TEXT,
  description TEXT,
  image       TEXT,
  expires_at  INTEGER,
  created_at  INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
  UNIQUE (domain, slug)
);

CREATE INDEX IF NOT EXISTS idx_links_user ON links(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS click_stats (
  link_id   TEXT NOT NULL REFERENCES links(id) ON DELETE CASCADE,
  day       TEXT NOT NULL,
  country   TEXT NOT NULL,
  referrer  TEXT NOT NULL,
  clicks    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (link_id, day, country, referrer)
) WITHOUT ROWID;
