-- arcanist.sh registry schema. D1 is the source of truth; R2 holds tarballs,
-- sealed index segments and the offline-signed TUF root/mirrors files.

CREATE TABLE users (
  id          INTEGER PRIMARY KEY,
  login       TEXT NOT NULL UNIQUE,
  email       TEXT,
  is_admin    INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL
);

CREATE TABLE tokens (
  id            TEXT PRIMARY KEY,          -- public id, e.g. "tok_ab12..."
  user_id       INTEGER NOT NULL REFERENCES users(id),
  name          TEXT NOT NULL,
  token_hash    TEXT NOT NULL UNIQUE,      -- hex sha256 of the secret token
  scopes        TEXT NOT NULL,             -- space separated: publish yank owners tokens
  packages      TEXT,                      -- JSON array of allowed package names, NULL = all
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER,
  last_used_at  INTEGER,
  revoked_at    INTEGER
);
CREATE INDEX tokens_user ON tokens(user_id);

CREATE TABLE packages (
  name        TEXT PRIMARY KEY,
  name_lower  TEXT NOT NULL UNIQUE,
  synopsis    TEXT NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL
);

CREATE TABLE package_owners (
  package   TEXT NOT NULL REFERENCES packages(name),
  user_id   INTEGER NOT NULL REFERENCES users(id),
  added_at  INTEGER NOT NULL,
  PRIMARY KEY (package, user_id)
);

CREATE TABLE versions (
  package       TEXT NOT NULL REFERENCES packages(name),
  version       TEXT NOT NULL,
  sha256        TEXT NOT NULL,
  size          INTEGER NOT NULL,
  cabal_file    TEXT NOT NULL,
  synopsis      TEXT NOT NULL DEFAULT '',
  license       TEXT NOT NULL DEFAULT '',
  deps          TEXT NOT NULL DEFAULT '[]', -- JSON [{name, range}]
  yanked        INTEGER NOT NULL DEFAULT 0,
  yanked_at     INTEGER,
  published_by  INTEGER NOT NULL REFERENCES users(id),
  published_at  INTEGER NOT NULL,
  PRIMARY KEY (package, version)
);

-- Append-only index. A chunk is the tar bytes of 1..3 entries appended by one
-- publish or yank, plus a gzip member of the same bytes.
CREATE TABLE index_chunks (
  seq         INTEGER PRIMARY KEY,         -- 1, 2, 3, ... (no gaps)
  tar_offset  INTEGER NOT NULL,
  tar_bytes   BLOB NOT NULL,
  gz_offset   INTEGER NOT NULL,
  gz_bytes    BLOB NOT NULL
);

-- Runs of chunks moved to R2 (index/segments/<id>.tar and .tar.gz).
CREATE TABLE index_segments (
  id          INTEGER PRIMARY KEY,
  first_seq   INTEGER NOT NULL,
  last_seq    INTEGER NOT NULL,
  tar_offset  INTEGER NOT NULL,
  tar_length  INTEGER NOT NULL,
  gz_offset   INTEGER NOT NULL,
  gz_length   INTEGER NOT NULL
);

-- Single row (id = 1): where the index ends and the resumable SHA-256 states.
CREATE TABLE index_state (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  seq         INTEGER NOT NULL,
  tar_length  INTEGER NOT NULL,
  gz_length   INTEGER NOT NULL,
  tar_sha     BLOB NOT NULL,
  gz_sha      BLOB NOT NULL,
  updated_at  INTEGER NOT NULL
);

-- Online-signed TUF metadata (snapshot.json, timestamp.json) as served bytes.
CREATE TABLE tuf_meta (
  file        TEXT PRIMARY KEY,
  version     INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  body        BLOB NOT NULL,
  -- snapshot.json only: the index view it pins
  index_seq   INTEGER NOT NULL DEFAULT 0,
  tar_length  INTEGER NOT NULL DEFAULT 0,
  gz_length   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE verifiers (
  name        TEXT PRIMARY KEY,
  public_key  TEXT NOT NULL,              -- base64 raw Ed25519 public key
  created_at  INTEGER NOT NULL,
  revoked_at  INTEGER
);

CREATE TABLE attestations (
  package      TEXT NOT NULL,
  version      TEXT NOT NULL,
  verifier     TEXT NOT NULL REFERENCES verifiers(name),
  bhc_version  TEXT NOT NULL,
  profile      TEXT NOT NULL,
  result       TEXT NOT NULL CHECK (result IN ('pass', 'fail')),
  log_url      TEXT,
  built_at     TEXT NOT NULL,
  statement    TEXT NOT NULL,             -- canonical JSON that was signed
  signature    TEXT NOT NULL,
  received_at  INTEGER NOT NULL,
  PRIMARY KEY (package, version, verifier, bhc_version, profile),
  FOREIGN KEY (package, version) REFERENCES versions(package, version)
);

-- Name policy: Hackage lookup cache and admin grants of reserved names.
CREATE TABLE name_reservations (
  name_lower  TEXT PRIMARY KEY,
  on_hackage  INTEGER NOT NULL,
  checked_at  INTEGER NOT NULL,
  granted_to  INTEGER REFERENCES users(id)
);

CREATE TABLE audit_log (
  id       INTEGER PRIMARY KEY,
  at       INTEGER NOT NULL,
  user_id  INTEGER,
  action   TEXT NOT NULL,
  subject  TEXT NOT NULL,
  detail   TEXT
);
