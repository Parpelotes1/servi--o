-- schema.sql
CREATE TABLE IF NOT EXISTS posts (
  id           TEXT PRIMARY KEY,
  titulo       TEXT NOT NULL,
  descricao    TEXT NOT NULL,
  valor        REAL,
  valor_texto  TEXT NOT NULL DEFAULT 'A combinar',
  contato_tipo TEXT NOT NULL,
  contato      TEXT NOT NULL,
  autor        TEXT NOT NULL,
  fotos        TEXT NOT NULL DEFAULT '[]',
  status       TEXT NOT NULL DEFAULT 'pendente',
  ip_hash      TEXT,
  criado_em    TEXT NOT NULL,
  aprovado_em  TEXT
);

CREATE INDEX IF NOT EXISTS idx_posts_status ON posts (status, criado_em DESC);
CREATE INDEX IF NOT EXISTS idx_posts_ip ON posts (ip_hash, criado_em);

CREATE TABLE IF NOT EXISTS reports (
  id        TEXT PRIMARY KEY,
  post_id   TEXT NOT NULL,
  motivo    TEXT NOT NULL,
  criado_em TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reports_post ON reports (post_id);

CREATE TABLE IF NOT EXISTS admins (
  usuario    TEXT PRIMARY KEY,
  senha_hash TEXT NOT NULL,
  criado_em  TEXT NOT NULL
);
