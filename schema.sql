-- D1 schema for Retest as a Service
CREATE TABLE IF NOT EXISTS retest_state (
  pr_number INTEGER PRIMARY KEY,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  last_seen_updated_at TEXT NULL,
  last_failure_checks TEXT NULL,
  next_retest_at TEXT NULL,
  last_retest_at TEXT NULL,
  disabled_at TEXT NULL
);

CREATE TABLE IF NOT EXISTS tracked_prs (
  pr_number INTEGER PRIMARY KEY,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS retest_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pr_number INTEGER NOT NULL,
  attempt_index INTEGER NOT NULL,
  scheduled_at TEXT NOT NULL,
  executed_at TEXT NULL,
  status TEXT NOT NULL,
  error_message TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_retest_attempts_due
  ON retest_attempts (executed_at, scheduled_at);

CREATE TABLE IF NOT EXISTS cron_runs (
  run_id TEXT PRIMARY KEY,
  scheduled_time_ms INTEGER NULL,
  cron TEXT NULL,
  started_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  finished_at TEXT NULL,
  status TEXT NOT NULL,
  error_message TEXT NULL
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
