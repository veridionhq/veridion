CREATE TABLE IF NOT EXISTS schema_migrations (
  migration_id text PRIMARY KEY,
  description text NOT NULL,
  applied_at text NOT NULL
);
