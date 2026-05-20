CREATE TABLE IF NOT EXISTS decision_events (
  tenant_id text NOT NULL,
  event_key text NOT NULL,
  generated_at text NOT NULL,
  repository text NOT NULL,
  policy_pack_id text NOT NULL,
  event_payload text NOT NULL,
  PRIMARY KEY (tenant_id, event_key)
);

CREATE INDEX IF NOT EXISTS decision_events_tenant_generated_at_idx
  ON decision_events (tenant_id, generated_at);

CREATE INDEX IF NOT EXISTS decision_events_tenant_repository_idx
  ON decision_events (tenant_id, repository);
