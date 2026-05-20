CREATE TABLE IF NOT EXISTS materialization_runs (
  run_id text NOT NULL,
  tenant_id text NOT NULL,
  generated_at text NOT NULL,
  output_root text NOT NULL,
  run_path text NOT NULL,
  since_value text NOT NULL,
  until_value text NOT NULL,
  status text NOT NULL,
  athena_database text NOT NULL,
  athena_table text NOT NULL,
  athena_s3_location text NOT NULL,
  PRIMARY KEY (tenant_id, run_id)
);

CREATE INDEX IF NOT EXISTS materialization_runs_tenant_generated_at_idx
  ON materialization_runs (tenant_id, generated_at);
