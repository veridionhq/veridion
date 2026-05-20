CREATE TABLE IF NOT EXISTS organizations (
  tenant_id text NOT NULL,
  organization_id text NOT NULL,
  display_name text NOT NULL,
  PRIMARY KEY (tenant_id, organization_id)
);

CREATE TABLE IF NOT EXISTS projects (
  tenant_id text NOT NULL,
  organization_id text NOT NULL,
  project_id text NOT NULL,
  display_name text NOT NULL,
  repository text NOT NULL,
  PRIMARY KEY (tenant_id, project_id)
);

CREATE TABLE IF NOT EXISTS services (
  tenant_id text NOT NULL,
  organization_id text NOT NULL,
  project_id text NOT NULL,
  service_id text NOT NULL,
  display_name text NOT NULL,
  repository text NOT NULL,
  service_owner text NOT NULL,
  owning_team text NOT NULL,
  service_criticality text NOT NULL,
  PRIMARY KEY (tenant_id, service_id)
);
