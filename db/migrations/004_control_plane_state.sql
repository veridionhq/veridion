CREATE TABLE IF NOT EXISTS managed_tenants (
  tenant_id text NOT NULL PRIMARY KEY,
  display_name text NOT NULL,
  organization_name text NOT NULL,
  status text NOT NULL,
  created_at text NOT NULL
);

CREATE TABLE IF NOT EXISTS provider_secret_refs (
  tenant_id text NOT NULL,
  secret_name text NOT NULL,
  provider text NOT NULL,
  secret_ref text NOT NULL,
  description text NOT NULL,
  updated_at text NOT NULL,
  PRIMARY KEY (tenant_id, secret_name)
);

CREATE TABLE IF NOT EXISTS service_users (
  tenant_id text NOT NULL,
  user_id text NOT NULL,
  principal_name text NOT NULL,
  email text NOT NULL,
  roles_csv text NOT NULL,
  status text NOT NULL,
  created_at text NOT NULL,
  PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE IF NOT EXISTS service_sessions (
  session_id text NOT NULL PRIMARY KEY,
  tenant_id text NOT NULL,
  user_id text NOT NULL,
  principal_name text NOT NULL,
  auth_type text NOT NULL,
  roles_csv text NOT NULL,
  status text NOT NULL,
  created_at text NOT NULL,
  expires_at text NOT NULL
);

CREATE TABLE IF NOT EXISTS producer_clients (
  tenant_id text NOT NULL,
  client_id text NOT NULL,
  display_name text NOT NULL,
  token_hash text NOT NULL,
  token_prefix text NOT NULL,
  roles_csv text NOT NULL,
  status text NOT NULL,
  created_at text NOT NULL,
  PRIMARY KEY (tenant_id, client_id)
);
