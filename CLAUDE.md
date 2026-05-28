# Veridion — Claude Code Guide

## Project Layout

```
src/veridion/action/
  decision_history.py            # Core analytics: load + analyze history events
  decision_history_config.py     # Dataclasses + JSON loader for service config
  decision_history_export.py     # CLI: export analytics snapshots to disk
  decision_history_materialize.py# CLI: Athena/S3 materialization
  decision_history_service.py    # HTTP server: all routes, auth, HTML rendering
  decision_history_store.py      # SQLite + Postgres dual-backend store
  history_identity.py            # JWT/JWKS/OIDC identity resolution
  athena_queries.py              # Athena SQL query builder

src/veridion/adapters/
  gitlab_note.py                 # GitLab MR note upsert

tests/unit/                      # Pytest unit tests (no external deps required)
tests/integration/               # Integration tests (SQLite + store)
```

## Running Tests

```bash
python3 -m pytest tests/ -x -q
```

All tests are fast (<1s total). No Docker or external services needed for unit tests.

## Architecture

### Dual Store Backend
`decision_history_store.py` implements `HistoryStore` with two backends:
- `SQLiteHistoryStore` — default, single-file, uses `sqlite3`
- `PostgresHistoryStore` — production, uses psycopg2/psycopg3 via DSN

`open_history_store(sqlite_path=..., store_dsn=...)` is the context-manager entry point. `ensure_history_store` applies idempotent schema migrations and is cached per-process via `_SCHEMA_ENSURED`.

### HTTP Service
`decision_history_service.py` is a single-file HTTP server (`http.server.BaseHTTPRequestHandler`). All HTML is rendered as Python f-strings with `_html_escape()` on every user value. No JS framework.

Key functions:
- `resolve_history_request(path, ...)` — central dispatcher for all routes
- `_authorize_request(...)` — multi-mode auth: Bearer cookie → session-ID cookie → Authorization header → trusted headers
- `_build_overview_payload(...)` — aggregates all data for the dashboard

### Auth Modes (layered, evaluated in order)
1. `veridion_app_bearer` cookie → raw bearer token
2. `veridion_app_session_id` cookie → DB-backed session (checks status + expiry)
3. `Authorization: Bearer ...` header
4. Trusted gateway headers (`X-Veridion-*`) with shared-secret validation
5. JWT/OIDC via `history_identity.py`

### Token Storage
Producer tokens stored as `(token_prefix[:8], sha256_hash)`. Lookup fetches **all** rows by prefix then `secrets.compare_digest` iterates to find the match (prefix collision safe).

### Schema Migrations
SQLite: `CREATE TABLE IF NOT EXISTS` in `_apply_sqlite_migrations` + legacy `_sqlite_add_column_if_missing` shims for pre-v005 databases. **Do not add new `_sqlite_add_column_if_missing` calls** — put new columns in the `CREATE TABLE` statement and bump `STORE_SCHEMA_VERSION` + `STORE_MIGRATIONS`.

Postgres: `CREATE TABLE IF NOT EXISTS` + `ADD COLUMN IF NOT EXISTS` via `_postgres_add_column_if_missing`.

## Brand Design System

Fonts: `Space Grotesk` (body/headings) + `IBM Plex Mono` (labels, mono, eyebrows) via Google Fonts CDN.

Palette:
- `--bg: #f0ebe1` (warm linen)
- `--surface: #faf7f2`
- `--accent: #b34b18` (orange-red)
- `--ink: #161710`
- Topnav/hero dark: `#0b0d0a`

Three HTML render functions: `render_app_login_html`, `render_app_html`, `render_focus_page_html` — all in `decision_history_service.py`.

## Security Invariants (do not weaken)

- **SQL params**: all user-supplied values must use `?`/`%s` placeholders. f-string table names are guarded by `_ALLOWED_COUNT_TABLES` allowlist.
- **Token comparison**: always `secrets.compare_digest`, never `==`.
- **Session expiry**: checked via `_session_not_expired()` in `_authorize_request`.
- **Login rate limit**: `_check_login_rate()` enforces 10 attempts/60 s per client IP before `_handle_app_login_post_request` runs.
- **service_url**: only derived from `X-Forwarded-Proto` + `Host` when `trusted_header_auth.enabled` is True.
- **JWKS/OIDC URLs**: must use `https://` (enforced in `history_identity.py`).
- **HTML escaping**: all user/config values passed to `_html_escape()` before insertion into f-string HTML.

## Common Patterns

```python
# Opening the store
with open_history_store(sqlite_path=..., store_dsn=...) as store:
    store.upsert_event(...)
    store.commit()

# Top-level store helpers (each calls ensure_history_store + open)
analyze_history_store(sqlite_path=..., tenant_id=...)
list_producer_clients(sqlite_path=..., store_dsn=..., tenant_id=...)
```

## Key Constants

| Constant | Value | Location |
|---|---|---|
| `API_VERSION` | `"v1"` | service.py:51 |
| `APP_SESSION_COOKIE` | `"veridion_app_bearer"` | service.py:52 |
| `APP_SESSION_ID_COOKIE` | `"veridion_app_session_id"` | service.py:53 |
| `STORE_SCHEMA_VERSION` | `6` | store.py:18 |
| `_LOGIN_RATE_LIMIT` | `10` attempts/60 s | service.py |

## Config File Format (`--config-path`)

```json
{
  "tenants": [{"tenant_id": "acme", "history_paths": [...]}],
  "sqlite_path": "/data/history.db",
  "store_dsn": "postgresql://...",
  "auth_tokens": ["raw-bearer-token"],
  "tokens": [{"token": "...", "roles": ["admin"], "tenants": ["acme"]}],
  "jwt": {"oidc_discovery_url": "https://...", "audience": "..."},
  "trusted_headers": {"enabled": true, "shared_secret": "..."},
  "schedules": [{"schedule_id": "nightly", "cron": "0 2 * * *", "tenants": ["acme"]}]
}
```

## Roles

`ingestor` · `materializer` · `reader` · `admin` — enforced in `_authorize_request`.
