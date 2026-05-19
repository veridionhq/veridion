import json

from veridion.action.decision_history_config import HistoryTenant, HistoryToken
from veridion.action.decision_history_store import upsert_history_store
from veridion.action.decision_history_service import resolve_history_request


def test_decision_history_service_routes_health_and_analytics(tmp_path) -> None:
    history_path = tmp_path / "history.ndjson"
    history_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "generated_at": "2026-05-14T12:00:00Z",
                        "repository": "acme/service-a",
                        "decision": {"verdict": "GO", "gate_status": "pass", "blocking_categories": []},
                        "automation": {"approval_gate_status": "satisfied", "stale_approvals": []},
                        "policy": {"pack_id": "app", "pack_version": "1", "rollout_stage": "general"},
                    }
                ),
                json.dumps(
                    {
                        "generated_at": "2026-05-14T13:00:00Z",
                        "repository": "acme/service-b",
                        "decision": {"verdict": "NO GO", "gate_status": "block", "blocking_categories": ["dependency_risk"]},
                        "automation": {"approval_gate_status": "blocked", "stale_approvals": []},
                        "policy": {"pack_id": "platform", "pack_version": "1", "rollout_stage": "general"},
                    }
                ),
            ]
        )
        + "\n"
    )
    history_paths = (str(history_path),)

    health_status, health = resolve_history_request("/healthz", history_paths=history_paths)
    analytics_status, analytics = resolve_history_request(
        "/analytics?repository=acme/service-b",
        history_paths=history_paths,
    )
    versioned_health_status, versioned_health = resolve_history_request("/api/v1/health", history_paths=history_paths)
    versioned_analytics_status, versioned_analytics = resolve_history_request(
        "/api/v1/analytics?repository=acme/service-b",
        history_paths=history_paths,
    )
    repositories_status, repositories = resolve_history_request("/repositories", history_paths=history_paths)

    assert health_status == 200
    assert health["status"] == "ok"
    assert analytics_status == 200
    assert analytics["summary"]["events"] == 1
    assert analytics["by_verdict"] == {"NO GO": 1}
    assert versioned_health_status == 200
    assert versioned_health["api_version"] == "v1"
    assert versioned_health["data"]["status"] == "ok"
    assert versioned_analytics_status == 200
    assert versioned_analytics["route"] == "/analytics"
    assert versioned_analytics["data"]["summary"]["events"] == 1
    assert repositories_status == 200
    assert repositories["repositories"] == ["acme/service-a", "acme/service-b"]


def test_decision_history_service_supports_tenants_and_auth(tmp_path) -> None:
    acme_history = tmp_path / "acme.ndjson"
    beta_history = tmp_path / "beta.ndjson"
    acme_history.write_text(
        json.dumps(
            {
                "generated_at": "2026-05-14T12:00:00Z",
                "repository": "acme/service-a",
                "decision": {"verdict": "GO", "gate_status": "pass", "blocking_categories": []},
                "automation": {"approval_gate_status": "satisfied", "stale_approvals": []},
                "policy": {"pack_id": "app", "pack_version": "1", "rollout_stage": "general"},
            }
        )
        + "\n"
    )
    beta_history.write_text(
        json.dumps(
            {
                "generated_at": "2026-05-14T13:00:00Z",
                "repository": "beta/service-b",
                "decision": {"verdict": "NO GO", "gate_status": "block", "blocking_categories": ["dependency_risk"]},
                "automation": {"approval_gate_status": "blocked", "stale_approvals": []},
                "policy": {"pack_id": "platform", "pack_version": "1", "rollout_stage": "general"},
            }
        )
        + "\n"
    )

    tenants = {
        "acme": HistoryTenant(tenant_id="acme", history_paths=(str(acme_history),)),
        "beta": HistoryTenant(tenant_id="beta", history_paths=(str(beta_history),)),
    }

    unauthorized_status, unauthorized = resolve_history_request(
        "/analytics?tenant=acme",
        history_paths=(),
        tenants=tenants,
        headers={},
        auth_tokens=("secret",),
    )
    tenants_status, tenants_payload = resolve_history_request(
        "/tenants",
        history_paths=(),
        tenants=tenants,
        headers={"Authorization": "Bearer secret"},
        auth_tokens=("secret",),
    )
    analytics_status, analytics = resolve_history_request(
        "/analytics?tenant=beta",
        history_paths=(),
        tenants=tenants,
        headers={"Authorization": "Bearer secret"},
        auth_tokens=("secret",),
    )
    scoped_list_status, scoped_list = resolve_history_request(
        "/tenants",
        history_paths=(),
        tenants=tenants,
        headers={"Authorization": "Bearer scoped"},
        scoped_tokens={"scoped": HistoryToken(token="scoped", tenants=("acme",))},
    )
    scoped_aggregate_status, scoped_aggregate = resolve_history_request(
        "/analytics",
        history_paths=(),
        tenants=tenants,
        headers={"Authorization": "Bearer scoped"},
        scoped_tokens={"scoped": HistoryToken(token="scoped", tenants=("acme",))},
    )

    assert unauthorized_status == 401
    assert unauthorized["error"] == "unauthorized"
    assert tenants_status == 200
    assert tenants_payload["tenants"] == ["acme", "beta"]
    assert analytics_status == 200
    assert analytics["by_verdict"] == {"NO GO": 1}
    assert scoped_list_status == 200
    assert scoped_list["tenants"] == ["acme"]
    assert scoped_aggregate_status == 403
    assert scoped_aggregate["error"] == "tenant_scope_required"
    dashboard_status, dashboard = resolve_history_request(
        "/dashboard?tenant=acme",
        history_paths=(),
        tenants=tenants,
        headers={"Authorization": "Bearer scoped"},
        scoped_tokens={"scoped": HistoryToken(token="scoped", tenants=("acme",))},
    )
    versioned_dashboard_status, versioned_dashboard = resolve_history_request(
        "/api/v1/dashboard?tenant=acme",
        history_paths=(),
        tenants=tenants,
        headers={"Authorization": "Bearer scoped"},
        scoped_tokens={"scoped": HistoryToken(token="scoped", tenants=("acme",))},
    )
    assert dashboard_status == 200
    assert "<html>" in dashboard["html"]
    assert versioned_dashboard_status == 200
    assert "<html>" in versioned_dashboard["html"]


def test_decision_history_service_uses_sqlite_store_and_scoped_tokens(tmp_path) -> None:
    sqlite_path = tmp_path / "history.db"
    acme_history = tmp_path / "acme.ndjson"
    acme_history.write_text(
        json.dumps(
            {
                "generated_at": "2026-05-14T12:00:00Z",
                "repository": "acme/service-a",
                "decision": {"verdict": "GO", "gate_status": "pass", "blocking_categories": []},
                "automation": {"approval_gate_status": "satisfied", "stale_approvals": []},
                "policy": {"pack_id": "app", "pack_version": "1", "rollout_stage": "general"},
            }
        )
        + "\n"
    )
    upsert_history_store(sqlite_path=sqlite_path, tenant_id="acme", history_paths=(str(acme_history),))
    tenants = {"acme": HistoryTenant(tenant_id="acme", history_paths=())}

    forbidden_status, forbidden = resolve_history_request(
        "/analytics?tenant=acme",
        history_paths=(),
        tenants=tenants,
        sqlite_path=str(sqlite_path),
        headers={"Authorization": "Bearer scoped"},
        scoped_tokens={"scoped": HistoryToken(token="scoped", tenants=("beta",))},
    )
    allowed_status, allowed = resolve_history_request(
        "/analytics?tenant=acme",
        history_paths=(),
        tenants=tenants,
        sqlite_path=str(sqlite_path),
        headers={"Authorization": "Bearer scoped"},
        scoped_tokens={"scoped": HistoryToken(token="scoped", tenants=("acme",))},
    )

    assert forbidden_status == 403
    assert forbidden["error"] == "forbidden"
    assert allowed_status == 200
    assert allowed["by_verdict"] == {"GO": 1}


def test_decision_history_service_enforces_roles_and_tracks_materializations(tmp_path) -> None:
    sqlite_path = tmp_path / "history.db"
    materialization_root = tmp_path / "materialized"
    history_path = tmp_path / "history.ndjson"
    config_path = tmp_path / "config.json"
    history_path.write_text(
        json.dumps(
            {
                "generated_at": "2026-05-14T12:00:00Z",
                "repository": "acme/service-a",
                "decision": {"verdict": "GO", "gate_status": "pass", "blocking_categories": []},
                "automation": {"approval_gate_status": "satisfied", "stale_approvals": []},
                "policy": {"pack_id": "app", "pack_version": "1", "rollout_stage": "general"},
            }
        )
        + "\n"
    )
    upsert_history_store(sqlite_path=sqlite_path, tenant_id="acme", history_paths=(str(history_path),))
    config_path.write_text(
        json.dumps(
            {
                "sqlite_path": str(sqlite_path),
                "materialization_root": str(materialization_root),
                "tenants": [{"tenant_id": "acme", "history_paths": []}],
                "tokens": [
                    {"token": "reader", "tenants": ["acme"], "roles": ["reader"]},
                    {"token": "materializer", "tenants": ["acme"], "roles": ["reader", "materializer"]},
                ],
            }
        )
    )
    tenants = {"acme": HistoryTenant(tenant_id="acme", history_paths=())}

    reader_post_status, reader_post = resolve_history_request(
        "/materializations",
        method="POST",
        body=json.dumps({"tenant": "acme", "run_id": "run-3"}),
        history_paths=(),
        tenants=tenants,
        sqlite_path=str(sqlite_path),
        materialization_root=str(materialization_root),
        config_path=str(config_path),
        headers={"Authorization": "Bearer reader"},
        scoped_tokens={"reader": HistoryToken(token="reader", tenants=("acme",), roles=("reader",))},
    )
    create_status, create_payload = resolve_history_request(
        "/materializations",
        method="POST",
        body=json.dumps({"tenant": "acme", "run_id": "run-3"}),
        history_paths=(),
        tenants=tenants,
        sqlite_path=str(sqlite_path),
        materialization_root=str(materialization_root),
        config_path=str(config_path),
        headers={"Authorization": "Bearer materializer"},
        scoped_tokens={"materializer": HistoryToken(token="materializer", tenants=("acme",), roles=("reader", "materializer"))},
    )
    list_status, list_payload = resolve_history_request(
        "/api/v1/materializations?tenant=acme",
        history_paths=(),
        tenants=tenants,
        sqlite_path=str(sqlite_path),
        materialization_root=str(materialization_root),
        config_path=str(config_path),
        headers={"Authorization": "Bearer reader"},
        scoped_tokens={"reader": HistoryToken(token="reader", tenants=("acme",), roles=("reader",))},
    )
    status_status, status_payload = resolve_history_request(
        "/api/v1/service/status?tenant=acme",
        history_paths=(),
        tenants=tenants,
        sqlite_path=str(sqlite_path),
        materialization_root=str(materialization_root),
        config_path=str(config_path),
        headers={"Authorization": "Bearer reader"},
        scoped_tokens={"reader": HistoryToken(token="reader", token_id="tok_reader", principal_name="reader-user", tenants=("acme",), roles=("reader",))},
    )

    assert reader_post_status == 403
    assert reader_post["error"] == "insufficient_role"
    assert create_status == 201
    assert create_payload["materialization"]["run_id"] == "run-3"
    assert list_status == 200
    assert list_payload["data"]["materializations"][0]["run_id"] == "run-3"
    assert status_status == 200
    assert status_payload["identity"]["token_id"] == "tok_reader"
    assert status_payload["data"]["store"]["backend"] == "sqlite"


def test_decision_history_service_rejects_inactive_identity(tmp_path) -> None:
    history_path = tmp_path / "history.ndjson"
    history_path.write_text(
        json.dumps(
            {
                "generated_at": "2026-05-14T12:00:00Z",
                "repository": "acme/service-a",
                "decision": {"verdict": "GO", "gate_status": "pass", "blocking_categories": []},
                "automation": {"approval_gate_status": "satisfied", "stale_approvals": []},
                "policy": {"pack_id": "app", "pack_version": "1", "rollout_stage": "general"},
            }
        )
        + "\n"
    )
    tenants = {"acme": HistoryTenant(tenant_id="acme", history_paths=(str(history_path),))}

    status, payload = resolve_history_request(
        "/api/v1/analytics?tenant=acme",
        history_paths=(),
        tenants=tenants,
        headers={"Authorization": "Bearer disabled"},
        scoped_tokens={"disabled": HistoryToken(token="disabled", status="disabled", tenants=("acme",), roles=("reader",))},
    )

    assert status == 403
    assert payload["data"]["error"] == "identity_inactive"
