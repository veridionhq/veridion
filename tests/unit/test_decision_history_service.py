import base64
import hashlib
import hmac
import json
import sqlite3

from veridion.action.decision_history_config import HistoryTenant, HistoryToken, JWTAuthConfig, MaterializationSchedule, TrustedHeaderAuthConfig
from veridion.action.decision_history_store import list_control_plane_audit, upsert_history_store
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
    assert "Store Status" in dashboard["html"]
    assert versioned_dashboard_status == 200
    assert "<html>" in versioned_dashboard["html"]


def test_decision_history_service_app_login_uses_session_cookie(tmp_path) -> None:
    sqlite_path = tmp_path / "history.db"
    scoped = {"admin": HistoryToken(token="admin", tenants=("acme",), roles=("admin",), principal_name="Admin One", token_id="admin-1")}

    resolve_history_request(
        "/api/v1/admin/tenants",
        method="POST",
        body=json.dumps({"tenant_id": "acme", "display_name": "Acme", "organization_name": "Acme Org"}),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": "Bearer admin"},
        scoped_tokens=scoped,
    )

    login_page_status, login_page = resolve_history_request(
        "/api/v1/app?tenant=acme",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={},
        scoped_tokens=scoped,
    )
    login_status, login_payload = resolve_history_request(
        "/api/v1/app/login",
        method="POST",
        body="tenant_id=&token=Bearer%20admin&next=%2Fapi%2Fv1%2Fapp",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        scoped_tokens=scoped,
    )
    cookie_header = str(login_payload.get("__headers", {}).get("Set-Cookie", ""))
    app_status, app_payload = resolve_history_request(
        "/api/v1/app?tenant=acme",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Cookie": cookie_header},
        scoped_tokens=scoped,
    )

    assert login_page_status == 200
    assert "Sign In To The Control Plane" in login_page["html"]
    assert "Operator Token Or JWT" in login_page["html"]
    assert login_status == 200
    assert "Signed in. Redirecting to the hosted app." in login_payload["html"]
    assert "veridion_app_bearer=" in cookie_header
    assert app_status == 200
    assert "Onboarding Checklist" in app_payload["html"]
    assert "Control Plane Audit" in app_payload["html"]


def test_decision_history_service_browser_session_can_submit_onboarding_forms(tmp_path) -> None:
    sqlite_path = tmp_path / "history.db"
    scoped = {"admin": HistoryToken(token="admin", tenants=("acme",), roles=("admin",), principal_name="Admin One", token_id="admin-1")}

    resolve_history_request(
        "/api/v1/admin/tenants",
        method="POST",
        body=json.dumps({"tenant_id": "acme", "display_name": "Acme", "organization_name": "Acme Org"}),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": "Bearer admin"},
        scoped_tokens=scoped,
    )

    login_status, login_payload = resolve_history_request(
        "/api/v1/app/login",
        method="POST",
        body="tenant_id=acme&token=admin&next=%2Fapi%2Fv1%2Fapp%3Ftenant%3Dacme",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        scoped_tokens=scoped,
    )
    cookie_header = str(login_payload.get("__headers", {}).get("Set-Cookie", ""))
    producer_status, producer_payload = resolve_history_request(
        "/api/v1/app",
        method="POST",
        body="action=create_producer_client&tenant_id=acme&client_id=github-actions&display_name=GitHub+Actions&roles_csv=ingestor&status=active",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie_header},
        scoped_tokens=scoped,
    )
    clients_status, clients_payload = resolve_history_request(
        "/api/v1/admin/producer-clients?tenant=acme",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Cookie": cookie_header},
        scoped_tokens=scoped,
    )

    assert login_status == 200
    assert producer_status == 200
    assert "Producer client github-actions created." in producer_payload["html"]
    assert "Producer token issued once." in producer_payload["html"]
    assert clients_status == 200
    assert clients_payload["data"]["producer_clients"][0]["client_id"] == "github-actions"
    assert clients_payload["identity"]["principal_name"] == "Admin One"


def test_decision_history_service_admin_producer_routes_round_trip(tmp_path) -> None:
    sqlite_path = tmp_path / "history.db"
    scoped = {"admin": HistoryToken(token="admin", tenants=("acme",), roles=("admin",), principal_name="Admin One", token_id="admin-1")}

    resolve_history_request(
        "/api/v1/admin/tenants",
        method="POST",
        body=json.dumps({"tenant_id": "acme", "display_name": "Acme", "organization_name": "Acme Org"}),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": "Bearer admin"},
        scoped_tokens=scoped,
    )

    create_status, create_payload = resolve_history_request(
        "/api/v1/admin/producer-clients",
        method="POST",
        body=json.dumps({"tenant": "acme", "client_id": "github-actions", "display_name": "GitHub Actions"}),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": "Bearer admin"},
        scoped_tokens=scoped,
    )
    list_status, list_payload = resolve_history_request(
        "/api/v1/admin/producer-clients?tenant=acme",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": "Bearer admin"},
        scoped_tokens=scoped,
    )

    assert create_status == 201
    assert create_payload["data"]["producer_client"]["client_id"] == "github-actions"
    assert create_payload["identity"]["principal_name"] == "Admin One"
    assert list_status == 200
    assert list_payload["data"]["producer_clients"][0]["client_id"] == "github-actions"
    assert list_payload["identity"]["principal_name"] == "Admin One"


def test_decision_history_service_browser_session_login_logout_records_audit(tmp_path) -> None:
    sqlite_path = tmp_path / "history.db"
    scoped = {"admin": HistoryToken(token="admin", tenants=("acme",), roles=("admin",), principal_name="Admin One", token_id="admin-1")}

    resolve_history_request(
        "/api/v1/admin/tenants",
        method="POST",
        body=json.dumps({"tenant_id": "acme", "display_name": "Acme", "organization_name": "Acme Org"}),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": "Bearer admin"},
        scoped_tokens=scoped,
    )

    failed_status, failed_payload = resolve_history_request(
        "/api/v1/app/login",
        method="POST",
        body="tenant_id=acme&token=bad-token&next=%2Fapi%2Fv1%2Fapp%3Ftenant%3Dacme",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        scoped_tokens=scoped,
    )
    login_status, login_payload = resolve_history_request(
        "/api/v1/app/login",
        method="POST",
        body="tenant_id=acme&token=Bearer%20admin&next=%2Fapi%2Fv1%2Fapp%3Ftenant%3Dacme",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        scoped_tokens=scoped,
    )
    cookie_header = str(login_payload.get("__headers", {}).get("Set-Cookie", ""))
    logout_status, logout_payload = resolve_history_request(
        "/api/v1/app/logout",
        method="POST",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Cookie": cookie_header},
        scoped_tokens=scoped,
    )

    audit = list_control_plane_audit(sqlite_path=str(sqlite_path), tenant_id="acme")
    audit_actions = {str(item.get("action", "")) for item in audit}

    assert failed_status == 200
    assert "Sign-in failed." in failed_payload["html"]
    assert login_status == 200
    assert "Signed in. Redirecting to the hosted app." in login_payload["html"]
    assert "veridion_app_bearer=" in cookie_header
    assert logout_status == 200
    assert "Signed out." in logout_payload["html"]
    assert "veridion_app_bearer=" in str(logout_payload.get("__headers", {}).get("Set-Cookie", ""))
    assert "Max-Age=0" in str(logout_payload.get("__headers", {}).get("Set-Cookie", ""))
    assert {"browser_login_failed", "browser_login_succeeded", "browser_logout"}.issubset(audit_actions)


def test_decision_history_service_repository_connect_state_matrix(tmp_path) -> None:
    sqlite_path = tmp_path / "history.db"
    admin_token = "admin"
    scoped = {admin_token: HistoryToken(token=admin_token, tenants=("acme",), roles=("admin",), principal_name="Admin One", token_id="admin-1")}

    resolve_history_request(
        "/api/v1/admin/tenants",
        method="POST",
        body=json.dumps({"tenant_id": "acme", "display_name": "Acme", "organization_name": "Acme Org"}),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": f"Bearer {admin_token}"},
        scoped_tokens=scoped,
    )

    blocked_status, blocked_payload = resolve_history_request(
        "/api/v1/app",
        method="POST",
        body="action=connect_repository&tenant_id=acme&repository=acme%2Fservice-a&service=service-a&organization=acme&project_id=acme%2Fservice-a&service_owner=payments-owner&owning_team=payments&service_criticality=high",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": f"Bearer {admin_token}", "Content-Type": "application/x-www-form-urlencoded"},
        scoped_tokens=scoped,
    )
    create_status, create_payload = resolve_history_request(
        "/api/v1/admin/producer-clients",
        method="POST",
        body=json.dumps({"tenant": "acme", "client_id": "github-actions", "display_name": "GitHub Actions"}),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": f"Bearer {admin_token}"},
        scoped_tokens=scoped,
    )
    producer_token = str(create_payload["data"]["producer_client"]["token"])
    waiting_status, waiting_payload = resolve_history_request(
        "/api/v1/app",
        method="POST",
        body="action=connect_repository&tenant_id=acme&repository=acme%2Fservice-a&service=service-a&organization=acme&project_id=acme%2Fservice-a&service_owner=payments-owner&owning_team=payments&service_criticality=high&producer_client=github-actions",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": f"Bearer {admin_token}", "Content-Type": "application/x-www-form-urlencoded"},
        scoped_tokens=scoped,
    )
    wrong_ingest_status, wrong_ingest_payload = resolve_history_request(
        "/api/v1/events",
        method="POST",
        body=json.dumps(
            {
                "tenant": "acme",
                "event": {
                    "generated_at": "2026-05-20T12:00:00Z",
                    "repository": "acme/service-b",
                    "organization": "acme",
                    "project": "acme/service-b",
                    "service": "service-b",
                    "decision": {"verdict": "NO GO", "gate_status": "block", "blocking_categories": ["public_exposure"]},
                    "automation": {"approval_gate_status": "blocked", "stale_approvals": []},
                    "policy": {"pack_id": "application-team", "pack_version": "1", "rollout_stage": "general"},
                    "trust_context": {"service_owner": "payments-owner", "owning_team": "payments", "service_criticality": "high"},
                },
            }
        ),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": f"Bearer {producer_token}"},
        scoped_tokens=scoped,
    )
    warning_status, warning_payload = resolve_history_request(
        "/api/v1/app",
        method="POST",
        body="action=connect_repository&tenant_id=acme&repository=acme%2Fservice-a&service=service-a&organization=acme&project_id=acme%2Fservice-a&service_owner=payments-owner&owning_team=payments&service_criticality=high&producer_client=github-actions",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": f"Bearer {admin_token}", "Content-Type": "application/x-www-form-urlencoded"},
        scoped_tokens=scoped,
    )
    correct_ingest_status, correct_ingest_payload = resolve_history_request(
        "/api/v1/events",
        method="POST",
        body=json.dumps(
            {
                "tenant": "acme",
                "event": {
                    "generated_at": "2026-05-20T12:05:00Z",
                    "repository": "acme/service-a",
                    "organization": "acme",
                    "project": "acme/service-a",
                    "service": "service-a",
                    "decision": {"verdict": "CONDITIONAL GO", "gate_status": "review", "blocking_categories": ["public_exposure"]},
                    "automation": {"approval_gate_status": "blocked", "stale_approvals": []},
                    "policy": {"pack_id": "platform-team", "pack_version": "1", "rollout_stage": "general"},
                    "trust_context": {"service_owner": "payments-owner", "owning_team": "payments", "service_criticality": "critical"},
                },
            }
        ),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": f"Bearer {producer_token}"},
        scoped_tokens=scoped,
    )
    success_status, success_payload = resolve_history_request(
        "/api/v1/app",
        method="POST",
        body="action=connect_repository&tenant_id=acme&repository=acme%2Fservice-a&service=service-a&organization=acme&project_id=acme%2Fservice-a&service_owner=payments-owner&owning_team=payments&service_criticality=high&producer_client=github-actions",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": f"Bearer {admin_token}", "Content-Type": "application/x-www-form-urlencoded"},
        scoped_tokens=scoped,
    )

    onboarding_audit = [
        item for item in list_control_plane_audit(sqlite_path=str(sqlite_path), tenant_id="acme") if str(item.get("action", "")) == "repository_onboarding_prepared"
    ]

    assert blocked_status == 200
    assert "No producer client is selected for this repository yet." in blocked_payload["html"]
    assert create_status == 201
    assert create_payload["data"]["producer_client"]["client_id"] == "github-actions"
    assert waiting_status == 200
    assert "Listening for the first hosted decision event from CI." in waiting_payload["html"]
    assert wrong_ingest_status == 202
    assert wrong_ingest_payload["data"]["repository"] == "acme/service-b"
    assert warning_status == 200
    assert "latest one landed for acme/service-b, not acme/service-a" in warning_payload["html"]
    assert correct_ingest_status == 202
    assert correct_ingest_payload["data"]["repository"] == "acme/service-a"
    assert success_status == 200
    assert "First hosted decision received." in success_payload["html"]
    assert "Open repository page" in success_payload["html"]
    assert len(onboarding_audit) >= 4


def test_decision_history_service_repository_connect_surfaces_missing_token_and_required_fields(tmp_path) -> None:
    sqlite_path = tmp_path / "history.db"
    admin_token = "admin"
    scoped = {admin_token: HistoryToken(token=admin_token, tenants=("acme",), roles=("admin",), principal_name="Admin One", token_id="admin-1")}

    resolve_history_request(
        "/api/v1/admin/tenants",
        method="POST",
        body=json.dumps({"tenant_id": "acme", "display_name": "Acme", "organization_name": "Acme Org"}),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": f"Bearer {admin_token}"},
        scoped_tokens=scoped,
    )
    create_status, _ = resolve_history_request(
        "/api/v1/admin/producer-clients",
        method="POST",
        body=json.dumps({"tenant": "acme", "client_id": "github-actions", "display_name": "GitHub Actions"}),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": f"Bearer {admin_token}"},
        scoped_tokens=scoped,
    )
    with sqlite3.connect(sqlite_path) as connection:
        connection.execute("UPDATE producer_clients SET token_prefix = '' WHERE tenant_id = ? AND client_id = ?", ("acme", "github-actions"))
        connection.commit()

    missing_token_status, missing_token_payload = resolve_history_request(
        "/api/v1/app",
        method="POST",
        body="action=connect_repository&tenant_id=acme&repository=acme%2Fservice-a&service=service-a&organization=acme&project_id=acme%2Fservice-a&service_owner=payments-owner&owning_team=payments&service_criticality=high&producer_client=github-actions",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": f"Bearer {admin_token}", "Content-Type": "application/x-www-form-urlencoded"},
        scoped_tokens=scoped,
    )
    missing_fields_status, missing_fields_payload = resolve_history_request(
        "/api/v1/app",
        method="POST",
        body="action=connect_repository&tenant_id=acme&repository=acme%2Fservice-a",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": f"Bearer {admin_token}", "Content-Type": "application/x-www-form-urlencoded"},
        scoped_tokens=scoped,
    )

    assert create_status == 201
    assert missing_token_status == 200
    assert "no token prefix is stored" in missing_token_payload["html"]
    assert "Rotate the producer or create a new one" in missing_token_payload["html"]
    assert missing_fields_status == 200
    assert "Tenant, repository, and service are required." in missing_fields_payload["html"]


def test_decision_history_service_control_plane_audit_tracks_hosted_actions(tmp_path) -> None:
    sqlite_path = tmp_path / "history.db"
    materialization_root = tmp_path / "materialized"
    config_path = tmp_path / "config.json"
    admin_token = "admin"
    scoped = {admin_token: HistoryToken(token=admin_token, tenants=("acme",), roles=("admin", "materializer"), principal_name="Admin One", token_id="admin-1")}
    schedules = {
        "nightly": MaterializationSchedule(
            schedule_id="nightly",
            cron="0 3 * * *",
            tenants=("acme",),
            athena_database="analytics",
            athena_s3_location_template="s3://bucket/{tenant_id}/",
        )
    }
    tenants = {"acme": HistoryTenant(tenant_id="acme", history_paths=())}
    config_path.write_text(
        json.dumps(
            {
                "sqlite_path": str(sqlite_path),
                "materialization_root": str(materialization_root),
                "tenants": [{"tenant_id": "acme", "history_paths": []}],
                "schedules": [
                    {
                        "schedule_id": "nightly",
                        "cron": "0 3 * * *",
                        "tenants": ["acme"],
                        "athena_database": "analytics",
                        "athena_s3_location_template": "s3://bucket/{tenant_id}/",
                    }
                ],
            }
        )
    )

    resolve_history_request(
        "/api/v1/admin/tenants",
        method="POST",
        body=json.dumps({"tenant_id": "acme", "display_name": "Acme", "organization_name": "Acme Org"}),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": f"Bearer {admin_token}"},
        scoped_tokens=scoped,
    )
    resolve_history_request(
        "/api/v1/admin/users",
        method="POST",
        body=json.dumps({"tenant": "acme", "user_id": "alice", "principal_name": "Alice Doe", "roles_csv": "reader,admin"}),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": f"Bearer {admin_token}"},
        scoped_tokens=scoped,
    )
    resolve_history_request(
        "/api/v1/admin/provider-secrets",
        method="POST",
        body=json.dumps({"tenant": "acme", "secret_name": "pagerduty-token", "provider": "pagerduty", "secret_ref": "aws-sm://pagerduty/acme"}),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": f"Bearer {admin_token}"},
        scoped_tokens=scoped,
    )
    create_status, create_payload = resolve_history_request(
        "/api/v1/admin/producer-clients",
        method="POST",
        body=json.dumps({"tenant": "acme", "client_id": "github-actions", "display_name": "GitHub Actions"}),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": f"Bearer {admin_token}"},
        scoped_tokens=scoped,
    )
    producer_token = str(create_payload["data"]["producer_client"]["token"])
    resolve_history_request(
        "/api/v1/events",
        method="POST",
        body=json.dumps(
            {
                "tenant": "acme",
                "event": {
                    "generated_at": "2026-05-20T12:15:00Z",
                    "repository": "acme/service-a",
                    "organization": "acme",
                    "project": "acme/service-a",
                    "service": "service-a",
                    "decision": {"verdict": "NO GO", "gate_status": "block", "blocking_categories": ["public_exposure"]},
                    "automation": {"approval_gate_status": "blocked", "stale_approvals": []},
                    "policy": {"pack_id": "platform-team", "pack_version": "1", "rollout_stage": "general"},
                    "trust_context": {"service_owner": "payments-owner", "owning_team": "payments", "service_criticality": "critical"},
                },
            }
        ),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": f"Bearer {producer_token}"},
        scoped_tokens=scoped,
    )
    materialization_status, materialization_payload = resolve_history_request(
        "/api/v1/materializations",
        method="POST",
        body=json.dumps({"tenant": "acme", "run_id": "run-audit-1", "schedule_id": "nightly"}),
        history_paths=(),
        tenants=tenants,
        sqlite_path=str(sqlite_path),
        materialization_root=str(materialization_root),
        config_path=str(config_path),
        schedules=schedules,
        headers={"Authorization": f"Bearer {admin_token}"},
        scoped_tokens=scoped,
    )
    app_status, app_payload = resolve_history_request(
        "/api/v1/app?tenant=acme",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": f"Bearer {admin_token}"},
        scoped_tokens=scoped,
    )

    audit_actions = {str(item.get("action", "")) for item in list_control_plane_audit(sqlite_path=str(sqlite_path), tenant_id="acme")}

    assert create_status == 201
    assert materialization_status == 201
    assert materialization_payload["data"]["materialization"]["run_id"] == "run-audit-1"
    assert app_status == 200
    assert "Control Plane Audit" in app_payload["html"]
    assert "event_ingested" in app_payload["html"]
    assert {"tenant_provisioned", "service_user_upserted", "provider_secret_upserted", "producer_created", "event_ingested", "materialization_created"}.issubset(audit_actions)


def test_decision_history_service_renders_runtime_failure_observability(tmp_path) -> None:
    sqlite_path = tmp_path / "history.db"
    scoped = {"admin": HistoryToken(token="admin", tenants=("acme",), roles=("admin",), principal_name="Admin One", token_id="admin-1")}
    materialization_root = tmp_path / "materialized"
    config_path = tmp_path / "config.json"
    schedules = {
        "nightly": MaterializationSchedule(
            schedule_id="nightly",
            cron="0 3 * * *",
            tenants=("acme",),
            athena_database="analytics",
            athena_s3_location_template="s3://bucket/{tenant_id}/",
        )
    }
    config_path.write_text(
        json.dumps(
            {
                "sqlite_path": str(sqlite_path),
                "materialization_root": str(materialization_root),
                "tenants": [{"tenant_id": "acme", "history_paths": []}],
                "schedules": [{"schedule_id": "nightly", "cron": "0 3 * * *", "tenants": ["acme"]}],
            }
        )
    )

    resolve_history_request(
        "/api/v1/admin/tenants",
        method="POST",
        body=json.dumps({"tenant_id": "acme", "display_name": "Acme", "organization_name": "Acme Org"}),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": "Bearer admin"},
        scoped_tokens=scoped,
    )
    failed_login_status, _ = resolve_history_request(
        "/api/v1/app/login",
        method="POST",
        body="tenant_id=acme&token=bad-token&next=%2Fapi%2Fv1%2Fapp%3Ftenant%3Dacme",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        scoped_tokens=scoped,
    )
    ingest_failure_status, _ = resolve_history_request(
        "/api/v1/events",
        method="POST",
        body=json.dumps({"tenant": "acme", "event": {"generated_at": "2026-05-20T12:00:00Z"}}),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": "Bearer admin"},
        scoped_tokens=scoped,
    )
    materialization_failure_status, _ = resolve_history_request(
        "/api/v1/materializations",
        method="POST",
        body=json.dumps({"tenant": "acme", "schedule_id": "missing-schedule"}),
        history_paths=(),
        tenants={"acme": HistoryTenant(tenant_id="acme", history_paths=())},
        sqlite_path=str(sqlite_path),
        materialization_root=str(materialization_root),
        config_path=str(config_path),
        schedules=schedules,
        headers={"Authorization": "Bearer admin"},
        scoped_tokens=scoped,
    )

    status, payload = resolve_history_request(
        "/api/v1/app?tenant=acme",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": "Bearer admin"},
        scoped_tokens=scoped,
    )

    assert failed_login_status == 200
    assert ingest_failure_status == 400
    assert materialization_failure_status == 404
    assert status == 200
    assert "Latest auth failure" in payload["html"]
    assert "token or tenant scope rejected" in payload["html"]
    assert "Latest ingest issue" in payload["html"]
    assert "repository field missing" in payload["html"]
    assert "Latest scheduler issue" in payload["html"]
    assert "schedule not found" in payload["html"]


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
                "schedules": [
                    {
                        "schedule_id": "nightly",
                        "cron": "0 3 * * *",
                        "tenants": ["acme"],
                        "athena_database": "analytics",
                        "athena_s3_location_template": "s3://bucket/{tenant_id}/",
                    }
                ],
                "tenants": [{"tenant_id": "acme", "history_paths": []}],
                "tokens": [
                    {"token": "reader", "tenants": ["acme"], "roles": ["reader"]},
                    {"token": "materializer", "tenants": ["acme"], "roles": ["reader", "materializer"]},
                ],
            }
    )
    )
    tenants = {"acme": HistoryTenant(tenant_id="acme", history_paths=())}
    schedule_map = {
        "nightly": MaterializationSchedule(
            schedule_id="nightly",
            cron="0 3 * * *",
            tenants=("acme",),
            athena_database="analytics",
            athena_s3_location_template="s3://bucket/{tenant_id}/",
        )
    }

    reader_post_status, reader_post = resolve_history_request(
        "/materializations",
        method="POST",
        body=json.dumps({"tenant": "acme", "run_id": "run-3", "schedule_id": "nightly"}),
        history_paths=(),
        tenants=tenants,
        schedules=schedule_map,
        sqlite_path=str(sqlite_path),
        materialization_root=str(materialization_root),
        config_path=str(config_path),
        headers={"Authorization": "Bearer reader"},
        scoped_tokens={"reader": HistoryToken(token="reader", tenants=("acme",), roles=("reader",))},
    )
    create_status, create_payload = resolve_history_request(
        "/api/v1/materializations",
        method="POST",
        body=json.dumps({"tenant": "acme", "run_id": "run-3", "schedule_id": "nightly"}),
        history_paths=(),
        tenants=tenants,
        schedules=schedule_map,
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
        schedules=schedule_map,
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
        schedules=schedule_map,
        sqlite_path=str(sqlite_path),
        materialization_root=str(materialization_root),
        config_path=str(config_path),
        headers={"Authorization": "Bearer reader"},
        scoped_tokens={"reader": HistoryToken(token="reader", token_id="tok_reader", principal_name="reader-user", tenants=("acme",), roles=("reader",))},
    )
    schedules_status, schedules_payload = resolve_history_request(
        "/api/v1/materialization-schedules",
        history_paths=(),
        tenants=tenants,
        headers={"Authorization": "Bearer reader"},
        scoped_tokens={"reader": HistoryToken(token="reader", token_id="tok_reader", principal_name="reader-user", tenants=("acme",), roles=("reader",))},
        schedules=schedule_map,
    )

    assert reader_post_status == 403
    assert reader_post["error"] == "insufficient_role"
    assert create_status == 201
    assert create_payload["data"]["schedule_id"] == "nightly"
    assert create_payload["data"]["materialization"]["run_id"] == "run-3"
    assert list_status == 200
    assert list_payload["data"]["materializations"][0]["run_id"] == "run-3"
    assert status_status == 200
    assert status_payload["identity"]["token_id"] == "tok_reader"
    assert status_payload["data"]["store"]["backend"] == "sqlite"
    assert schedules_status == 200
    assert schedules_payload["data"]["schedules"][0]["schedule_id"] == "nightly"


def test_decision_history_service_enforces_roles_across_app_and_admin_surfaces(tmp_path) -> None:
    sqlite_path = tmp_path / "history.db"
    tenants = {"acme": HistoryTenant(tenant_id="acme", history_paths=())}

    resolve_history_request(
        "/api/v1/admin/tenants",
        method="POST",
        body=json.dumps({"tenant_id": "acme", "display_name": "Acme", "organization_name": "Acme Org"}),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": "Bearer admin"},
        scoped_tokens={"admin": HistoryToken(token="admin", tenants=("acme",), roles=("admin",), principal_name="Admin One", token_id="admin-1")},
    )

    reader_app_post_status, reader_app_post = resolve_history_request(
        "/api/v1/app",
        method="POST",
        body="action=create_producer_client&tenant_id=acme&client_id=github-actions&display_name=GitHub+Actions&roles_csv=ingestor&status=active",
        history_paths=(),
        tenants=tenants,
        sqlite_path=str(sqlite_path),
        headers={"Authorization": "Bearer reader", "Content-Type": "application/x-www-form-urlencoded"},
        scoped_tokens={"reader": HistoryToken(token="reader", tenants=("acme",), roles=("reader",), principal_name="Reader One", token_id="reader-1")},
    )
    materializer_admin_status, materializer_admin = resolve_history_request(
        "/api/v1/admin/producer-clients",
        method="POST",
        body=json.dumps({"tenant": "acme", "client_id": "ci-acme", "display_name": "CI Acme"}),
        history_paths=(),
        tenants=tenants,
        sqlite_path=str(sqlite_path),
        headers={"Authorization": "Bearer materializer"},
        scoped_tokens={"materializer": HistoryToken(token="materializer", tenants=("acme",), roles=("materializer",), principal_name="Mat One", token_id="mat-1")},
    )
    ingestor_app_get_status, ingestor_app_get = resolve_history_request(
        "/api/v1/app?tenant=acme",
        history_paths=(),
        tenants=tenants,
        sqlite_path=str(sqlite_path),
        headers={"Authorization": "Bearer ingestor"},
        scoped_tokens={"ingestor": HistoryToken(token="ingestor", tenants=("acme",), roles=("ingestor",), principal_name="Ing One", token_id="ing-1")},
    )

    assert reader_app_post_status == 403
    assert reader_app_post["data"]["error"] == "insufficient_role"
    assert materializer_admin_status == 403
    assert materializer_admin["data"]["error"] == "insufficient_role"
    assert ingestor_app_get_status == 403
    assert ingestor_app_get["data"]["error"] == "insufficient_role"


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


def test_decision_history_service_accepts_jwt_identity_for_versioned_api(tmp_path) -> None:
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
    jwt_token = _build_test_jwt(
        secret="super-secret",
        payload={
            "iss": "https://issuer.example",
            "aud": "veridion-history",
            "sub": "svc-acme",
            "jti": "jwt-1",
            "roles": ["reader"],
            "tenants": ["acme"],
        },
    )

    status, payload = resolve_history_request(
        "/api/v1/analytics?tenant=acme",
        history_paths=(),
        tenants=tenants,
        headers={"Authorization": f"Bearer {jwt_token}"},
        jwt_config=JWTAuthConfig(
            issuer="https://issuer.example",
            audience="veridion-history",
            shared_secret="super-secret",
        ),
    )

    assert status == 200
    assert payload["identity"]["auth_type"] == "jwt"
    assert payload["identity"]["token_id"] == "jwt-1"
    assert payload["data"]["summary"]["events"] == 1


def test_decision_history_service_requires_auth_when_jwks_is_configured(tmp_path) -> None:
    history_path = tmp_path / "history.ndjson"
    jwks_path = tmp_path / "jwks.json"
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
    jwks_path.write_text(json.dumps({"keys": []}))
    tenants = {"acme": HistoryTenant(tenant_id="acme", history_paths=(str(history_path),))}

    status, payload = resolve_history_request(
        "/api/v1/analytics?tenant=acme",
        history_paths=(),
        tenants=tenants,
        headers={},
        jwt_config=JWTAuthConfig(jwks_path=str(jwks_path)),
    )

    assert status == 401
    assert payload["data"]["error"] == "unauthorized"


def test_decision_history_service_accepts_trusted_header_identity(tmp_path) -> None:
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
        headers={
            "X-Veridion-Auth-Secret": "secret",
            "X-Veridion-Principal": "alice@example.com",
            "X-Veridion-Token-Id": "tok_hdr",
            "X-Veridion-Roles": "reader",
            "X-Veridion-Tenants": "acme",
        },
        trusted_header_auth=TrustedHeaderAuthConfig(enabled=True, shared_secret="secret"),
    )

    assert status == 200
    assert payload["identity"]["auth_type"] == "trusted_header"
    assert payload["identity"]["principal_name"] == "alice@example.com"


def test_decision_history_service_bootstraps_browser_session_from_trusted_headers(tmp_path) -> None:
    sqlite_path = tmp_path / "history.db"
    resolve_history_request(
        "/api/v1/admin/tenants",
        method="POST",
        body=json.dumps({"tenant_id": "acme", "display_name": "Acme", "organization_name": "Acme Org"}),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": "Bearer admin"},
        scoped_tokens={"admin": HistoryToken(token="admin", tenants=("acme",), roles=("admin",), principal_name="Admin One", token_id="admin-1")},
    )

    status, payload = resolve_history_request(
        "/api/v1/app?tenant=acme",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={
            "X-Veridion-Auth-Secret": "secret",
            "X-Veridion-Principal": "alice@example.com",
            "X-Veridion-Token-Id": "tok_hdr",
            "X-Veridion-Roles": "reader",
            "X-Veridion-Tenants": "acme",
        },
        trusted_header_auth=TrustedHeaderAuthConfig(enabled=True, shared_secret="secret"),
    )
    cookie_header = str(payload.get("__headers", {}).get("Set-Cookie", ""))
    replay_status, replay_payload = resolve_history_request(
        "/api/v1/app?tenant=acme",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Cookie": cookie_header},
        trusted_header_auth=TrustedHeaderAuthConfig(enabled=True, shared_secret="secret"),
    )

    audit_actions = {str(item.get("action", "")) for item in list_control_plane_audit(sqlite_path=str(sqlite_path), tenant_id="acme")}

    assert status == 200
    assert "Onboarding Checklist" in payload["html"]
    assert "trusted-header-browser-session" in payload["html"]
    assert replay_status == 200
    assert "Onboarding Checklist" in replay_payload["html"]
    assert "veridion_app_bearer=" in cookie_header or "veridion_app_session_id=" in cookie_header
    assert "browser_session_bootstrapped" in audit_actions


def test_decision_history_service_bootstraps_browser_session_from_jwt(tmp_path) -> None:
    sqlite_path = tmp_path / "history.db"
    resolve_history_request(
        "/api/v1/admin/tenants",
        method="POST",
        body=json.dumps({"tenant_id": "acme", "display_name": "Acme", "organization_name": "Acme Org"}),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": "Bearer admin"},
        scoped_tokens={"admin": HistoryToken(token="admin", tenants=("acme",), roles=("admin",), principal_name="Admin One", token_id="admin-1")},
    )
    jwt_token = _build_test_jwt(
        secret="super-secret",
        payload={
            "iss": "https://issuer.example",
            "aud": "veridion-history",
            "sub": "svc-acme",
            "jti": "jwt-1",
            "roles": ["reader"],
            "tenants": ["acme"],
            "principal_name": "JWT Operator",
        },
    )

    status, payload = resolve_history_request(
        "/api/v1/app?tenant=acme",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": f"Bearer {jwt_token}"},
        jwt_config=JWTAuthConfig(
            issuer="https://issuer.example",
            audience="veridion-history",
            shared_secret="super-secret",
        ),
    )

    assert status == 200
    assert "Onboarding Checklist" in payload["html"]
    assert "jwt-browser-session" in payload["html"]
    assert "veridion_app_bearer=" in str(payload.get("__headers", {}).get("Set-Cookie", ""))


def test_decision_history_service_exposes_overview_and_identity_endpoints(tmp_path) -> None:
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
    config_path.write_text(json.dumps({"sqlite_path": str(sqlite_path), "materialization_root": str(materialization_root), "tenants": [{"tenant_id": "acme", "history_paths": []}]}))
    tenants = {"acme": HistoryTenant(tenant_id="acme", history_paths=())}

    overview_status, overview = resolve_history_request(
        "/api/v1/overview?tenant=acme",
        history_paths=(),
        tenants=tenants,
        sqlite_path=str(sqlite_path),
        materialization_root=str(materialization_root),
        config_path=str(config_path),
        headers={"Authorization": "Bearer reader"},
        scoped_tokens={"reader": HistoryToken(token="reader", tenants=("acme",), roles=("reader",), principal_name="Reader One", token_id="reader-1")},
    )
    identity_status, identity = resolve_history_request(
        "/api/v1/identity",
        history_paths=(),
        tenants=tenants,
        sqlite_path=str(sqlite_path),
        headers={"Authorization": "Bearer reader"},
        scoped_tokens={"reader": HistoryToken(token="reader", tenants=("acme",), roles=("reader",), principal_name="Reader One", token_id="reader-1")},
    )

    assert overview_status == 200
    assert overview["data"]["analytics"]["summary"]["events"] == 1
    assert overview["data"]["status"]["store"]["backend"] == "sqlite"
    assert overview["data"]["catalog"]["services"][0]["service_id"] == "service-a"
    assert identity_status == 200
    assert identity["data"]["identity"]["principal_name"] == "Reader One"


def test_decision_history_service_ingests_events_and_exposes_catalog(tmp_path) -> None:
    sqlite_path = tmp_path / "history.db"
    tenants = {"acme": HistoryTenant(tenant_id="acme", history_paths=())}
    event = {
        "generated_at": "2026-05-14T12:00:00Z",
        "repository": "acme/service-a",
        "organization": "acme",
        "project": "acme/service-a",
        "service": "service-a",
        "decision": {"verdict": "GO", "gate_status": "pass", "blocking_categories": []},
        "automation": {"approval_gate_status": "satisfied", "stale_approvals": []},
        "policy": {"pack_id": "app", "pack_version": "1", "rollout_stage": "general"},
        "trust_context": {"service_owner": "payments-owner", "owning_team": "payments", "service_criticality": "high"},
    }

    ingest_status, ingest = resolve_history_request(
        "/api/v1/events",
        method="POST",
        body=json.dumps({"tenant": "acme", "event": event}),
        history_paths=(),
        tenants=tenants,
        sqlite_path=str(sqlite_path),
        headers={"Authorization": "Bearer ingestor"},
        scoped_tokens={"ingestor": HistoryToken(token="ingestor", tenants=("acme",), roles=("ingestor",))},
    )
    services_status, services = resolve_history_request(
        "/api/v1/services?tenant=acme",
        history_paths=(),
        tenants=tenants,
        sqlite_path=str(sqlite_path),
        headers={"Authorization": "Bearer reader"},
        scoped_tokens={"reader": HistoryToken(token="reader", tenants=("acme",), roles=("reader",))},
    )

    assert ingest_status == 202
    assert ingest["data"]["repository"] == "acme/service-a"
    assert services_status == 200
    assert services["data"]["services"][0]["service_id"] == "service-a"


def test_decision_history_service_admin_and_session_surfaces(tmp_path) -> None:
    sqlite_path = tmp_path / "history.db"
    admin = {"Authorization": "Bearer admin"}
    scoped = {"admin": HistoryToken(token="admin", tenants=("acme",), roles=("admin",), principal_name="Admin One", token_id="admin-1")}

    create_tenant_status, _ = resolve_history_request(
        "/api/v1/admin/tenants",
        method="POST",
        body=json.dumps({"tenant_id": "acme", "display_name": "Acme", "organization_name": "Acme Org"}),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers=admin,
        scoped_tokens=scoped,
    )
    create_user_status, _ = resolve_history_request(
        "/api/v1/admin/users",
        method="POST",
        body=json.dumps({"tenant": "acme", "user_id": "alice", "principal_name": "Alice", "roles_csv": "reader,admin"}),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers=admin,
        scoped_tokens=scoped,
    )
    create_secret_status, _ = resolve_history_request(
        "/api/v1/admin/provider-secrets",
        method="POST",
        body=json.dumps({"tenant": "acme", "secret_name": "pagerduty-token", "provider": "pagerduty", "secret_ref": "aws-sm://pagerduty/acme"}),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers=admin,
        scoped_tokens=scoped,
    )
    create_client_status, create_client = resolve_history_request(
        "/api/v1/admin/producer-clients",
        method="POST",
        body=json.dumps({"tenant": "acme", "client_id": "ci-acme", "display_name": "CI Acme"}),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers=admin,
        scoped_tokens=scoped,
    )
    producer_token = create_client["data"]["producer_client"]["token"]
    ingest_status, ingest = resolve_history_request(
        "/api/v1/events",
        method="POST",
        body=json.dumps(
            {
                "tenant": "acme",
                "event": {
                    "generated_at": "2026-05-14T12:00:00Z",
                    "repository": "acme/service-a",
                    "organization": "acme",
                    "project": "acme/service-a",
                    "service": "service-a",
                    "decision": {"verdict": "GO", "gate_status": "pass", "blocking_categories": []},
                    "automation": {"approval_gate_status": "satisfied", "stale_approvals": []},
                    "policy": {"pack_id": "app", "pack_version": "1", "rollout_stage": "general"},
                    "trust_context": {"service_owner": "payments-owner", "owning_team": "payments", "service_criticality": "high"},
                },
            }
        ),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": f"Bearer {producer_token}"},
        scoped_tokens={},
    )
    session_status, session = resolve_history_request(
        "/api/v1/auth/sessions",
        method="POST",
        body=json.dumps({"tenant": "acme", "session_id": "sess-1"}),
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers=admin,
        scoped_tokens=scoped,
    )
    app_status, app = resolve_history_request(
        "/api/v1/app?tenant=acme",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers=admin,
        scoped_tokens=scoped,
    )
    connected_status, connected = resolve_history_request(
        "/api/v1/app",
        method="POST",
        body="action=connect_repository&tenant_id=acme&repository=acme%2Fservice-a&service=service-a&organization=acme&project_id=acme%2Fservice-a&service_owner=payments-owner&owning_team=payments&service_criticality=high&producer_client=ci-acme",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": "Bearer admin", "Content-Type": "application/x-www-form-urlencoded"},
        scoped_tokens=scoped,
    )

    assert create_tenant_status == 201
    assert create_user_status == 201
    assert create_secret_status == 201
    assert create_client_status == 201
    assert create_client["data"]["producer_client"]["token"]
    assert ingest_status == 202
    assert ingest["data"]["repository"] == "acme/service-a"
    assert session_status == 201
    assert session["data"]["session_id"] == "sess-1"
    assert app_status == 200
    assert connected_status == 200
    assert "Managed Tenants" in app["html"]
    assert "Repository Drilldown" in app["html"]
    assert "Producer Token Controls" in app["html"]
    assert "Second Tenant Playbook" in app["html"]
    assert "Connect First Repo" in app["html"]
    assert "Auth Hardening" in app["html"]
    assert "Operator Observability" in app["html"]
    assert "Provision Second Tenant" in app["html"]
    assert "Role Model" in app["html"]
    assert "Recovery Playbooks" in app["html"]
    assert "Control Plane Audit" in app["html"]
    assert "First hosted decision received." in connected["html"]
    assert "Recover With Fresh Token" in connected["html"]
    assert "Open repository page" in connected["html"]


def test_decision_history_service_app_forms_support_onboarding_actions(tmp_path) -> None:
    sqlite_path = tmp_path / "history.db"
    admin = {"Authorization": "Bearer admin", "Content-Type": "application/x-www-form-urlencoded"}
    scoped = {"admin": HistoryToken(token="admin", tenants=("acme",), roles=("admin",), principal_name="Admin One", token_id="admin-1")}

    create_tenant_status, tenant_app = resolve_history_request(
        "/api/v1/app",
        method="POST",
        body="action=create_tenant&tenant_id=acme&display_name=Acme+Production&organization_name=Acme&status=active",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers=admin,
        scoped_tokens=scoped,
    )
    producer_status, producer_app = resolve_history_request(
        "/api/v1/app",
        method="POST",
        body="action=create_producer_client&tenant_id=acme&client_id=github-actions&display_name=GitHub+Actions&roles_csv=ingestor&status=active",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers=admin,
        scoped_tokens=scoped,
    )
    user_status, user_app = resolve_history_request(
        "/api/v1/app",
        method="POST",
        body="action=create_service_user&tenant_id=acme&user_id=alice&principal_name=Alice+Doe&email=alice%40example.com&roles_csv=reader%2Cadmin&status=active",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers=admin,
        scoped_tokens=scoped,
    )
    secret_status, secret_app = resolve_history_request(
        "/api/v1/app",
        method="POST",
        body="action=create_provider_secret&tenant_id=acme&provider=pagerduty&secret_name=pagerduty-token&secret_ref=aws-secretsmanager%3A%2F%2Fveridion%2Facme%2Fpagerduty&description=PagerDuty+API+token",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers=admin,
        scoped_tokens=scoped,
    )
    rotate_status, rotate_app = resolve_history_request(
        "/api/v1/app",
        method="POST",
        body="action=rotate_producer_client&tenant_id=acme&client_id=github-actions",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers=admin,
        scoped_tokens=scoped,
    )
    revoke_status, revoke_app = resolve_history_request(
        "/api/v1/app",
        method="POST",
        body="action=revoke_producer_client&tenant_id=acme&client_id=github-actions",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers=admin,
        scoped_tokens=scoped,
    )
    connect_status, connect_app = resolve_history_request(
        "/api/v1/app",
        method="POST",
        body="action=connect_repository&tenant_id=acme&repository=acme%2Fservice-a&service=service-a&organization=acme&project_id=acme%2Fservice-a&service_owner=payments-owner&owning_team=payments&service_criticality=high&producer_client=github-actions",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers=admin,
        scoped_tokens=scoped,
    )
    clients_status, clients = resolve_history_request(
        "/api/v1/admin/producer-clients?tenant=acme",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": "Bearer admin"},
        scoped_tokens=scoped,
    )
    repo_page_status, repo_page = resolve_history_request(
        "/api/v1/app/repository?tenant=acme&repository=acme/service-a",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": "Bearer admin"},
        scoped_tokens=scoped,
    )
    service_page_status, service_page = resolve_history_request(
        "/api/v1/app/service?tenant=acme&service=service-a",
        history_paths=(),
        sqlite_path=str(sqlite_path),
        headers={"Authorization": "Bearer admin"},
        scoped_tokens=scoped,
    )

    assert create_tenant_status == 200
    assert "Tenant acme provisioned." in tenant_app["html"]
    assert producer_status == 200
    assert "Producer client github-actions created." in producer_app["html"]
    assert "Producer token issued once." in producer_app["html"]
    assert rotate_status == 200
    assert "Producer client github-actions rotated." in rotate_app["html"]
    assert "Producer token issued once." in rotate_app["html"]
    assert revoke_status == 200
    assert "Producer client github-actions revoked." in revoke_app["html"]
    assert user_status == 200
    assert "Service user alice created." in user_app["html"]
    assert secret_status == 200
    assert connect_status == 200
    assert "Provider secret reference pagerduty-token stored." in secret_app["html"]
    assert "Add Producer Client" in secret_app["html"]
    assert "Add Service User" in secret_app["html"]
    assert "Rotate Token" in secret_app["html"]
    assert "Second Tenant Playbook" in secret_app["html"]
    assert "Generate Repo Plan" in connect_app["html"]
    assert "Producer github-actions is revoked" in connect_app["html"]
    assert "Recover With Fresh Token" in connect_app["html"]
    assert "VERIDION_HOSTED_INGESTOR_TOKEN" in connect_app["html"]
    assert "Operator Observability" in connect_app["html"]
    assert "Provision Second Tenant" in connect_app["html"]
    assert "Troubleshoot Missing Events" in connect_app["html"]
    assert "Rotate the producer to reveal a fresh token" in connect_app["html"]
    assert "Auth Recovery" in connect_app["html"]
    assert "Role Model" in connect_app["html"]
    assert clients_status == 200
    assert clients["data"]["producer_clients"][0]["status"] == "revoked"
    assert clients["data"]["producer_clients"][0]["last_issued_at"]
    assert repo_page_status == 200
    assert "Dedicated repository page" in repo_page["data"]["html"]
    assert "History Summary" in repo_page["data"]["html"]
    assert "Decision Guidance" in repo_page["data"]["html"]
    assert "Recent Decisions" in repo_page["data"]["html"]
    assert "Next action" in repo_page["data"]["html"]
    assert service_page_status == 200
    assert "Dedicated service page" in service_page["data"]["html"]
    assert "Decision Guidance" in service_page["data"]["html"]
    assert "Recent Decisions" in service_page["data"]["html"]


def _build_test_jwt(*, secret: str, payload: dict[str, object]) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64(header)
    payload_b64 = _b64(payload)
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("=")
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def _b64(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(encoded).decode("utf-8").rstrip("=")
