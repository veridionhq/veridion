import json

from veridion.action.decision_history_config import load_history_service_config, schedule_map, tenant_map


def test_load_history_service_config_reads_tenants_and_tokens(tmp_path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "service_name": "Veridion Control Plane",
                "auth_tokens": ["global-token"],
                "sqlite_path": "/tmp/history.db",
                "tokens": [
                    {
                        "token": "tenant-token",
                        "token_id": "tok_123",
                        "principal_name": "acme-reader",
                        "auth_type": "bearer",
                        "status": "active",
                        "tenants": ["acme"],
                        "roles": ["reader"],
                    }
                ],
                "jwt": {
                    "issuer": "https://issuer.example",
                    "audience": "veridion-history",
                    "shared_secret": "super-secret",
                },
                "schedules": [
                    {
                        "schedule_id": "nightly",
                        "cron": "0 3 * * *",
                        "tenants": ["acme"],
                        "athena_database": "analytics",
                    }
                ],
                "tenants": [
                    {
                        "tenant_id": "acme",
                        "display_name": "Acme Production",
                        "history_paths": ["/tmp/acme"],
                        "auth_tokens": ["acme-token"],
                    }
                ],
            }
        )
    )

    config = load_history_service_config(config_path)

    assert config.service_name == "Veridion Control Plane"
    assert config.auth_tokens == ("global-token",)
    assert config.sqlite_path == "/tmp/history.db"
    assert config.tenants[0].tenant_id == "acme"
    assert config.tenants[0].display_name == "Acme Production"
    assert tenant_map(config)["acme"].auth_tokens == ("acme-token",)
    assert config.tokens[0].token_id == "tok_123"
    assert config.tokens[0].principal_name == "acme-reader"
    assert config.tokens[0].tenants == ("acme",)
    assert config.jwt.issuer == "https://issuer.example"
    assert schedule_map(config)["nightly"].athena_database == "analytics"
