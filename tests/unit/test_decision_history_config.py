import json

from veridion.action.decision_history_config import load_history_service_config, tenant_map


def test_load_history_service_config_reads_tenants_and_tokens(tmp_path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "auth_tokens": ["global-token"],
                "tenants": [
                    {
                        "tenant_id": "acme",
                        "history_paths": ["/tmp/acme"],
                        "auth_tokens": ["acme-token"],
                    }
                ],
            }
        )
    )

    config = load_history_service_config(config_path)

    assert config.auth_tokens == ("global-token",)
    assert config.tenants[0].tenant_id == "acme"
    assert tenant_map(config)["acme"].auth_tokens == ("acme-token",)
