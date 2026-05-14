from veridion.policy import parse_policy_pack_yaml


def test_parse_policy_pack_yaml_extracts_metadata_and_config() -> None:
    pack = parse_policy_pack_yaml(
        """
policy_pack_id: regulated-service
policy_pack_name: Regulated Service
policy_pack_version: 2026.05
policy_pack_owner: platform-trust
policy_rollout_stage: pilot
max_severity: critical
allow_conditional: true
no_go_below_score: 60
conditional_go_below_score: 85
"""
    )

    assert pack.metadata.pack_id == "regulated-service"
    assert pack.metadata.display_name == "Regulated Service"
    assert pack.metadata.version == "2026.05"
    assert pack.metadata.owner == "platform-trust"
    assert pack.metadata.rollout_stage == "pilot"
    assert pack.config.max_severity == "critical"
    assert pack.config.no_go_below_score == 60
