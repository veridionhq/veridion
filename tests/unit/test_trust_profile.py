import pytest

from veridion.action.trust_profile import merge_metadata_with_trust_profile


def test_merge_metadata_with_trust_profile_preserves_pr_fields_and_overrides_context() -> None:
    merged = merge_metadata_with_trust_profile(
        metadata_payload={
            "title": "feat: ship change",
            "body": "Prepared with Cursor.",
            "runtime": {"rollout_strategy": "direct"},
            "ownership": {"service_owner": "payments-owner"},
        },
        trust_profile_payload={
            "schema_version": 1,
            "scope": {
                "repo_id": "veridionhq/veridion",
                "service_id": "veridion/rdi-engine",
                "team_id": "platform-trust",
            },
            "provenance": {
                "source": "fixture",
                "generated_at": "2026-05-08T00:00:00Z",
            },
            "historical": {"repo_criticality": "high"},
            "runtime": {"environment": "production", "rollout_strategy": "canary"},
            "ownership": {"owning_team": "payments-platform"},
            "trust_baseline": {"repo_stability": "fragile"},
        },
    )

    assert merged == {
        "title": "feat: ship change",
        "body": "Prepared with Cursor.",
        "trust_profile_metadata": {
            "schema_version": 1,
            "repo_id": "veridionhq/veridion",
            "service_id": "veridion/rdi-engine",
            "team_id": "platform-trust",
            "source": "fixture",
            "generated_at": "2026-05-08T00:00:00Z",
            "precedence": "trust_profile_artifact",
        },
        "historical": {"repo_criticality": "high"},
        "runtime": {"environment": "production", "rollout_strategy": "direct"},
        "ownership": {
            "owning_team": "payments-platform",
            "service_owner": "payments-owner",
        },
        "trust_baseline": {"repo_stability": "fragile"},
    }


def test_merge_metadata_with_trust_profile_rejects_unsupported_schema_version() -> None:
    with pytest.raises(RuntimeError, match=r"trust profile schema_version must be 1"):
        merge_metadata_with_trust_profile(
            metadata_payload={},
            trust_profile_payload={"schema_version": 2},
        )
