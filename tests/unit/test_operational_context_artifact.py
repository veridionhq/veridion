import pytest

from veridion.context import (
    SUPPORTED_OPERATIONAL_CONTEXT_SCHEMA_VERSION,
    build_operational_context_artifact,
    extract_operational_context_sections,
    validate_operational_context_payload,
)


def test_build_operational_context_artifact_merges_metadata_and_trust_profile() -> None:
    artifact = build_operational_context_artifact(
        metadata_payload={
            "title": "feat: ship change",
            "runtime": {"rollout_strategy": "direct"},
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
        source="github-test",
        generated_at="2026-05-10T00:00:00Z",
    )

    assert artifact == {
        "schema_version": SUPPORTED_OPERATIONAL_CONTEXT_SCHEMA_VERSION,
        "provenance": {
            "source": "github-test",
            "generated_at": "2026-05-10T00:00:00Z",
        },
        "metadata": {
            "title": "feat: ship change",
            "runtime": {"rollout_strategy": "direct"},
        },
        "historical": {"repo_criticality": "high"},
        "runtime": {"environment": "production", "rollout_strategy": "direct"},
        "ownership": {"owning_team": "payments-platform"},
        "trust_baseline": {"repo_stability": "fragile"},
        "trust_profile_metadata": {
            "schema_version": 1,
            "repo_id": "veridionhq/veridion",
            "service_id": "veridion/rdi-engine",
            "team_id": "platform-trust",
            "source": "fixture",
            "generated_at": "2026-05-08T00:00:00Z",
            "precedence": "trust_profile_artifact",
        },
    }


def test_validate_operational_context_payload_rejects_bad_shape() -> None:
    with pytest.raises(RuntimeError, match=r"operational context schema_version must be 1"):
        validate_operational_context_payload({"schema_version": 2})

    with pytest.raises(RuntimeError, match=r"operational context runtime must be an object when provided"):
        validate_operational_context_payload({"schema_version": 1, "runtime": []})


def test_extract_operational_context_sections_returns_plain_objects() -> None:
    sections = extract_operational_context_sections(
        {
            "schema_version": 1,
            "metadata": {"title": "ok"},
            "historical": {"repo_criticality": "high"},
            "runtime": {"environment": "production"},
            "ownership": {"owning_team": "platform"},
            "trust_baseline": {"repo_stability": "fragile"},
            "trust_profile_metadata": {"repo_id": "veridionhq/veridion"},
        }
    )

    assert sections == {
        "metadata": {"title": "ok"},
        "historical": {"repo_criticality": "high"},
        "runtime": {"environment": "production"},
        "ownership": {"owning_team": "platform"},
        "trust_baseline": {"repo_stability": "fragile"},
        "trust_profile_metadata": {"repo_id": "veridionhq/veridion"},
    }
