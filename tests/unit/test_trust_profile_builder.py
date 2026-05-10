import pytest

from veridion.action.trust_profile_builder import (
    DEFAULT_REPO_TRUST_SOURCE_PATH,
    DEFAULT_SERVICE_CATALOG_EXPORT_PATH,
    DEFAULT_TRUST_CATALOG_SOURCE_PATH,
    build_trust_profile,
    merge_trust_profile_sources,
    resolve_trust_profile_paths,
)


def test_build_trust_profile_emits_versioned_artifact() -> None:
    artifact = build_trust_profile(
        {
            "scope": {
                "repo_id": "veridionhq/veridion",
                "service_id": "veridion/rdi-engine",
                "team_id": "platform-trust",
            },
            "provenance": {
                "source": "fixture-source",
            },
            "historical": {"repo_criticality": "high"},
            "runtime": {"environment": "production"},
            "ownership": {"service_owner": "payments-owner"},
            "trust_baseline": {"repo_stability": "fragile"},
        },
        generated_at="2026-05-08T00:00:00Z",
    )

    assert artifact == {
        "schema_version": 1,
        "scope": {
            "repo_id": "veridionhq/veridion",
            "service_id": "veridion/rdi-engine",
            "team_id": "platform-trust",
        },
        "provenance": {
            "source": "fixture-source",
            "generated_at": "2026-05-08T00:00:00Z",
        },
        "historical": {"repo_criticality": "high"},
        "runtime": {"environment": "production"},
        "ownership": {"service_owner": "payments-owner"},
        "trust_baseline": {"repo_stability": "fragile"},
    }


def test_build_trust_profile_allows_source_override() -> None:
    artifact = build_trust_profile(
        {
            "provenance": {"source": "fixture-source"},
        },
        source_name="catalog-sync",
        generated_at="2026-05-08T00:00:00Z",
    )

    assert artifact["provenance"] == {
        "source": "catalog-sync",
        "generated_at": "2026-05-08T00:00:00Z",
    }


def test_merge_trust_profile_sources_allows_repo_overrides() -> None:
    merged = merge_trust_profile_sources(
        {
            "scope": {"team_id": "platform-trust"},
            "runtime": {"environment": "production", "rollout_strategy": "rolling"},
            "ownership": {"review_coverage": "cross_team"},
        },
        {
            "scope": {"repo_id": "veridionhq/veridion"},
            "runtime": {"rollout_strategy": "canary"},
            "ownership": {"service_owner": "payments-owner"},
        },
    )

    assert merged == {
        "scope": {
            "team_id": "platform-trust",
            "repo_id": "veridionhq/veridion",
        },
        "provenance": {},
        "historical": {},
        "runtime": {
            "environment": "production",
            "rollout_strategy": "canary",
        },
        "ownership": {
            "review_coverage": "cross_team",
            "service_owner": "payments-owner",
        },
        "trust_baseline": {},
    }


def test_resolve_trust_profile_paths_uses_explicit_values() -> None:
    assert resolve_trust_profile_paths(
        config_path="repo.json",
        catalog_path="catalog.json",
        service_catalog_path="service-catalog.json",
    ) == ("repo.json", "catalog.json", "service-catalog.json")


def test_resolve_trust_profile_paths_uses_default_conventions(monkeypatch: pytest.MonkeyPatch) -> None:
    existing = {
        DEFAULT_REPO_TRUST_SOURCE_PATH,
        DEFAULT_TRUST_CATALOG_SOURCE_PATH,
        DEFAULT_SERVICE_CATALOG_EXPORT_PATH,
    }

    monkeypatch.setattr(
        "veridion.action.trust_profile_builder.Path.exists",
        lambda self: str(self) in existing,
    )

    assert resolve_trust_profile_paths() == (
        DEFAULT_REPO_TRUST_SOURCE_PATH,
        DEFAULT_TRUST_CATALOG_SOURCE_PATH,
        DEFAULT_SERVICE_CATALOG_EXPORT_PATH,
    )


def test_resolve_trust_profile_paths_requires_repo_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("veridion.action.trust_profile_builder.Path.exists", lambda self: False)

    with pytest.raises(RuntimeError, match=r"no trust profile source found"):
        resolve_trust_profile_paths()
