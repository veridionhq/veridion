"""Policy configuration and lightweight YAML parsing."""

from __future__ import annotations

from dataclasses import dataclass

from veridion.normalize.common import SEVERITY_ORDER, as_string, normalize_severity
from veridion.policy.labels import VALID_POLICY_TRIGGERS, VALID_REQUIRE_APPROVAL_FOR


@dataclass(frozen=True)
class PolicyConfig:
    """Configurable release policy for decision evaluation."""

    # Semantics: "high" means block high and critical findings, not allow high.
    max_severity: str = "critical"
    allow_conditional: bool = True
    no_go_below_score: int = 60
    conditional_go_below_score: int = 85
    require_approval_for: tuple[str, ...] = ()
    # Valid values: production_deployment, public_exposure, large_blast_radius, after_hours_deploy,
    # deployment_freeze_active, active_incident, firing_alerts, degraded_canary_health,
    # runtime_rollback_blocked, repo_fragility, service_fragility, weak_rollback_readiness,
    # shared_platform_surface, database_migration_surface.
    require_platform_owner_for: tuple[str, ...] = ()
    # Valid values: repo_criticality_high, service_criticality_high, repo_fragility, service_fragility,
    # low_test_coverage, low_team_deploy_safety, payments_surface, auth_surface, data_surface.
    require_service_owner_for: tuple[str, ...] = ()
    # Valid values: historical_instability, flaky_service, production_deployment, after_hours_deploy, missing_oncall,
    # deployment_freeze_active, active_incident, firing_alerts, degraded_canary_health,
    # runtime_rollback_blocked, weak_rollback_readiness, service_fragility, low_team_deploy_safety,
    # shared_platform_surface, database_migration_surface, data_surface.
    require_sre_owner_for: tuple[str, ...] = ()
    # Valid values: sensitive_repo, public_exposure, dependency_reputation_risk, payments_surface, auth_surface,
    # data_surface, accepted_risk_present, accepted_risk_governance_gap, active_incident, firing_alerts.
    require_security_owner_for: tuple[str, ...] = ()
    require_complete_accepted_risk_metadata: bool = False
    historical_instability_score_penalty: int = 0
    service_criticality_score_penalty: int = 0
    sensitive_repo_score_penalty: int = 0
    ai_signal_score_penalty: int = 0
    ai_authored_commit_score_penalty: int = 0
    production_deployment_score_penalty: int = 0
    after_hours_deploy_score_penalty: int = 0
    public_exposure_score_penalty: int = 0
    large_blast_radius_score_penalty: int = 0
    low_team_trust_score_penalty: int = 0
    unowned_service_score_penalty: int = 0
    missing_oncall_score_penalty: int = 0
    cross_team_change_score_penalty: int = 0
    repo_fragility_score_penalty: int = 0
    service_fragility_score_penalty: int = 0
    low_test_coverage_score_penalty: int = 0
    weak_rollback_readiness_score_penalty: int = 0
    dependency_reputation_risk_score_penalty: int = 0
    low_team_deploy_safety_score_penalty: int = 0
    shared_platform_surface_score_penalty: int = 0
    database_migration_surface_score_penalty: int = 0
    payments_surface_score_penalty: int = 0
    auth_surface_score_penalty: int = 0
    data_surface_score_penalty: int = 0


def parse_policy_yaml(text: str) -> PolicyConfig:
    """Parse a minimal YAML policy format used by the initial product wedge."""

    parsed: dict[str, object] = {}
    current_list_key: str | None = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("- "):
            if current_list_key is None:
                raise ValueError("list item found before a list key")
            parsed.setdefault(current_list_key, [])
            current_value = parsed[current_list_key]
            if not isinstance(current_value, list):
                raise ValueError(f"policy key '{current_list_key}' is not a list")
            current_value.append(stripped[2:].strip())
            continue

        if ":" not in line:
            raise ValueError(f"invalid policy line: {raw_line}")

        key, raw_value = line.split(":", maxsplit=1)
        key = key.strip()
        value = raw_value.strip()

        if not value:
            parsed[key] = []
            current_list_key = key
            continue

        parsed[key] = _parse_scalar(value)
        current_list_key = None

    return _policy_from_mapping(parsed)


def _policy_from_mapping(parsed: dict[str, object]) -> PolicyConfig:
    max_severity = normalize_severity(as_string(parsed.get("max_severity"), default="critical"))
    if max_severity not in SEVERITY_ORDER:
        raise ValueError(f"unsupported max_severity: {max_severity}")

    approval_values = parsed.get("require_approval_for", [])
    if not isinstance(approval_values, list):
        raise ValueError("require_approval_for must be a list")

    return PolicyConfig(
        max_severity=max_severity,
        allow_conditional=_as_bool(parsed.get("allow_conditional"), default=True),
        no_go_below_score=_as_int(parsed.get("no_go_below_score"), default=60),
        conditional_go_below_score=_as_int(parsed.get("conditional_go_below_score"), default=85),
        require_approval_for=_approval_string_list(approval_values),
        require_platform_owner_for=_string_list(parsed.get("require_platform_owner_for"), "require_platform_owner_for"),
        require_service_owner_for=_string_list(parsed.get("require_service_owner_for"), "require_service_owner_for"),
        require_sre_owner_for=_string_list(parsed.get("require_sre_owner_for"), "require_sre_owner_for"),
        require_security_owner_for=_string_list(parsed.get("require_security_owner_for"), "require_security_owner_for"),
        require_complete_accepted_risk_metadata=_as_bool(
            parsed.get("require_complete_accepted_risk_metadata"),
            default=False,
        ),
        historical_instability_score_penalty=_as_int(parsed.get("historical_instability_score_penalty"), default=0),
        service_criticality_score_penalty=_as_int(parsed.get("service_criticality_score_penalty"), default=0),
        sensitive_repo_score_penalty=_as_int(parsed.get("sensitive_repo_score_penalty"), default=0),
        ai_signal_score_penalty=_as_int(parsed.get("ai_signal_score_penalty"), default=0),
        ai_authored_commit_score_penalty=_as_int(parsed.get("ai_authored_commit_score_penalty"), default=0),
        production_deployment_score_penalty=_as_int(parsed.get("production_deployment_score_penalty"), default=0),
        after_hours_deploy_score_penalty=_as_int(parsed.get("after_hours_deploy_score_penalty"), default=0),
        public_exposure_score_penalty=_as_int(parsed.get("public_exposure_score_penalty"), default=0),
        large_blast_radius_score_penalty=_as_int(parsed.get("large_blast_radius_score_penalty"), default=0),
        low_team_trust_score_penalty=_as_int(parsed.get("low_team_trust_score_penalty"), default=0),
        unowned_service_score_penalty=_as_int(parsed.get("unowned_service_score_penalty"), default=0),
        missing_oncall_score_penalty=_as_int(parsed.get("missing_oncall_score_penalty"), default=0),
        cross_team_change_score_penalty=_as_int(parsed.get("cross_team_change_score_penalty"), default=0),
        repo_fragility_score_penalty=_as_int(parsed.get("repo_fragility_score_penalty"), default=0),
        service_fragility_score_penalty=_as_int(parsed.get("service_fragility_score_penalty"), default=0),
        low_test_coverage_score_penalty=_as_int(parsed.get("low_test_coverage_score_penalty"), default=0),
        weak_rollback_readiness_score_penalty=_as_int(parsed.get("weak_rollback_readiness_score_penalty"), default=0),
        dependency_reputation_risk_score_penalty=_as_int(parsed.get("dependency_reputation_risk_score_penalty"), default=0),
        low_team_deploy_safety_score_penalty=_as_int(parsed.get("low_team_deploy_safety_score_penalty"), default=0),
        shared_platform_surface_score_penalty=_as_int(parsed.get("shared_platform_surface_score_penalty"), default=0),
        database_migration_surface_score_penalty=_as_int(parsed.get("database_migration_surface_score_penalty"), default=0),
        payments_surface_score_penalty=_as_int(parsed.get("payments_surface_score_penalty"), default=0),
        auth_surface_score_penalty=_as_int(parsed.get("auth_surface_score_penalty"), default=0),
        data_surface_score_penalty=_as_int(parsed.get("data_surface_score_penalty"), default=0),
    )


def _string_list(value: object, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a list")
    values = tuple(as_string(item, default="") for item in value if as_string(item))
    invalid = tuple(item for item in values if item not in VALID_POLICY_TRIGGERS)
    if invalid:
        raise ValueError(f"{field_name} contains unsupported trigger(s): {', '.join(invalid)}")
    return values


def _approval_string_list(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError("require_approval_for must be a list")
    values = tuple(as_string(item, default="") for item in value if as_string(item))
    invalid = tuple(item for item in values if item not in VALID_REQUIRE_APPROVAL_FOR)
    if invalid:
        raise ValueError(f"require_approval_for contains unsupported value(s): {', '.join(invalid)}")
    return values


def _parse_scalar(value: str) -> object:
    lowered = value.lower()
    if value == "[]":
        return []
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if value.isdigit():
        return int(value)
    return value


def _as_bool(value: object, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
    raise ValueError(f"expected boolean value, got: {value!r}")


def _as_int(value: object, *, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    raise ValueError(f"expected integer value, got: {value!r}")
