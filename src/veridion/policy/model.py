"""Policy configuration and lightweight YAML parsing."""

from __future__ import annotations

from dataclasses import dataclass

from veridion.normalize.common import SEVERITY_ORDER, as_string, normalize_severity
from veridion.policy.labels import VALID_POLICY_TRIGGERS


@dataclass(frozen=True)
class PolicyConfig:
    """Configurable release policy for decision evaluation."""

    # Semantics: "high" means block high and critical findings, not allow high.
    max_severity: str = "critical"
    allow_conditional: bool = True
    no_go_below_score: int = 60
    conditional_go_below_score: int = 85
    require_approval_for: tuple[str, ...] = ()
    # Valid values: repo_criticality_high, service_criticality_high.
    require_service_owner_for: tuple[str, ...] = ()
    # Valid values: historical_instability, flaky_service.
    require_sre_owner_for: tuple[str, ...] = ()
    # Valid values: sensitive_repo.
    require_security_owner_for: tuple[str, ...] = ()


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
        require_approval_for=tuple(as_string(item, default="") for item in approval_values if as_string(item)),
        require_service_owner_for=_string_list(parsed.get("require_service_owner_for"), "require_service_owner_for"),
        require_sre_owner_for=_string_list(parsed.get("require_sre_owner_for"), "require_sre_owner_for"),
        require_security_owner_for=_string_list(parsed.get("require_security_owner_for"), "require_security_owner_for"),
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
