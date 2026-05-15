"""Versioned policy-pack parsing helpers."""

from __future__ import annotations

from dataclasses import dataclass

from veridion.policy.model import PolicyConfig, _policy_from_mapping


@dataclass(frozen=True)
class PolicyPackMetadata:
    """Metadata describing a policy pack as a product surface."""

    pack_id: str = ""
    display_name: str = ""
    version: str = ""
    owner: str = ""
    rollout_stage: str = ""


@dataclass(frozen=True)
class PolicyPack:
    """Policy config paired with product-facing pack metadata."""

    metadata: PolicyPackMetadata
    config: PolicyConfig


def parse_policy_pack_yaml(text: str) -> PolicyPack:
    """Parse policy-pack metadata and policy config from YAML."""

    parsed = _parse_yaml_mapping(text)
    metadata = PolicyPackMetadata(
        pack_id=_as_string(parsed.get("policy_pack_id")),
        display_name=_as_string(parsed.get("policy_pack_name")),
        version=_as_string(parsed.get("policy_pack_version")),
        owner=_as_string(parsed.get("policy_pack_owner")),
        rollout_stage=_as_string(parsed.get("policy_rollout_stage")),
    )
    return PolicyPack(metadata=metadata, config=_policy_from_mapping(parsed))


def _parse_yaml_mapping(text: str) -> dict[str, object]:
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

    return parsed


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


def _as_string(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""
