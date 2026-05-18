"""Configuration helpers for multi-tenant decision-history services."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class HistoryTenant:
    tenant_id: str
    history_paths: tuple[str, ...]
    auth_tokens: tuple[str, ...] = ()


@dataclass(frozen=True)
class HistoryToken:
    token: str
    tenants: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()


@dataclass(frozen=True)
class HistoryServiceConfig:
    tenants: tuple[HistoryTenant, ...]
    sqlite_path: str = ""
    auth_tokens: tuple[str, ...] = ()
    tokens: tuple[HistoryToken, ...] = ()


def load_history_service_config(path: str | Path) -> HistoryServiceConfig:
    payload = json.loads(Path(path).read_text())
    if not isinstance(payload, dict):
        raise RuntimeError("history service config must be a JSON object")

    tenants_payload = payload.get("tenants")
    if not isinstance(tenants_payload, list) or not tenants_payload:
        raise RuntimeError("history service config must contain a non-empty tenants array")
    sqlite_path = _optional_string(payload.get("sqlite_path"))

    tenants: list[HistoryTenant] = []
    for item in tenants_payload:
        if not isinstance(item, dict):
            raise RuntimeError("history service config tenants must be objects")
        tenant_id = _required_string(item, "tenant_id")
        history_paths = _string_list(item.get("history_paths"))
        if not history_paths and not sqlite_path:
            raise RuntimeError(f"tenant {tenant_id} must define one or more history_paths")
        tenants.append(
            HistoryTenant(
                tenant_id=tenant_id,
                history_paths=tuple(history_paths),
                auth_tokens=tuple(_string_list(item.get("auth_tokens"))),
            )
        )

    return HistoryServiceConfig(
        tenants=tuple(tenants),
        sqlite_path=sqlite_path,
        auth_tokens=tuple(_string_list(payload.get("auth_tokens"))),
        tokens=tuple(_parse_tokens(payload.get("tokens"))),
    )


def tenant_map(config: HistoryServiceConfig) -> dict[str, HistoryTenant]:
    return {tenant.tenant_id: tenant for tenant in config.tenants}


def token_map(config: HistoryServiceConfig) -> dict[str, HistoryToken]:
    return {token.token: token for token in config.tokens}


def _required_string(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"history service config requires non-empty {key}")
    return value.strip()


def _optional_string(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _parse_tokens(value: object) -> list[HistoryToken]:
    if not isinstance(value, list):
        return []
    tokens: list[HistoryToken] = []
    for item in value:
        if not isinstance(item, dict):
            raise RuntimeError("history service config tokens must be objects")
        tokens.append(
            HistoryToken(
                token=_required_string(item, "token"),
                tenants=tuple(_string_list(item.get("tenants"))),
                roles=tuple(_string_list(item.get("roles"))),
            )
        )
    return tokens
