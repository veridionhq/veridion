"""Configuration helpers for multi-tenant decision-history services."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class HistoryTenant:
    tenant_id: str
    history_paths: tuple[str, ...]
    display_name: str = ""
    auth_tokens: tuple[str, ...] = ()


@dataclass(frozen=True)
class MaterializationSchedule:
    schedule_id: str
    cron: str
    tenants: tuple[str, ...] = ()
    enabled: bool = True
    athena_database: str = ""
    athena_table: str = "veridion_decision_events"
    athena_s3_location_template: str = ""


@dataclass(frozen=True)
class JWTAuthConfig:
    issuer: str = ""
    audience: str = ""
    shared_secret: str = ""
    roles_claim: str = "roles"
    tenants_claim: str = "tenants"
    principal_claim: str = "sub"


@dataclass(frozen=True)
class TrustedHeaderAuthConfig:
    enabled: bool = False
    shared_secret: str = ""
    secret_header: str = "X-Veridion-Auth-Secret"
    principal_header: str = "X-Veridion-Principal"
    token_id_header: str = "X-Veridion-Token-Id"
    roles_header: str = "X-Veridion-Roles"
    tenants_header: str = "X-Veridion-Tenants"
    status_header: str = "X-Veridion-Status"


@dataclass(frozen=True)
class HistoryToken:
    token: str
    token_id: str = ""
    principal_name: str = ""
    auth_type: str = "bearer"
    status: str = "active"
    tenants: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()


@dataclass(frozen=True)
class HistoryServiceConfig:
    tenants: tuple[HistoryTenant, ...]
    service_name: str = "Veridion History Service"
    sqlite_path: str = ""
    store_dsn: str = ""
    materialization_root: str = ""
    auth_tokens: tuple[str, ...] = ()
    tokens: tuple[HistoryToken, ...] = ()
    jwt: JWTAuthConfig = JWTAuthConfig()
    trusted_headers: TrustedHeaderAuthConfig = TrustedHeaderAuthConfig()
    schedules: tuple[MaterializationSchedule, ...] = ()


def load_history_service_config(path: str | Path) -> HistoryServiceConfig:
    payload = json.loads(Path(path).read_text())
    if not isinstance(payload, dict):
        raise RuntimeError("history service config must be a JSON object")

    tenants_payload = payload.get("tenants")
    if not isinstance(tenants_payload, list) or not tenants_payload:
        raise RuntimeError("history service config must contain a non-empty tenants array")
    sqlite_path = _optional_string(payload.get("sqlite_path"))
    store_dsn = _optional_string(payload.get("store_dsn"))

    tenants: list[HistoryTenant] = []
    for item in tenants_payload:
        if not isinstance(item, dict):
            raise RuntimeError("history service config tenants must be objects")
        tenant_id = _required_string(item, "tenant_id")
        history_paths = _string_list(item.get("history_paths"))
        if not history_paths and not sqlite_path and not store_dsn:
            raise RuntimeError(f"tenant {tenant_id} must define one or more history_paths")
        tenants.append(
            HistoryTenant(
                tenant_id=tenant_id,
                history_paths=tuple(history_paths),
                display_name=_optional_string(item.get("display_name")),
                auth_tokens=tuple(_string_list(item.get("auth_tokens"))),
            )
        )

    return HistoryServiceConfig(
        tenants=tuple(tenants),
        service_name=_optional_string(payload.get("service_name")) or "Veridion History Service",
        sqlite_path=sqlite_path,
        store_dsn=store_dsn,
        materialization_root=_optional_string(payload.get("materialization_root")),
        auth_tokens=tuple(_string_list(payload.get("auth_tokens"))),
        tokens=tuple(_parse_tokens(payload.get("tokens"))),
        jwt=_parse_jwt(payload.get("jwt")),
        trusted_headers=_parse_trusted_headers(payload.get("trusted_headers")),
        schedules=tuple(_parse_schedules(payload.get("schedules"))),
    )


def tenant_map(config: HistoryServiceConfig) -> dict[str, HistoryTenant]:
    return {tenant.tenant_id: tenant for tenant in config.tenants}


def token_map(config: HistoryServiceConfig) -> dict[str, HistoryToken]:
    return {token.token: token for token in config.tokens}


def schedule_map(config: HistoryServiceConfig) -> dict[str, MaterializationSchedule]:
    return {schedule.schedule_id: schedule for schedule in config.schedules}


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
                token_id=_optional_string(item.get("token_id")) or _required_string(item, "token"),
                principal_name=_optional_string(item.get("principal_name")) or _optional_string(item.get("display_name")),
                auth_type=_optional_string(item.get("auth_type")) or "bearer",
                status=_optional_string(item.get("status")) or "active",
                tenants=tuple(_string_list(item.get("tenants"))),
                roles=tuple(_string_list(item.get("roles"))),
            )
        )
    return tokens


def _parse_jwt(value: object) -> JWTAuthConfig:
    if not isinstance(value, dict):
        return JWTAuthConfig()
    return JWTAuthConfig(
        issuer=_optional_string(value.get("issuer")),
        audience=_optional_string(value.get("audience")),
        shared_secret=_optional_string(value.get("shared_secret")),
        roles_claim=_optional_string(value.get("roles_claim")) or "roles",
        tenants_claim=_optional_string(value.get("tenants_claim")) or "tenants",
        principal_claim=_optional_string(value.get("principal_claim")) or "sub",
    )


def _parse_schedules(value: object) -> list[MaterializationSchedule]:
    if not isinstance(value, list):
        return []
    schedules: list[MaterializationSchedule] = []
    for item in value:
        if not isinstance(item, dict):
            raise RuntimeError("history service config schedules must be objects")
        schedules.append(
            MaterializationSchedule(
                schedule_id=_required_string(item, "schedule_id"),
                cron=_required_string(item, "cron"),
                tenants=tuple(_string_list(item.get("tenants"))),
                enabled=_bool_value(item.get("enabled"), default=True),
                athena_database=_optional_string(item.get("athena_database")),
                athena_table=_optional_string(item.get("athena_table")) or "veridion_decision_events",
                athena_s3_location_template=_optional_string(item.get("athena_s3_location_template")),
            )
        )
    return schedules


def _parse_trusted_headers(value: object) -> TrustedHeaderAuthConfig:
    if not isinstance(value, dict):
        return TrustedHeaderAuthConfig()
    return TrustedHeaderAuthConfig(
        enabled=_bool_value(value.get("enabled"), default=False),
        shared_secret=_optional_string(value.get("shared_secret")),
        secret_header=_optional_string(value.get("secret_header")) or "X-Veridion-Auth-Secret",
        principal_header=_optional_string(value.get("principal_header")) or "X-Veridion-Principal",
        token_id_header=_optional_string(value.get("token_id_header")) or "X-Veridion-Token-Id",
        roles_header=_optional_string(value.get("roles_header")) or "X-Veridion-Roles",
        tenants_header=_optional_string(value.get("tenants_header")) or "X-Veridion-Tenants",
        status_header=_optional_string(value.get("status_header")) or "X-Veridion-Status",
    )


def _bool_value(value: object, *, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "false"}:
            return lowered == "true"
    return default
