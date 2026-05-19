"""Identity resolution helpers for the Veridion history service."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

from veridion.action.decision_history_config import HistoryToken, JWTAuthConfig, TrustedHeaderAuthConfig


def resolve_bearer_identity(
    *,
    token: str,
    scoped_tokens: dict[str, HistoryToken],
    jwt_config: JWTAuthConfig,
) -> HistoryToken | None:
    scoped = scoped_tokens.get(token)
    if scoped is not None:
        return scoped
    return _resolve_jwt_identity(token=token, jwt_config=jwt_config)


def resolve_trusted_header_identity(
    *,
    headers: dict[str, str],
    config: TrustedHeaderAuthConfig,
) -> HistoryToken | None:
    if not config.enabled or not config.shared_secret:
        return None
    header_lookup = {key.lower(): value for key, value in headers.items()}
    if header_lookup.get(config.secret_header.lower(), "").strip() != config.shared_secret:
        return None
    principal = header_lookup.get(config.principal_header.lower(), "").strip()
    if not principal:
        return None
    token_id = header_lookup.get(config.token_id_header.lower(), "").strip() or principal
    roles = _split_csv(header_lookup.get(config.roles_header.lower(), ""))
    tenants = _split_csv(header_lookup.get(config.tenants_header.lower(), ""))
    status = header_lookup.get(config.status_header.lower(), "").strip() or "active"
    return HistoryToken(
        token=f"trusted:{token_id}",
        token_id=token_id,
        principal_name=principal,
        auth_type="trusted_header",
        status=status,
        tenants=tuple(tenants),
        roles=tuple(roles),
    )


def _resolve_jwt_identity(*, token: str, jwt_config: JWTAuthConfig) -> HistoryToken | None:
    if not jwt_config.shared_secret:
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_b64, payload_b64, signature_b64 = parts
    try:
        header = _load_segment(header_b64)
        payload = _load_segment(payload_b64)
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    if str(header.get("alg", "")).upper() != "HS256":
        return None
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    expected = hmac.new(jwt_config.shared_secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    try:
        provided = _urlsafe_b64decode(signature_b64)
    except Exception:
        return None
    if not hmac.compare_digest(expected, provided):
        return None
    if jwt_config.issuer and str(payload.get("iss", "")) != jwt_config.issuer:
        return None
    if jwt_config.audience:
        audience = payload.get("aud")
        if isinstance(audience, list):
            if jwt_config.audience not in [str(item) for item in audience]:
                return None
        elif str(audience or "") != jwt_config.audience:
            return None
    principal_name = _claim_string(payload.get(jwt_config.principal_claim)) or _claim_string(payload.get("sub"))
    roles = _claim_strings(payload.get(jwt_config.roles_claim))
    tenants = _claim_strings(payload.get(jwt_config.tenants_claim))
    return HistoryToken(
        token=token,
        token_id=_claim_string(payload.get("jti")) or principal_name or "jwt",
        principal_name=principal_name,
        auth_type="jwt",
        status="active",
        tenants=tuple(tenants),
        roles=tuple(roles),
    )


def _load_segment(segment: str) -> object:
    return json.loads(_urlsafe_b64decode(segment).decode("utf-8"))


def _urlsafe_b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _claim_strings(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [item.strip() for item in value.split(",") if item.strip()]
    return []


def _claim_string(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]
