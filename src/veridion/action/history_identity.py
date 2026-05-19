"""Identity resolution helpers for the Veridion history service."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path
from urllib import error, request

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


def jwt_auth_enabled(config: JWTAuthConfig) -> bool:
    return bool(config.shared_secret or config.jwks_path or config.jwks_url or config.oidc_discovery_url)


def _resolve_jwt_identity(*, token: str, jwt_config: JWTAuthConfig) -> HistoryToken | None:
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
    algorithm = str(header.get("alg", "")).upper()
    if algorithm == "HS256":
        if not jwt_config.shared_secret:
            return None
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        expected = hmac.new(jwt_config.shared_secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
        try:
            provided = _urlsafe_b64decode(signature_b64)
        except Exception:
            return None
        if not hmac.compare_digest(expected, provided):
            return None
    elif algorithm == "RS256":
        if not _verify_rs256_jwt(
            header=header,
            payload_b64=payload_b64,
            header_b64=header_b64,
            signature_b64=signature_b64,
            jwt_config=jwt_config,
        ):
            return None
    else:
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


def _verify_rs256_jwt(
    *,
    header: dict[str, object],
    header_b64: str,
    payload_b64: str,
    signature_b64: str,
    jwt_config: JWTAuthConfig,
) -> bool:
    jwks = _load_jwks(jwt_config)
    if jwks is None:
        return False
    kid = str(header.get("kid", ""))
    key = _select_jwk(jwks, kid)
    if key is None:
        return False
    modulus_b64 = str(key.get("n", ""))
    exponent_b64 = str(key.get("e", ""))
    if not modulus_b64 or not exponent_b64:
        return False
    try:
        modulus = int.from_bytes(_urlsafe_b64decode(modulus_b64), "big")
        exponent = int.from_bytes(_urlsafe_b64decode(exponent_b64), "big")
        signature = int.from_bytes(_urlsafe_b64decode(signature_b64), "big")
    except Exception:
        return False
    signed = pow(signature, exponent, modulus)
    key_bytes = max(1, (modulus.bit_length() + 7) // 8)
    em = signed.to_bytes(key_bytes, "big")
    digest = hashlib.sha256(f"{header_b64}.{payload_b64}".encode("utf-8")).digest()
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + digest
    return _verify_pkcs1_v1_5(em, digest_info)


def _verify_pkcs1_v1_5(em: bytes, digest_info: bytes) -> bool:
    if len(em) < len(digest_info) + 11:
        return False
    if not em.startswith(b"\x00\x01"):
        return False
    try:
        separator = em.index(b"\x00", 2)
    except ValueError:
        return False
    padding = em[2:separator]
    if len(padding) < 8 or any(byte != 0xFF for byte in padding):
        return False
    return em[separator + 1 :] == digest_info


def _load_jwks(jwt_config: JWTAuthConfig) -> dict[str, object] | None:
    if jwt_config.jwks_path:
        payload = json.loads(Path(jwt_config.jwks_path).read_text())
        return payload if isinstance(payload, dict) else None
    if jwt_config.jwks_url:
        try:
            with request.urlopen(jwt_config.jwks_url, timeout=15) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
                payload = json.loads(response.read().decode("utf-8"))
        except (error.URLError, error.HTTPError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None
    if jwt_config.oidc_discovery_url:
        discovery = _fetch_json(jwt_config.oidc_discovery_url)
        if discovery is None:
            return None
        jwks_uri = str(discovery.get("jwks_uri", "")) if isinstance(discovery, dict) else ""
        if not jwks_uri:
            return None
        return _fetch_json(jwks_uri)
    return None


def _select_jwk(jwks: dict[str, object], kid: str) -> dict[str, object] | None:
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        return None
    candidates = [item for item in keys if isinstance(item, dict)]
    if kid:
        for item in candidates:
            if str(item.get("kid", "")) == kid:
                return item
    return candidates[0] if candidates else None


def _fetch_json(url: str) -> dict[str, object] | None:
    try:
        with request.urlopen(url, timeout=15) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            payload = json.loads(response.read().decode("utf-8"))
    except (error.URLError, error.HTTPError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


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
