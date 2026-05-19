from veridion.action.decision_history_config import JWTAuthConfig, TrustedHeaderAuthConfig
from veridion.action.history_identity import jwt_auth_enabled, resolve_bearer_identity, resolve_trusted_header_identity

import base64
import hashlib
import hmac
import json


def test_resolve_trusted_header_identity_reads_principal_roles_and_tenants() -> None:
    identity = resolve_trusted_header_identity(
        headers={
            "X-Veridion-Auth-Secret": "secret",
            "X-Veridion-Principal": "alice@example.com",
            "X-Veridion-Token-Id": "tok_1",
            "X-Veridion-Roles": "reader,materializer",
            "X-Veridion-Tenants": "acme,beta",
        },
        config=TrustedHeaderAuthConfig(enabled=True, shared_secret="secret"),
    )

    assert identity is not None
    assert identity.auth_type == "trusted_header"
    assert identity.principal_name == "alice@example.com"
    assert identity.roles == ("reader", "materializer")
    assert identity.tenants == ("acme", "beta")


def test_resolve_bearer_identity_accepts_hs256_jwt() -> None:
    token = _build_test_jwt(
        secret="super-secret",
        payload={
            "iss": "https://issuer.example",
            "aud": "veridion-history",
            "sub": "svc-acme",
            "jti": "jwt-1",
            "roles": ["reader"],
            "tenants": ["acme"],
        },
    )

    identity = resolve_bearer_identity(
        token=token,
        scoped_tokens={},
        jwt_config=JWTAuthConfig(
            issuer="https://issuer.example",
            audience="veridion-history",
            shared_secret="super-secret",
        ),
    )

    assert identity is not None
    assert identity.auth_type == "jwt"
    assert identity.token_id == "jwt-1"


def test_jwt_auth_enabled_for_jwks_configs() -> None:
    assert jwt_auth_enabled(JWTAuthConfig(shared_secret="secret")) is True
    assert jwt_auth_enabled(JWTAuthConfig(jwks_path="/tmp/jwks.json")) is True
    assert jwt_auth_enabled(JWTAuthConfig(jwks_url="https://issuer.example/jwks.json")) is True
    assert jwt_auth_enabled(JWTAuthConfig()) is False


def _build_test_jwt(*, secret: str, payload: dict[str, object]) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64(header)
    payload_b64 = _b64(payload)
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("=")
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def _b64(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(encoded).decode("utf-8").rstrip("=")
