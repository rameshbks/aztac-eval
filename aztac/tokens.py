"""Signing keys and task-bound agent tokens.

An agent token is a short-lived JWT issued by the Agent Token Service (ATS) through
an OAuth 2.0 Token Exchange (RFC 8693). It carries:

  sub                    the human principal the agent acts for
  act.sub                the agent identity (RFC 8693 actor claim)
  task_id                the task this token is bound to
  authorization_details  the compiled task scope (RFC 9396 Rich Authorization Requests)
  exp                    short lifetime (default 300 s)
  jti                    unique id used for revocation
"""

from __future__ import annotations

import base64
import json
import time
import uuid
from dataclasses import dataclass

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

AUDIENCE = "aztac-resource-gateway"
TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"


def _b64u_uint(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


@dataclass
class SigningKey:
    kid: str
    private_pem: bytes
    public_pem: bytes

    @classmethod
    def generate(cls, kid: str | None = None) -> "SigningKey":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        priv = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        pub = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return cls(kid=kid or uuid.uuid4().hex[:12], private_pem=priv, public_pem=pub)

    @classmethod
    def load(cls, path: str) -> "SigningKey":
        with open(path) as f:
            d = json.load(f)
        return cls(kid=d["kid"], private_pem=d["private_pem"].encode(), public_pem=d["public_pem"].encode())

    def save(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(
                {"kid": self.kid, "private_pem": self.private_pem.decode(), "public_pem": self.public_pem.decode()}, f
            )

    @property
    def private_key(self):
        # Parse once: PEM loading runs OpenSSL key checks that cost tens of ms per call.
        if not hasattr(self, "_priv"):
            self._priv = serialization.load_pem_private_key(self.private_pem, password=None)
        return self._priv

    @property
    def public_key(self):
        if not hasattr(self, "_pub"):
            self._pub = serialization.load_pem_public_key(self.public_pem)
        return self._pub

    def jwk(self) -> dict:
        pub = serialization.load_pem_public_key(self.public_pem)
        nums = pub.public_numbers()
        return {"kty": "RSA", "kid": self.kid, "use": "sig", "alg": "RS256", "n": _b64u_uint(nums.n), "e": _b64u_uint(nums.e)}


def mint_agent_token(
    key: SigningKey,
    issuer: str,
    subject: str,
    agent_id: str,
    task_id: str,
    authorization_details: list[dict],
    ttl_s: int = 300,
) -> tuple[str, dict]:
    now = int(time.time())
    claims = {
        "iss": issuer,
        "aud": AUDIENCE,
        "sub": subject,
        "act": {"sub": agent_id},
        "task_id": task_id,
        "authorization_details": authorization_details,
        "iat": now,
        "nbf": now,
        "exp": now + ttl_s,
        "jti": uuid.uuid4().hex,
    }
    token = jwt.encode(claims, key.private_key, algorithm="RS256", headers={"kid": key.kid})
    return token, claims


def mint_user_token(key: SigningKey, issuer: str, username: str, ttl_s: int = 3600) -> str:
    """Dev-mode stand-in for an IdP-issued user access token (used when Keycloak is not deployed)."""
    now = int(time.time())
    claims = {"iss": issuer, "sub": username, "preferred_username": username, "iat": now, "exp": now + ttl_s,
              "aud": "agent-platform", "azp": "agent-platform"}
    return jwt.encode(claims, key.private_key, algorithm="RS256", headers={"kid": key.kid})


class TokenVerifier:
    """Verifies RS256 JWTs against a static key set (in-process) or a JWKS URL."""

    def __init__(self, public_keys: dict[str, bytes] | None = None, jwks_url: str | None = None,
                 audience: str | None = AUDIENCE, issuer: str | None = None, leeway_s: int = 5):
        self.public_keys = {k: (serialization.load_pem_public_key(v) if isinstance(v, bytes) else v)
                            for k, v in (public_keys or {}).items()}
        self.jwks_client = jwt.PyJWKClient(jwks_url, cache_keys=True) if jwks_url else None
        self.audience = audience
        self.issuer = issuer
        self.leeway_s = leeway_s

    def verify(self, token: str) -> dict:
        if self.jwks_client is not None:
            key = self.jwks_client.get_signing_key_from_jwt(token).key
        else:
            kid = jwt.get_unverified_header(token).get("kid")
            if kid not in self.public_keys:
                raise jwt.InvalidTokenError(f"unknown signing key {kid}")
            key = self.public_keys[kid]
        options = {"require": ["exp", "iat", "sub"], "verify_aud": self.audience is not None}
        return jwt.decode(token, key, algorithms=["RS256"], audience=self.audience, issuer=self.issuer,
                          leeway=self.leeway_s, options=options)
