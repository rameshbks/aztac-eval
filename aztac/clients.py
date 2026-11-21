"""One interface over the ATS + gateway, in-process or over HTTP."""

from __future__ import annotations

import json
import os
import time

import httpx

from .services import AgentTokenService, ResourceGateway, RevocationList
from .tokens import TOKEN_EXCHANGE_GRANT, SigningKey, TokenVerifier, mint_user_token


class InProcStack:
    """ATS + gateway in one process with real RS256 signing and verification.
    Used for large benchmark runs; network cost is measured separately with HTTPStack."""

    def __init__(self, mode="graduated", risk_threshold=2.0, ttl_s=300, pdp_fn=None, approver_key="approver-secret"):
        self.idp_key = SigningKey.generate("dev-idp")
        ats_key = SigningKey.generate("ats")
        self.ats = AgentTokenService(ats_key, "https://ats.aztac.local",
                                     TokenVerifier({self.idp_key.kid: self.idp_key.public_pem}, audience="agent-platform"),
                                     ttl_s=ttl_s)
        self.gw = ResourceGateway(TokenVerifier({ats_key.kid: ats_key.public_pem}, issuer="https://ats.aztac.local"),
                                  mode=mode, risk_threshold=risk_threshold, revocations=self.ats.revocations,
                                  approver_key=approver_key, pdp_fn=pdp_fn)
        self.approver_key = approver_key

    def user_token(self, username="alice") -> str:
        return mint_user_token(self.idp_key, "dev-idp", username)

    def exchange(self, subject_token, agent_id, task_id, details, ttl_s=None) -> dict:
        return self.ats.exchange(TOKEN_EXCHANGE_GRANT, subject_token, agent_id, task_id, details, ttl_s)

    def authorize(self, token, tool, args) -> dict:
        return self.gw.authorize(token, tool, args)

    def resolve(self, challenge_id, approved) -> dict:
        return self.gw.resolve_challenge(challenge_id, approved, self.approver_key)

    def redeem(self, token, challenge_id, tool, args) -> dict:
        return self.gw.redeem_challenge(token, challenge_id, tool, args)

    def revoke(self, jti) -> None:
        self.ats.revoke(jti)


class HTTPStack:
    """ATS and gateway on other hosts. Subject token comes from Keycloak (or ATS dev IdP)."""

    def __init__(self, ats_url, gateway_url, approver_key=None, admin_key=None, keycloak=None):
        self.ats_url, self.gateway_url = ats_url.rstrip("/"), gateway_url.rstrip("/")
        self.approver_key = approver_key or os.getenv("APPROVER_KEY", "approver-secret")
        self.admin_key = admin_key or os.getenv("ATS_ADMIN_KEY", "admin-secret")
        self.keycloak = keycloak  # dict(token_url, client_id, client_secret, username, password)
        self.c = httpx.Client(timeout=10)

    def user_token(self, username="alice") -> str:
        if self.keycloak:
            k = self.keycloak
            r = self.c.post(k["token_url"], data={"grant_type": "password", "client_id": k["client_id"],
                                                  "client_secret": k["client_secret"], "username": k["username"],
                                                  "password": k["password"], "scope": "openid"})
            r.raise_for_status()
            return r.json()["access_token"]
        r = self.c.post(f"{self.ats_url}/dev/user-token", json={"username": username})
        r.raise_for_status()
        return r.json()["access_token"]

    def exchange(self, subject_token, agent_id, task_id, details, ttl_s=None) -> dict:
        data = {"grant_type": TOKEN_EXCHANGE_GRANT, "subject_token": subject_token, "actor": agent_id,
                "task_id": task_id, "authorization_details": json.dumps(details)}
        if ttl_s:
            data["ttl_s"] = str(ttl_s)
        r = self.c.post(f"{self.ats_url}/token", data=data)
        r.raise_for_status()
        return r.json()

    def authorize(self, token, tool, args) -> dict:
        r = self.c.post(f"{self.gateway_url}/authorize", json={"token": token, "tool": tool, "args": args})
        r.raise_for_status()
        return r.json()

    def resolve(self, challenge_id, approved) -> dict:
        r = self.c.post(f"{self.gateway_url}/approvals", json={"challenge_id": challenge_id, "approved": approved},
                        headers={"x-approver-key": self.approver_key})
        r.raise_for_status()
        return r.json()

    def redeem(self, token, challenge_id, tool, args) -> dict:
        r = self.c.post(f"{self.gateway_url}/redeem",
                        json={"token": token, "challenge_id": challenge_id, "tool": tool, "args": args})
        r.raise_for_status()
        return r.json()

    def revoke(self, jti) -> None:
        self.c.post(f"{self.ats_url}/revoke", json={"jti": jti}, headers={"x-admin-key": self.admin_key}).raise_for_status()
