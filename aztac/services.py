"""Agent Token Service (ATS) and Resource Gateway (PEP), as plain classes.

The same classes run in-process for fast experiments, or behind FastAPI on
separate hosts (see aztac/http_apps.py and deploy/). Enforcement lives here,
outside the agent runtime: a compromised agent holds only its task token and
cannot widen it.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid

import jwt

from .pdp import ALLOW, DENY, NARROW, REVOKED, STEP_UP, Decision, RiskEngine, decide
from .tokens import TOKEN_EXCHANGE_GRANT, SigningKey, TokenVerifier, mint_agent_token


class RevocationList:
    """Revoked token ids with timestamps; gateways sync from the ATS."""

    def __init__(self):
        self._items: dict[str, float] = {}
        self._lock = threading.Lock()

    def add(self, jti: str, at: float | None = None) -> None:
        with self._lock:
            self._items.setdefault(jti, at or time.time())

    def __contains__(self, jti: str) -> bool:
        return jti in self._items

    def since(self, t: float) -> dict[str, float]:
        with self._lock:
            return {j: ts for j, ts in self._items.items() if ts >= t}


class AgentTokenService:
    """OAuth 2.0 Token Exchange (RFC 8693) issuer for task-bound agent tokens.

    subject_token: the human user's access token from the enterprise IdP
                   (Keycloak / Entra ID), verified against the IdP's JWKS.
    actor:         the registered agent identity.
    authorization_details: the compiled task scope (RFC 9396).
    """

    def __init__(self, key: SigningKey, issuer: str, subject_verifier: TokenVerifier,
                 registered_agents: set[str] | None = None, ttl_s: int = 300, max_ttl_s: int = 900):
        self.key, self.issuer, self.subject_verifier = key, issuer, subject_verifier
        self.registered_agents = registered_agents
        self.ttl_s, self.max_ttl_s = ttl_s, max_ttl_s
        self.revocations = RevocationList()

    def exchange(self, grant_type: str, subject_token: str, agent_id: str, task_id: str,
                 authorization_details: list[dict], ttl_s: int | None = None) -> dict:
        if grant_type != TOKEN_EXCHANGE_GRANT:
            raise PermissionError("unsupported_grant_type")
        if self.registered_agents is not None and agent_id not in self.registered_agents:
            raise PermissionError("unknown agent identity")
        user = self.subject_verifier.verify(subject_token)
        ttl = min(ttl_s or self.ttl_s, self.max_ttl_s)
        token, claims = mint_agent_token(self.key, self.issuer, user["sub"], agent_id, task_id,
                                         authorization_details, ttl)
        return {"access_token": token, "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "token_type": "Bearer", "expires_in": ttl, "jti": claims["jti"]}

    def revoke(self, jti: str) -> None:
        self.revocations.add(jti)

    def jwks(self) -> dict:
        return {"keys": [self.key.jwk()]}


class ResourceGateway:
    """Policy enforcement point in front of the tools / resource servers."""

    def __init__(self, verifier: TokenVerifier, mode: str = "graduated", risk_threshold: float = 2.0,
                 revocations: RevocationList | None = None, on_revoke=None, approver_key: str = "approver-secret",
                 pdp_fn=None):
        self.verifier, self.mode = verifier, mode
        self.risk = RiskEngine(risk_threshold)
        self.revocations = revocations or RevocationList()
        self.on_revoke = on_revoke  # callback to propagate to ATS (HTTP mode)
        self.approver_key = approver_key
        self.pdp_fn = pdp_fn or decide  # swap for OPA client
        self.challenges: dict[str, dict] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _call_hash(jti: str, tool: str, args: dict) -> str:
        return hashlib.sha256(json.dumps([jti, tool, args], sort_keys=True, default=str).encode()).hexdigest()

    def _revoke(self, jti: str) -> None:
        self.revocations.add(jti)
        if self.on_revoke:
            self.on_revoke(jti)

    def authorize(self, token: str, tool: str, args: dict) -> dict:
        t0 = time.perf_counter()
        try:
            claims = self.verifier.verify(token)
        except (jwt.InvalidTokenError, jwt.PyJWKClientError, KeyError, ValueError) as e:  # unknown key, bad format: fail closed
            return self._out(Decision(DENY, f"invalid token: {e}", violations=["invalid_token"]), None, t0)
        jti = claims["jti"]
        if jti in self.revocations:
            return self._out(Decision(REVOKED, "token revoked"), jti, t0)

        try:
            d = self.pdp_fn(claims["authorization_details"], tool, args, self.mode)
        except Exception as e:  # fail closed: a policy that cannot be evaluated denies the call
            d = Decision(DENY, f"policy evaluation error: {type(e).__name__}", violations=["policy_error"])
        extra = {}
        if d.outcome == STEP_UP:
            cid = uuid.uuid4().hex
            with self._lock:
                self.challenges[cid] = {"hash": self._call_hash(jti, tool, args), "jti": jti, "status": "pending"}
            extra["challenge_id"] = cid
        if d.outcome in (DENY, NARROW) and self.risk.record(jti, d.outcome):
            self._revoke(jti)
            extra["revoked_now"] = True
        return self._out(d, jti, t0, extra)

    def resolve_challenge(self, challenge_id: str, approved: bool, approver_key: str) -> dict:
        """Called by the human's approval channel (not the agent)."""
        if approver_key != self.approver_key:
            raise PermissionError("bad approver credential")
        with self._lock:
            ch = self.challenges.get(challenge_id)
            if ch is None or ch["status"] != "pending":
                raise KeyError("unknown or used challenge")
            ch["status"] = "approved" if approved else "rejected"
        revoked_now = False
        if not approved and self.risk.record(ch["jti"], "STEP_UP_REJECTED"):
            self._revoke(ch["jti"])
            revoked_now = True
        return {"status": ch["status"], "revoked_now": revoked_now}

    def redeem_challenge(self, token: str, challenge_id: str, tool: str, args: dict) -> dict:
        """Agent retries the exact call after approval; approval is single-use and bound to the call."""
        t0 = time.perf_counter()
        claims = self.verifier.verify(token)
        jti = claims["jti"]
        if jti in self.revocations:
            return self._out(Decision(REVOKED, "token revoked"), jti, t0)
        with self._lock:
            ch = self.challenges.get(challenge_id)
            ok = ch is not None and ch["status"] == "approved" and ch["hash"] == self._call_hash(jti, tool, args)
            if ok:
                ch["status"] = "used"
        if ok:
            return self._out(Decision(ALLOW, "approved by human"), jti, t0)
        return self._out(Decision(DENY, "approval missing, rejected or not bound to this call"), jti, t0)

    @staticmethod
    def _out(d: Decision, jti, t0, extra=None) -> dict:
        out = {"outcome": d.outcome, "reason": d.reason, "violations": d.violations, "jti": jti,
               "decision_us": (time.perf_counter() - t0) * 1e6}
        if d.args is not None:
            out["args"] = d.args
        out.update(extra or {})
        return out
