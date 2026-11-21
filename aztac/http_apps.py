"""FastAPI wrappers so the ATS and gateway can run on separate hosts.

Run:
  uvicorn aztac.http_apps:ats_app --host 0.0.0.0 --port 8100
  uvicorn aztac.http_apps:gateway_app --host 0.0.0.0 --port 8200

Configuration is by environment variable (see deploy/.env.example).
"""

from __future__ import annotations

import base64
import hmac
import json
import os
import tempfile
import threading
import time

import httpx
from fastapi import FastAPI, Form, Header, HTTPException
from pydantic import BaseModel

from .opa import OPAClient
from .services import AgentTokenService, ResourceGateway
from .tokens import SigningKey, TokenVerifier, mint_user_token


def _env(name, default=None):
    v = os.getenv(name, default)
    return v if v not in ("", None) else default


# --------------------------------------------------------------------------- ATS
def build_ats_app() -> FastAPI:
    key_path = _env("ATS_KEY_PATH", os.path.join(tempfile.gettempdir(), "aztac_ats_key.json"))
    key = SigningKey.load(key_path) if os.path.exists(key_path) else SigningKey.generate()
    if not os.path.exists(key_path):
        key.save(key_path)
    issuer = _env("ATS_ISSUER", "https://ats.aztac.local")
    admin_key = _env("ATS_ADMIN_KEY", "admin-secret")

    if _env("SUBJECT_JWKS_URL"):  # enterprise IdP (Keycloak / Entra ID)
        subject_verifier = TokenVerifier(jwks_url=_env("SUBJECT_JWKS_URL"), audience=_env("SUBJECT_AUDIENCE"),
                                         issuer=_env("SUBJECT_ISSUER"))
        dev_idp = None
    else:  # dev mode: ATS also signs stand-in user tokens
        dev_idp = SigningKey.generate("dev-idp")
        subject_verifier = TokenVerifier({dev_idp.kid: dev_idp.public_pem}, audience="agent-platform")

    agents = _env("ATS_AGENTS")
    ats = AgentTokenService(key, issuer, subject_verifier,
                            registered_agents=set(agents.split(",")) if agents else None,
                            ttl_s=int(_env("ATS_TTL_S", "300")))
    app = FastAPI(title="AZTAC Agent Token Service")

    # Only the trusted scope-compilation component may request agent tokens: it authenticates as an OAuth
    # client (RFC 6749 client authentication, form or HTTP Basic). The agent runtime never holds this
    # credential nor the user's token, so it cannot submit a scope of its own.
    compiler_id = _env("COMPILER_CLIENT_ID", "scope-compiler")
    compiler_secret = _env("COMPILER_CLIENT_SECRET")

    def _client_ok(form_id, form_secret, authorization):
        if not compiler_secret:
            return True  # client authentication disabled (in-process experiments)
        cid, csec = form_id, form_secret
        if authorization and authorization.lower().startswith("basic "):
            try:
                cid, csec = base64.b64decode(authorization[6:]).decode().split(":", 1)
            except Exception:
                return False
        return cid == compiler_id and csec is not None and hmac.compare_digest(csec, compiler_secret)

    @app.post("/token")
    def token(grant_type: str = Form(...), subject_token: str = Form(...), actor: str = Form(...),
              task_id: str = Form(...), authorization_details: str = Form(...), ttl_s: int | None = Form(None),
              client_id: str | None = Form(None), client_secret: str | None = Form(None),
              authorization: str | None = Header(None)):
        if not _client_ok(client_id, client_secret, authorization):
            raise HTTPException(401, "invalid_client")
        try:
            return ats.exchange(grant_type, subject_token, actor, task_id, json.loads(authorization_details), ttl_s)
        except PermissionError as e:
            raise HTTPException(403, str(e))
        except Exception as e:  # invalid subject token etc.
            raise HTTPException(400, f"invalid_request: {e}")

    @app.post("/revoke")
    def revoke(body: dict, x_admin_key: str = Header(...)):
        if x_admin_key != admin_key:
            raise HTTPException(403)
        ats.revoke(body["jti"])
        return {"revoked": body["jti"], "at": time.time()}

    @app.get("/revocations")
    def revocations(since: float = 0.0):
        return ats.revocations.since(since)

    @app.get("/jwks")
    def jwks():
        return ats.jwks()

    if dev_idp is not None:
        @app.post("/dev/user-token")
        def dev_user_token(body: dict):
            return {"access_token": mint_user_token(dev_idp, "dev-idp", body.get("username", "alice"))}

    return app


# ----------------------------------------------------------------------- Gateway
class AuthorizeBody(BaseModel):
    token: str
    tool: str
    args: dict


class RedeemBody(AuthorizeBody):
    challenge_id: str


class ResolveBody(BaseModel):
    challenge_id: str
    approved: bool


def build_gateway_app() -> FastAPI:
    ats_url = _env("ATS_URL", "http://localhost:8100")
    admin_key = _env("ATS_ADMIN_KEY", "admin-secret")
    poll_ms = int(_env("REVOCATION_POLL_MS", "200"))
    verifier = TokenVerifier(jwks_url=f"{ats_url}/jwks", issuer=_env("ATS_ISSUER", "https://ats.aztac.local"))

    def push_revoke(jti):
        try:
            httpx.post(f"{ats_url}/revoke", json={"jti": jti}, headers={"x-admin-key": admin_key}, timeout=2)
        except httpx.HTTPError:
            pass  # local list already updated; ATS will be retried by poller design in production

    pdp_fn = OPAClient(_env("OPA_URL")).decide if _env("PDP", "python") == "opa" else None
    gw = ResourceGateway(verifier, mode=_env("ENFORCEMENT_MODE", "graduated"),
                         risk_threshold=float(_env("RISK_THRESHOLD", "2.0")), on_revoke=push_revoke,
                         approver_key=_env("APPROVER_KEY", "approver-secret"), pdp_fn=pdp_fn)

    def poller():
        last = 0.0
        while True:
            try:
                items = httpx.get(f"{ats_url}/revocations", params={"since": last}, timeout=2).json()
                for jti, ts in items.items():
                    gw.revocations.add(jti, ts)
                    last = max(last, ts)
            except Exception:
                pass
            time.sleep(poll_ms / 1000)

    threading.Thread(target=poller, daemon=True).start()
    app = FastAPI(title="AZTAC Resource Gateway")

    @app.post("/authorize")
    def authorize(b: AuthorizeBody):
        return gw.authorize(b.token, b.tool, b.args)

    @app.post("/redeem")
    def redeem(b: RedeemBody):
        return gw.redeem_challenge(b.token, b.challenge_id, b.tool, b.args)

    @app.post("/approvals")
    def resolve(b: ResolveBody, x_approver_key: str = Header(...)):
        try:
            return gw.resolve_challenge(b.challenge_id, b.approved, x_approver_key)
        except PermissionError:
            raise HTTPException(403)
        except KeyError as e:
            raise HTTPException(404, str(e))

    # Enforcing reverse proxy (case study): the upstream API trusts only this gateway's secret, so an
    # agent token can reach it only through an ALLOW or NARROW decision.
    upstream, upstream_secret = _env("UPSTREAM_URL"), _env("UPSTREAM_SECRET", "")
    proxy = httpx.Client(timeout=15)

    @app.post("/call")
    def call(b: AuthorizeBody):
        if not upstream:
            raise HTTPException(404, "no upstream configured")
        d = gw.authorize(b.token, b.tool, b.args)
        if d["outcome"] not in ("ALLOW", "NARROW"):
            return {"decision": d}
        args = d.get("args") or b.args
        t0 = time.perf_counter()
        r = proxy.post(f"{upstream.rstrip('/')}/tools/{b.tool}", json=args, headers={"x-caller-key": upstream_secret})
        body = r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text
        return {"decision": d, "status": r.status_code, "result": body,
                "upstream_ms": (time.perf_counter() - t0) * 1e3}

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "mode": gw.mode, "upstream": bool(upstream)}

    return app


def __getattr__(name):  # lazy so importing this module does not start both apps
    if name == "ats_app":
        return build_ats_app()
    if name == "gateway_app":
        return build_gateway_app()
    raise AttributeError(name)
