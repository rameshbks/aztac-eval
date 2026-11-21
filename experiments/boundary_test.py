"""Trust-boundary test: what can a compromised agent runtime do with the credentials it might obtain?

Runs against a live deployment (ATS with COMPILER_CLIENT_SECRET set, Keycloak as IdP, gateway).
The attacker holds a legitimate narrow task token (pay one IBAN) and, in the worst case, a stolen copy of
the user's IdP token, but not the compiler's client credential. Each attempt is repeated --trials times.

  python experiments/boundary_test.py --ats-url ... --gateway-url ... --keycloak-token-url ... --out results/boundary.json
Environment: COMPILER_CLIENT_SECRET (to mint the legitimate token), KEYCLOAK_CLIENT_SECRET, KEYCLOAK_USER_PASSWORD,
             ATS_ADMIN_KEY (for the revocation case)
"""
import argparse
import base64
import json
import os
import sys
import time

import httpx

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from aztac.scope import scope_from_calls  # noqa: E402
from aztac.tokens import TOKEN_EXCHANGE_GRANT, SigningKey, mint_agent_token  # noqa: E402

LEGIT_IBAN = "DE89370400440532013000"
ATTACKER_IBAN = "GB33BUKB20201555555555"
# the narrow scope a compiler would produce for "send 100 to DE89...", built with the same code path
NARROW = scope_from_calls("banking", [("send_money", {"recipient": LEGIT_IBAN, "amount": 100.0,
                                                      "subject": "rent", "date": "2026-11-21"})])
WIDE = [{"type": "agent_tool_invocation", "locations": ["banking"], "actions": ["send_money"]}]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ats-url", required=True)
    p.add_argument("--gateway-url", required=True)
    p.add_argument("--keycloak-token-url", required=True)
    p.add_argument("--trials", type=int, default=20)
    p.add_argument("--out", required=True)
    a = p.parse_args()
    c = httpx.Client(timeout=20)
    comp = {"client_id": os.getenv("COMPILER_CLIENT_ID", "scope-compiler"),
            "client_secret": os.environ["COMPILER_CLIENT_SECRET"]}

    def user_token():
        r = c.post(a.keycloak_token_url, data={
            "grant_type": "password", "client_id": "agent-platform", "scope": "openid",
            "client_secret": os.environ["KEYCLOAK_CLIENT_SECRET"], "username": "alice",
            "password": os.environ["KEYCLOAK_USER_PASSWORD"]})
        r.raise_for_status()
        return r.json()["access_token"]

    def exchange(subject, scope, auth=None, ttl=None):
        data = {"grant_type": TOKEN_EXCHANGE_GRANT, "subject_token": subject, "actor": "agent-1",
                "task_id": f"t-{time.time_ns()}", "authorization_details": json.dumps(scope), **(auth or {})}
        if ttl:
            data["ttl_s"] = str(ttl)
        return c.post(f"{a.ats_url}/token", data=data)

    def authorize(token, iban):
        r = c.post(f"{a.gateway_url}/authorize", json={"token": token, "tool": "send_money",
                                                        "args": {"recipient": iban, "amount": 50.0,
                                                                 "subject": "x", "date": "2026-11-21"}})
        return r.json()["outcome"]

    def tamper(token):  # widen the scope inside a valid token, keep the original signature
        h, pl, s = token.split(".")
        claims = json.loads(base64.urlsafe_b64decode(pl + "=" * (-len(pl) % 4)))
        claims["authorization_details"] = WIDE
        pl2 = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
        return f"{h}.{pl2}.{s}"

    cases = {
        "control: compiler exchange (expect 200)": lambda: exchange(user_token(), NARROW, comp).status_code,
        "control: in-scope call (expect ALLOW)": lambda: authorize(exchange(user_token(), NARROW, comp).json()["access_token"], LEGIT_IBAN),
        "narrow token, attacker IBAN (expect DENY)": lambda: authorize(exchange(user_token(), NARROW, comp).json()["access_token"], ATTACKER_IBAN),
        "stolen user token, no client credential, wide scope": lambda: exchange(user_token(), WIDE).status_code,
        "stolen user token, wrong client secret, wide scope": lambda: exchange(user_token(), WIDE, {**comp, "client_secret": "guess"}).status_code,
        "task token re-exchanged for wide scope (even with compiler credential)":
            lambda: exchange(exchange(user_token(), NARROW, comp).json()["access_token"], WIDE, comp).status_code,
        "tampered task token with widened scope": lambda: authorize(tamper(exchange(user_token(), NARROW, comp).json()["access_token"]), ATTACKER_IBAN),
        "self-signed forged token with wide scope":
            lambda: authorize(mint_agent_token(SigningKey.generate("attacker"), "https://ats.aztac.local", "alice", "agent-1", "t", WIDE, 300)[0], ATTACKER_IBAN),
    }
    results = {}
    for name, fn in cases.items():
        outs = [str(fn()) for _ in range(a.trials)]
        results[name] = dict(sorted({o: outs.count(o) for o in set(outs)}.items()))
        print(f"{name:78s} {results[name]}", flush=True)
    # expiry and revocation: a few trials each (they need waiting / admin calls)
    exp = []
    for _ in range(3):
        t = exchange(user_token(), NARROW, comp, ttl=1).json()["access_token"]
        time.sleep(7.5)  # 1 s lifetime + 5 s clock-skew leeway at the gateway
        exp.append(authorize(t, LEGIT_IBAN))
    name = "expired task token (1 s TTL, 5 s leeway), in-scope call"
    results[name] = {o: exp.count(o) for o in set(exp)}
    print(f"{name:78s} {results[name]}")
    rev = []
    for _ in range(3):
        r = exchange(user_token(), NARROW, comp).json()
        c.post(f"{a.ats_url}/revoke", json={"jti": r["jti"]}, headers={"x-admin-key": os.environ["ATS_ADMIN_KEY"]})
        time.sleep(1.0)
        rev.append(authorize(r["access_token"], LEGIT_IBAN))
    results["revoked task token, in-scope call"] = {o: rev.count(o) for o in set(rev)}
    print(f"{'revoked task token, in-scope call':78s} {results['revoked task token, in-scope call']}")
    json.dump(results, open(a.out, "w"), indent=2)


if __name__ == "__main__":
    main()
