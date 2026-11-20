"""E5: time from a revocation decision to enforcement at every gateway.

python experiments/revocation.py --ats-url http://ATS:8100 \
    --gateway-urls http://GW1:8200 http://GW2:8200 --trials 50 --out results/e5_revocation.json

Per trial: obtain a token, keep probing every gateway with an in-scope call every
--probe-ms, revoke the token at the ATS (admin revocation, e.g. by the SOC), and record
for each gateway the time until its first REVOKED answer. With a revocation poll
interval P, the expected worst case is about P plus one network round trip.

--trigger risk instead makes the agent issue out-of-scope calls at the FIRST gateway
until its risk engine revokes the token, and measures propagation to the others.
"""

from __future__ import annotations

import argparse
import json
import os
import threading
import time

import httpx

SCOPE = [{"type": "agent_tool_invocation", "locations": ["banking"], "actions": ["get_balance"]},
         {"type": "agent_read_policy", "locations": ["banking"], "mode": "scoped"}]
GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"


def q(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p * (len(xs) - 1))))] if xs else None


def trial(a, c, user_tok, k):
    tok = c.post(f"{a.ats_url}/token", data={"grant_type": GRANT, "subject_token": user_tok, "actor": "agent://rev",
                                             "task_id": f"rev-{k}", "authorization_details": json.dumps(SCOPE)}).json()
    token = tok["access_token"]
    first = {}
    t_revoke = [None]
    stop = threading.Event()

    def probe(url):
        cc = httpx.Client(timeout=5)
        while not stop.is_set():
            r = cc.post(f"{url}/authorize", json={"token": token, "tool": "get_balance", "args": {}}).json()
            if r["outcome"] == "REVOKED" and t_revoke[0] is not None and url not in first:
                first[url] = (time.perf_counter() - t_revoke[0]) * 1e3
                return
            time.sleep(a.probe_ms / 1000)

    ths = [threading.Thread(target=probe, args=(u,)) for u in a.gateway_urls]
    for t in ths:
        t.start()
    time.sleep(0.3)
    if a.trigger == "admin":
        t_revoke[0] = time.perf_counter()
        c.post(f"{a.ats_url}/revoke", json={"jti": tok["jti"]}, headers={"x-admin-key": a.admin_key})
    else:
        gw0 = a.gateway_urls[0]
        while True:
            r = c.post(f"{gw0}/authorize", json={"token": token, "tool": "update_password",
                                                 "args": {"password": "x"}}).json()
            if r.get("revoked_now"):
                t_revoke[0] = time.perf_counter()
                break
    deadline = time.time() + 10
    while len(first) < len(a.gateway_urls) and time.time() < deadline:
        time.sleep(0.01)
    stop.set()
    for t in ths:
        t.join()
    return first


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ats-url", default="http://127.0.0.1:8100")
    p.add_argument("--gateway-urls", nargs="+", default=["http://127.0.0.1:8200"])
    p.add_argument("--admin-key", default=os.getenv("ATS_ADMIN_KEY", "admin-secret"))
    p.add_argument("--subject-token", default=os.getenv("SUBJECT_TOKEN"))
    p.add_argument("--trigger", default="admin", choices=["admin", "risk"])
    p.add_argument("--trials", type=int, default=30)
    p.add_argument("--probe-ms", type=float, default=5)
    p.add_argument("--out", default="results/e5_revocation.json")
    a = p.parse_args()
    c = httpx.Client(timeout=10)
    user_tok = a.subject_token or c.post(f"{a.ats_url}/dev/user-token", json={"username": "alice"}).json()["access_token"]
    per_gw = {u: [] for u in a.gateway_urls}
    for k in range(a.trials):
        res = trial(a, c, user_tok, k)
        for u in a.gateway_urls:
            per_gw[u].append(res.get(u))
    summary = {u: {"n": len(v), "missed": sum(x is None for x in v),
                   "ms_p50": q([x for x in v if x is not None], .5), "ms_p95": q([x for x in v if x is not None], .95),
                   "ms_max": max([x for x in v if x is not None], default=None)} for u, v in per_gw.items()}
    print(json.dumps(summary, indent=2))
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump({"config": vars(a), "summary": summary, "raw": per_gw}, open(a.out, "w"), indent=2)


if __name__ == "__main__":
    main()
