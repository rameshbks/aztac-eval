"""E4: throughput and latency of the ATS and gateway under concurrent agents.

python experiments/loadtest.py --ats-url http://ATS:8100 --gateway-url http://GW:8200 \
    --concurrency 10 100 500 --duration 30 --out results/e4_load.json

Each simulated agent obtains a task token (token exchange) and then issues a mix of
authorization requests (70% in-scope reads, 20% in-scope writes, 10% out-of-scope
writes) for the test duration. Risk-based revocation is avoided by giving every agent a
fresh token when it is revoked, so the measurement is of steady-state decisions.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import statistics
import time

import httpx

SCOPE = [
    {"type": "agent_tool_invocation", "locations": ["banking"], "actions": ["get_balance"]},
    {"type": "agent_tool_invocation", "locations": ["banking"], "actions": ["send_money"],
     "constraints": {"recipient": ["gb29nwbk60161331926819"]}, "bounds": {"amount": 500.0}},
    {"type": "agent_read_policy", "locations": ["banking"], "mode": "suite"},
]
CALLS = ([("get_balance", {})] * 7
         + [("send_money", {"recipient": "GB29NWBK60161331926819", "amount": 100, "subject": "x", "date": "d"})] * 2
         + [("send_money", {"recipient": "US133000000121212121212", "amount": 1, "subject": "x", "date": "d"})])
ERRORS = {}
GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"


def q(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p * (len(xs) - 1))))] if xs else float("nan")


async def get_token(c, ats, user_tok, i):
    t0 = time.perf_counter()
    r = await c.post(f"{ats}/token", data={"grant_type": GRANT, "subject_token": user_tok, "actor": f"agent://load/{i}",
                                           "task_id": f"load-{i}-{random.random()}",
                                           "authorization_details": json.dumps(SCOPE)})
    r.raise_for_status()
    return r.json()["access_token"], (time.perf_counter() - t0) * 1e3


async def agent(i, c, a, user_tok, stop, lat, ex_lat, outcomes):
    tok, ms = await get_token(c, a.ats_url, user_tok, i)
    ex_lat.append(ms)
    rng = random.Random(i)
    while time.perf_counter() < stop:
        fn, args = rng.choice(CALLS)
        t0 = time.perf_counter()
        try:
            r = await c.post(f"{a.gateway_url}/authorize", json={"token": tok, "tool": fn, "args": args})
        except httpx.HTTPError as e:
            outcomes["NET_" + type(e).__name__] = outcomes.get("NET_" + type(e).__name__, 0) + 1
            await asyncio.sleep(0.2)
            continue
        if r.status_code != 200:
            k = f"HTTP_{r.status_code}"
            outcomes[k] = outcomes.get(k, 0) + 1
            ERRORS.setdefault(k, r.text[:300])
            await asyncio.sleep(0.2)
            continue
        lat.append((time.perf_counter() - t0) * 1e3)
        o = r.json()["outcome"]
        outcomes[o] = outcomes.get(o, 0) + 1
        if o == "REVOKED" or r.json().get("revoked_now"):
            tok, ms = await get_token(c, a.ats_url, user_tok, i)
            ex_lat.append(ms)


async def run_level(a, n):
    limits = httpx.Limits(max_connections=n + 10, max_keepalive_connections=n + 10)
    async with httpx.AsyncClient(timeout=30, limits=limits) as c:
        user_tok = (await c.post(f"{a.ats_url}/dev/user-token", json={"username": "alice"})).json()["access_token"] \
            if not a.subject_token else a.subject_token
        lat, ex_lat, outcomes = [], [], {}
        start = time.perf_counter()
        stop = start + a.duration
        await asyncio.gather(*[agent(i, c, a, user_tok, stop, lat, ex_lat, outcomes) for i in range(n)])
        el = time.perf_counter() - start
    return {"concurrency": n, "duration_s": el, "requests": len(lat), "throughput_rps": len(lat) / el,
            "authz_ms_p50": q(lat, .5), "authz_ms_p95": q(lat, .95), "authz_ms_p99": q(lat, .99),
            "authz_ms_mean": statistics.fmean(lat) if lat else None,
            "token_exchanges": len(ex_lat), "exchange_ms_p50": q(ex_lat, .5), "exchange_ms_p95": q(ex_lat, .95),
            "exchange_ms_p99": q(ex_lat, .99), "outcomes": outcomes,
            "errors": sum(v for k, v in outcomes.items() if k.startswith(("HTTP_", "NET_")))}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ats-url", default="http://127.0.0.1:8100")
    p.add_argument("--gateway-url", default="http://127.0.0.1:8200")
    p.add_argument("--subject-token", default=os.getenv("SUBJECT_TOKEN"), help="Keycloak user token (else dev IdP)")
    p.add_argument("--concurrency", nargs="+", type=int, default=[10, 100])
    p.add_argument("--duration", type=float, default=20)
    p.add_argument("--out", default="results/e4_load.json")
    a = p.parse_args()
    results = []
    for n in a.concurrency:
        r = asyncio.run(run_level(a, n))
        results.append(r)
        print(json.dumps({k: (round(v, 2) if isinstance(v, float) else v) for k, v in r.items()}), flush=True)
        if ERRORS:
            print("non-200 samples:", json.dumps(ERRORS)[:800], flush=True)
            ERRORS.clear()
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump(results, open(a.out, "w"), indent=2)


if __name__ == "__main__":
    main()
