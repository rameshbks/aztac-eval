"""E1 / E3: fully-compromised agent on all AgentDojo suites (no LLM, no API key).

E1  python experiments/run_scripted.py --out results/e1.jsonl
    Runs every (user task x injection task) pair with a scripted agent that executes
    both the legitimate task and every attacker action, plus every user task with no
    attack (benign utility / false blocks). Compares no defense vs AZTAC.

E3  python experiments/run_scripted.py --perturb over_broad_tools --out results/e3_broad.jsonl
    Same, but with deliberate scope-compilation errors (see aztac/scope.py:perturb).

Add --stack http --ats-url ... --gateway-url ... to route every decision across hosts.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
import warnings

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
warnings.filterwarnings("ignore")

from agentdojo.task_suite.load_suites import get_suites

from aztac.agentdojo_integration import APPROVERS, AZTACContext, scripted_pipeline
from aztac.clients import HTTPStack, InProcStack
from aztac.scope import OracleCompiler, perturb
from aztac.scoring import run_pair


def make_stack(a):
    if a.stack == "http":
        kc = None
        if a.keycloak_token_url:
            kc = dict(token_url=a.keycloak_token_url, client_id=a.keycloak_client_id,
                      client_secret=os.getenv("KEYCLOAK_CLIENT_SECRET", ""), username=a.keycloak_user,
                      password=os.getenv("KEYCLOAK_USER_PASSWORD", ""))
        return HTTPStack(a.ats_url, a.gateway_url, keycloak=kc)
    return InProcStack(mode=a.mode, risk_threshold=a.risk_threshold)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--benchmark-version", default="v1.2.2")
    p.add_argument("--suites", nargs="*", default=["banking", "slack", "travel", "workspace"])
    p.add_argument("--defenses", nargs="*", default=["none", "aztac"])
    p.add_argument("--mode", default="graduated", choices=["graduated", "strict"])
    p.add_argument("--approver", default="oracle", choices=list(APPROVERS))
    p.add_argument("--risk-threshold", type=float, default=2.0)
    p.add_argument("--read-mode", default="suite", choices=["suite", "scoped"])
    p.add_argument("--perturb", default="none",
                   choices=["none", "over_broad_tools", "over_broad_targets", "over_narrow", "static_role"])
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--limit-user-tasks", type=int, default=None)
    p.add_argument("--stack", default="inproc", choices=["inproc", "http"])
    p.add_argument("--ats-url", default="http://localhost:8100")
    p.add_argument("--gateway-url", default="http://localhost:8200")
    p.add_argument("--keycloak-token-url", default=None)
    p.add_argument("--keycloak-client-id", default="agent-platform")
    p.add_argument("--keycloak-user", default="alice")
    p.add_argument("--out", required=True)
    a = p.parse_args()

    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    suites = get_suites(a.benchmark_version)
    rng = random.Random(a.seed)
    stack = make_stack(a) if "aztac" in a.defenses else None
    config = {k: v for k, v in vars(a).items() if k not in ("out",)}

    with open(a.out, "w") as f:
        for sname in a.suites:
            suite = suites[sname]
            user_tasks = list(suite.user_tasks.values())[: a.limit_user_tasks]
            inj_tasks = [None] + list(suite.injection_tasks.values())
            for defense in a.defenses:
                ctx = None
                if defense == "aztac":
                    pf = None
                    if a.perturb != "none":
                        pf = lambda s, _suite=suite: perturb(s, _suite, a.perturb, rng)
                    ctx = AZTACContext(stack=stack, compiler=OracleCompiler(a.read_mode),
                                       approver=APPROVERS[a.approver](), suite=suite, perturb_fn=pf)
                pipeline, agent = scripted_pipeline(ctx)
                n = 0
                t_start = time.time()
                for ut in user_tasks:
                    for it in inj_tasks:
                        agent.set_tasks(ut, it)
                        if ctx:
                            ctx.begin(ut)
                        try:
                            score, _ = run_pair(suite, pipeline, ut, it, {})
                            err = None
                        except Exception as e:  # keep going; record the failure
                            score, err = {"utility": False, "attack_success": None,
                                          "attack_success_executed": None}, repr(e)[:300]
                        row = {"suite": sname, "defense": defense, "user_task": ut.ID,
                               "injection_task": it.ID if it else None, **score, "error": err,
                               "events": ctx.events if ctx else [], "session": ctx.session if ctx else {},
                               "config": config}
                        f.write(json.dumps(row) + "\n")
                        n += 1
                print(f"{sname:10s} {defense:6s} {n:4d} runs in {time.time() - t_start:6.1f}s", flush=True)


if __name__ == "__main__":
    main()
