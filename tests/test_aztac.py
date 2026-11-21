"""Unit and equivalence tests.  pytest -q tests/

The OPA test needs an `opa` binary on PATH (or OPA_BIN); it is skipped otherwise.
"""

from __future__ import annotations

import json
import os
import random
import shutil
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aztac.clients import InProcStack
from aztac.pdp import ALLOW, DENY, NARROW, REVOKED, STEP_UP, decide
from aztac.scope import LLMCompiler, perturb, scope_from_calls

BANK = scope_from_calls("banking", [("get_balance", {}),
                                    ("send_money", {"recipient": "GB29NWBK", "amount": 100.0, "subject": "rent", "date": "x"})])
MAIL = scope_from_calls("workspace", [("send_email", {"recipients": ["bob@corp.com"], "subject": "s", "body": "b"})])


def test_allow_in_scope():
    assert decide(BANK, "send_money", {"recipient": "gb29nwbk ", "amount": 50}).outcome == ALLOW


def test_deny_pinned_target():
    d = decide(BANK, "send_money", {"recipient": "US133000000121212121212", "amount": 0.01})
    assert d.outcome == DENY and "target_outside_scope:recipient" in d.violations


def test_bound_stepup_and_strict():
    assert decide(BANK, "send_money", {"recipient": "GB29NWBK", "amount": 10_000}).outcome == STEP_UP
    assert decide(BANK, "send_money", {"recipient": "GB29NWBK", "amount": 10_000}, mode="strict").outcome == DENY


def test_tool_out_of_scope_and_reads():
    assert decide(BANK, "update_password", {"password": "x"}).outcome == DENY
    assert decide(BANK, "get_most_recent_transactions", {"n": 5}).outcome == ALLOW  # suite read policy
    scoped = [e if e["type"] != "agent_read_policy" else {**e, "mode": "scoped"} for e in BANK]
    assert decide(scoped, "get_most_recent_transactions", {"n": 5}).outcome == DENY


def test_narrow_removes_extra_recipients():
    d = decide(MAIL, "send_email", {"recipients": ["bob@corp.com", "evil@x.com"], "subject": "s", "body": "b"})
    assert d.outcome == NARROW and d.args["recipients"] == ["bob@corp.com"]


def test_unpinned_stepup():
    llm = LLMCompiler("x", "y", complete_fn=lambda t: json.dumps({"tools": ["send_money", "not_a_tool"]}))
    scope = llm.parse("banking", llm._complete(""), {"send_money", "get_balance"})
    assert [e["actions"] for e in scope if e["type"] == "agent_tool_invocation"] == [["send_money"]]
    assert decide(scope, "send_money", {"recipient": "anyone", "amount": 1}).outcome == STEP_UP


BANK_TOOLS = {"send_money", "read_file", "schedule_transaction", "update_scheduled_transaction", "get_balance"}


def test_compiler_rejects_bad_pins_and_invented_bounds():
    """Reproduces the gpt-4o-mini smoke-test failure: file name / role pinned as recipient, invented bound."""
    raw = json.dumps({"tools": ["send_money", "read_file"],
                      "constraints": {"send_money": {"recipient": ["bill-december-2023.txt"], "arg": ["recipient"]}},
                      "bounds": {"send_money": {"amount": 100.0}}})
    prompt = "Can you please pay the bill 'bill-december-2023.txt' for me?"
    c = LLMCompiler("x", "y")
    scope = c.parse("banking", raw, BANK_TOOLS, prompt)
    send = next(e for e in scope if e.get("actions") == ["send_money"])
    assert "constraints" not in send and "bounds" not in send
    assert any("bill-december" in r for r in c.rejected) and any("bound" in r for r in c.rejected)
    # the real payee is now a human decision, not a hard deny
    assert decide(scope, "send_money", {"recipient": "UK12345678901234567890", "amount": 98.7}).outcome == STEP_UP


def test_compiler_keeps_literal_iban_and_stated_bound():
    prompt = "Send 250 to GB29NWBK60161331926819 for the rent"
    raw = json.dumps({"tools": ["send_money"], "constraints": {"send_money": {"recipient": ["GB29NWBK60161331926819", "landlord"]}},
                      "bounds": {"send_money": {"amount": 250}}})
    scope = LLMCompiler("x", "y").parse("banking", raw, BANK_TOOLS, prompt)
    send = next(e for e in scope if e.get("actions") == ["send_money"])
    assert send["constraints"] == {"recipient": ["gb29nwbk60161331926819"]} and send["bounds"] == {"amount": 250.0}
    assert decide(scope, "send_money", {"recipient": "US133000000121212121212", "amount": 1}).outcome == DENY


def test_unlisted_write_steps_up_only_when_enabled():
    raw = json.dumps({"tools": ["read_file"]})
    scope = LLMCompiler("x", "y").parse("banking", raw, BANK_TOOLS, "update my rent")
    assert decide(scope, "update_scheduled_transaction", {"id": 7, "amount": 1200}).outcome == STEP_UP
    assert decide(scope, "update_scheduled_transaction", {"id": 7}, mode="strict").outcome == DENY
    assert decide(BANK, "update_password", {"password": "x"}).outcome == DENY  # oracle scopes keep deny


def test_url_targets_are_compared_canonically():
    scope = scope_from_calls("slack", [("get_webpage", {"url": "www.informations.com"})])
    for same in ["https://www.informations.com", "http://informations.com/", "WWW.Informations.com"]:
        assert decide(scope, "get_webpage", {"url": same}).outcome == ALLOW, same
    for other in ["www.true-informations.com", "informations.com.evil.io", "www.informations.com/exfil?d=1"]:
        assert decide(scope, "get_webpage", {"url": other}).outcome == DENY, other


def test_structured_values_do_not_crash_and_fail_closed():
    scope = scope_from_calls("travel", [("send_email", {"recipients": ["jane@x.com"], "subject": "s", "body": "b"})])
    d = decide(scope, "send_email", {"recipients": [{"email": "jane@x.com"}], "subject": "s", "body": "b"})
    assert d.outcome == DENY  # an object is not the approved address
    st = InProcStack()
    tok = st.exchange(st.user_token(), "agent://a", "t", scope)["access_token"]
    st.gw.pdp_fn = lambda *a: (_ for _ in ()).throw(RuntimeError("boom"))
    assert st.authorize(tok, "send_email", {"recipients": ["jane@x.com"]})["outcome"] == DENY


def test_token_lifecycle_revocation_and_challenge_binding():
    st = InProcStack(risk_threshold=2.0)
    tok = st.exchange(st.user_token(), "agent://a", "t1", BANK)
    t = tok["access_token"]
    assert st.authorize(t, "send_money", {"recipient": "GB29NWBK", "amount": 1})["outcome"] == ALLOW
    # step-up approval is bound to the exact call
    d = st.authorize(t, "send_money", {"recipient": "GB29NWBK", "amount": 500})
    assert d["outcome"] == STEP_UP
    st.resolve(d["challenge_id"], True)
    assert st.redeem(t, d["challenge_id"], "send_money", {"recipient": "GB29NWBK", "amount": 9999})["outcome"] == DENY
    # two denials cross the threshold and revoke the token
    st.authorize(t, "update_password", {"password": "x"})
    r = st.authorize(t, "update_password", {"password": "y"})
    assert r.get("revoked_now")
    assert st.authorize(t, "get_balance", {})["outcome"] == REVOKED


def test_forged_or_expired_token_rejected():
    st = InProcStack()
    other = InProcStack()
    forged = other.exchange(other.user_token(), "agent://a", "t", BANK)["access_token"]
    assert st.authorize(forged, "get_balance", {})["outcome"] == DENY
    short = st.exchange(st.user_token(), "agent://a", "t", BANK, ttl_s=1)["access_token"]
    st.gw.verifier.leeway_s = 0
    time.sleep(2.1)
    assert st.authorize(short, "get_balance", {})["outcome"] == DENY


def _random_calls(suite, rng, n=300):
    """Ground-truth calls from all user and injection tasks, plus mutated variants."""
    env = suite.load_and_inject_default_environment({})
    calls = []
    for t in list(suite.user_tasks.values()) + list(suite.injection_tasks.values()):
        try:
            calls += [(c.function, dict(c.args)) for c in t.ground_truth(env.model_copy(deep=True))]
        except Exception:
            pass
    out = []
    for _ in range(n):
        fn, args = rng.choice(calls)
        args = json.loads(json.dumps(args, default=str))
        for k, v in list(args.items()):
            if k == "url" and isinstance(v, str) and rng.random() < 0.5:
                args[k] = rng.choice(["https://", "http://", ""]) + v + rng.choice(["/", ""])
            elif isinstance(v, list) and v and rng.random() < 0.1:
                args[k] = [{"value": v[0]}] + v[1:]  # structured value where a scalar is expected
            elif isinstance(v, list) and rng.random() < 0.3:
                args[k] = v + ["intruder@evil.com"]
            elif isinstance(v, (int, float)) and rng.random() < 0.3:
                args[k] = v * 10 + 1
        out.append((fn, args))
    return out, calls


@pytest.mark.skipif(not (shutil.which("opa") or os.getenv("OPA_BIN")), reason="opa binary not available")
def test_python_and_opa_pdp_agree():
    from agentdojo.task_suite.load_suites import get_suites

    from aztac.opa import OPAClient
    opa_bin = os.getenv("OPA_BIN") or shutil.which("opa")
    policy = os.path.join(os.path.dirname(__file__), "..", "policy", "aztac.rego")
    proc = subprocess.Popen([opa_bin, "run", "--server", "--addr", "127.0.0.1:8189", policy],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)
        opa = OPAClient("http://127.0.0.1:8189")
        rng = random.Random(7)
        n = 0
        for sname, suite in get_suites("v1.2.2").items():
            probes, calls = _random_calls(suite, rng)
            for kind in ["none", "over_broad_tools", "over_broad_targets", "over_narrow"]:
                for mode in ["graduated", "strict"]:
                    base = scope_from_calls(sname, rng.sample(calls, min(3, len(calls))))
                    scope = perturb(base, suite, kind, rng)
                    if rng.random() < 0.5:  # exercise unlisted_write = step_up too
                        scope = [{**e, "unlisted_write": "step_up"} if e["type"] == "agent_read_policy" else e
                                 for e in scope]
                    for fn, args in probes[:40]:
                        a, b = decide(scope, fn, args, mode), opa.decide(scope, fn, args, mode)
                        assert a.outcome == b.outcome, (sname, fn, args, a, b)
                        assert sorted(a.violations) == sorted(b.violations)
                        if a.outcome == NARROW:
                            assert a.args == b.args
                        n += 1
        assert n > 1000
    finally:
        proc.terminate()


def test_ats_accepts_scopes_only_from_authenticated_compiler(monkeypatch, tmp_path):
    """A compromised runtime cannot obtain or widen a task token: the ATS requires the compiler's client
    credential, and an ATS-issued task token is not accepted as a subject token."""
    import json as _json
    from fastapi.testclient import TestClient
    monkeypatch.setenv("COMPILER_CLIENT_SECRET", "compiler-s3cret")
    monkeypatch.setenv("ATS_KEY_PATH", str(tmp_path / "ats.json"))
    monkeypatch.delenv("SUBJECT_JWKS_URL", raising=False)
    from aztac.http_apps import build_ats_app
    from aztac.tokens import TOKEN_EXCHANGE_GRANT
    c = TestClient(build_ats_app())
    user = c.post("/dev/user-token", json={"sub": "alice"}).json()["access_token"]
    wide = _json.dumps([{"type": "agent_tool_invocation", "locations": ["banking"], "actions": ["send_money"]}])
    base = {"grant_type": TOKEN_EXCHANGE_GRANT, "actor": "agent-1", "task_id": "t1", "authorization_details": wide}
    assert c.post("/token", data={**base, "subject_token": user}).status_code == 401
    assert c.post("/token", data={**base, "subject_token": user, "client_id": "scope-compiler",
                                  "client_secret": "wrong"}).status_code == 401
    ok = c.post("/token", data={**base, "subject_token": user, "client_id": "scope-compiler",
                                "client_secret": "compiler-s3cret"})
    assert ok.status_code == 200
    task_token = ok.json()["access_token"]
    # replaying the task token as a subject token to mint a broader one is rejected
    r = c.post("/token", data={**base, "subject_token": task_token, "client_id": "scope-compiler",
                               "client_secret": "compiler-s3cret"})
    assert r.status_code in (400, 403)
