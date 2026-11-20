# AZTAC evaluation harness

Code for the experiments in *Securing Agentic AI in the Enterprise: An Identity-Bound Zero Trust
Access Control Model for Autonomous AI Agents*.

AZTAC enforces least privilege for AI agents **at the identity layer, outside the agent runtime**:

1. **Scope compilation.** Before the agent reads any untrusted data, the trusted user request
   is compiled into a task scope expressed as RFC 9396 `authorization_details`: the permitted
   tools, pinned targets (recipients, accounts, URLs) and numeric bounds.
2. **Token exchange.** The Agent Token Service (ATS) exchanges the user's IdP token (Keycloak
   or Entra ID) for a short-lived, task-bound agent token using RFC 8693. The token carries
   the agent as `act.sub`.
3. **Enforcement at the resource gateway.** Every tool call is checked against the signed
   token by a deterministic policy decision point (Python, or OPA/Rego). The possible outcomes
   are ALLOW, NARROW (unapproved recipients stripped), STEP_UP (single-use human approval bound
   to the exact call), DENY or REVOKED.
4. **Continuous verification.** A per-token risk score revokes the token mid-task. Revocations
   propagate to every gateway through the ATS.

## Experiments

| ID | What it measures |
|---|---|
| E1 | Fully compromised agent (scripted) on all four AgentDojo v1.2.2 suites: 97 user tasks, 949 attack cases |
| E2 | Real LLM agents (gpt-4o-mini) against AgentDojo's built-in defenses and CaMeL, same tasks and attacks |
| E3 | Deliberately wrong scopes (too broad, too narrow) combined with attentive, approve-all and reject-all approvers, plus ablations |
| E4 | Gateway throughput and latency at 10, 50 and 100 concurrent agents |
| E5 | Revocation propagation across two gateways on separate hosts |

Operational metrics reported: decision latency, authorization round trip, token-exchange latency,
throughput, revocation delay, benign tasks blocked and step-ups per run.

## Layout

```
aztac/
  tool_meta.py              tool classes (read / write / egress), target and bounded args
  scope.py                  OracleCompiler, LLMCompiler (trusted prompt only), perturb() for E3
  tokens.py                 RS256 keys, task-bound agent tokens, verification (static keys or JWKS)
  pdp.py                    deterministic PDP + risk engine
  services.py               AgentTokenService (RFC 8693) and ResourceGateway (PEP)
  http_apps.py              FastAPI apps so ATS and gateway run on separate hosts
  opa.py, ../policy/aztac.rego   equivalent Rego PDP (tested against pdp.py)
  agentdojo_integration.py  session start, enforcing ToolsExecutor, approvers, scripted compromised agent
  scoring.py                official AgentDojo score + executed-action score
experiments/
  run_scripted.py           E1 (compromised agent), E3 (scope errors) - no API key
  run_llm.py                E2 real LLMs + attacks, AZTAC vs baselines
  loadtest.py               E4 throughput / latency
  revocation.py             E5 revocation propagation across gateways
  aggregate.py              tables (Markdown, CSV, LaTeX)
  run_all_scripted.sh       E1 + E3 + ablations in one go
deploy/                     Dockerfile, docker-compose (profiles per VM), Keycloak realm
tests/                      unit tests + Python-vs-OPA equivalence test
```

## Quick start (one machine, no API key)

```bash
pip install -r requirements.txt
pytest -q tests/                                  # set OPA_BIN=/path/to/opa to include the Rego test
bash experiments/run_all_scripted.sh              # ~15-30 min on 2 vCPU; writes results/table_*.md
```

## Multi-host deployment

Use at least three VMs in the same cloud region: **identity** (Keycloak + ATS), **enforcement**
(gateway + OPA), and **agents** (experiment runner). Add a fourth for a second gateway in E5.

```bash
cp deploy/.env.example deploy/.env      # set IDENTITY_HOST and the secrets
# identity VM
docker compose -f deploy/docker-compose.yml --env-file deploy/.env --profile identity up -d --build
# enforcement VM(s)
docker compose -f deploy/docker-compose.yml --env-file deploy/.env --profile enforcement up -d --build
```

On the agent VM, run any experiment with `--stack http --ats-url http://IDENTITY:8100 --gateway-url http://ENFORCE:8200`.
For the scripted runner, add `--keycloak-token-url http://IDENTITY:8080/realms/aztac/protocol/openid-connect/token`
so that subject tokens come from Keycloak. Set `KEYCLOAK_CLIENT_SECRET` and `KEYCLOAK_USER_PASSWORD` in the environment.

Record the VM types, region and measured RTT between VMs (`ping`) in the paper.

## Experiments

**E1: fully compromised agent** (`run_scripted.py`). For every user × injection task pair, a
scripted agent performs the legitimate task and every attacker action. This is the worst case
for an agent runtime that has been hijacked (successful injection, malicious plugin or
compromised framework). It is LLM-independent and deterministic.

**E2: real LLM agents** (`run_llm.py`) under AgentDojo's `important_instructions` attack.
It compares AZTAC with `none`, `spotlighting_with_delimiting`, `transformers_pi_detector`,
`repeat_user_prompt` and `tool_filter` (OpenAI models only). Run AZTAC with the **LLM compiler**
as the main result and the oracle compiler as an upper bound. The full benchmark is about
1,046 agent runs per defense. To control cost, start with `--suites banking slack` or
`--sample-pairs 100`, using a small model such as gpt-4o-mini. Results append, and `--resume`
continues an interrupted run.

**CaMeL baseline:** clone `github.com/google-research/camel-prompt-injection` (Python 3.10, `uv`),
copy `baselines/run_camel_safe.py` into it, put `OPENAI_API_KEY` in its `.env`, and run

```
uv run --env-file .env run_camel_safe.py --model openai:gpt-4o-mini-2024-07-18 \
    --suites banking slack travel workspace \
    --pairs-from <path>/results/e2_gpt4omini.jsonl --pairs-suites workspace
```

It uses CaMeL's own pipeline and log folder, runs the same workspace pairs as the AZTAC runs, and
records interpreter crashes in `results_camel/crashes.jsonl` instead of stopping (each counts as a
failed task with no attack success). Results are written to `results_camel/summary.json`.

**E3: scope errors × human behaviour** (`run_scripted.py --perturb ... --approver ...`).
Over-broad tools, unpinned targets and over-narrow scopes, each crossed with three human
approvers: oracle (attentive), approve_all (approval fatigue) and reject_all (no human
available).

**E4: load** (`loadtest.py --concurrency 10 100 500`). Run the load generator on its own VM.

**E5: revocation** (`revocation.py --gateway-urls GW1 GW2`, with `--trigger admin` and `--trigger risk`).
The expected worst case is the poll interval plus one round trip. Sweep `REVOCATION_POLL_MS`
(50/200/1000).

## Metrics reported by `aggregate.py`

Benign utility, utility under attack, ASR (official AgentDojo score), ASR (executed actions
only), percentage of benign runs with any blocked call (false blocks), step-ups per run,
percentage of runs revoked, PDP decision time (µs), authorization round trip (ms) and
token-exchange time (ms), each at p50/p95/p99.

## Points to state honestly in the paper

- **Oracle scope and oracle approver** are upper bounds and must be labelled as such. The
  LLM compiler is the realistic configuration.
- **Two ASR numbers.** A few AgentDojo injection tasks are scored from the *attempted*
  tool-call trace, so blocked calls still count as successes. Report both numbers and explain
  the difference.
- **Residual attacks** stay within approved tools and approved targets. Examples are a
  phishing link sent to a recipient the user also messages, or an extra calendar event
  without participants. Access control cannot stop content manipulation of this kind;
  data-flow defenses such as CaMeL are complementary. This is a limitation, and also an
  argument for layering defenses (see `aztac-llm+spotlighting`).
- **Revocation costs utility.** When the risk engine revokes a token, the remaining
  legitimate steps of the task fail. The ablation with `--risk-threshold inf` quantifies
  this trade-off.
- **Tool execution.** In AgentDojo the tools run in-process after the gateway authorizes the
  call. In production the gateway fronts the real resource servers.
- **Per-instance state.** Risk scores and approval challenges are held by each gateway
  instance; only revocations are shared.
- **Approvers are simulated.** A human study is future work.
