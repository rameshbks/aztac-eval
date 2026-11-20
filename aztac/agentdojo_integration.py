"""AgentDojo integration: session start (token exchange), enforcing tool executor,
simulated human approvers, and a scripted fully-compromised agent."""

from __future__ import annotations

import time
import uuid
from ast import literal_eval
from collections.abc import Sequence
from dataclasses import dataclass, field

from agentdojo.agent_pipeline import AgentPipeline, InitQuery, SystemMessage, ToolsExecutionLoop, ToolsExecutor
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionsRuntime
from agentdojo.types import ChatAssistantMessage, ChatMessage, ChatToolResultMessage, text_content_block_from_string

from .pdp import ALLOW, NARROW, STEP_UP, decide
from .scope import OracleCompiler


# ----------------------------------------------------------------- approvers
class OracleApprover:
    """Attentive human: approves exactly the calls the real task needs (upper bound)."""
    name = "oracle"

    def __init__(self):
        self.reference = None

    def set_task(self, suite_name, user_task, env):
        self.reference = OracleCompiler(read_mode="suite").compile(suite_name, user_task, env)

    def approve(self, tool, args) -> bool:
        return decide(self.reference, tool, args, mode="strict").outcome == ALLOW


class ApproveAll:
    """Rubber-stamp human (approval fatigue): lower bound."""
    name = "approve_all"

    def set_task(self, *a):
        pass

    def approve(self, tool, args) -> bool:
        return True


class RejectAll:
    """No human available: every step-up fails closed."""
    name = "reject_all"

    def set_task(self, *a):
        pass

    def approve(self, tool, args) -> bool:
        return False


APPROVERS = {"oracle": OracleApprover, "approve_all": ApproveAll, "reject_all": RejectAll}


# ------------------------------------------------------------------ context
@dataclass
class AZTACContext:
    stack: object                      # InProcStack or HTTPStack
    compiler: object                   # OracleCompiler / LLMCompiler
    approver: object
    suite: object                      # agentdojo TaskSuite
    agent_id: str = "agent://enterprise/assistant-01"
    perturb_fn: object = None          # optional scope perturbation for E3
    user_task: object = None
    token: str | None = None
    jti: str | None = None
    scope: list | None = None
    events: list = field(default_factory=list)
    session: dict = field(default_factory=dict)

    def begin(self, user_task):
        self.user_task, self.token, self.jti, self.scope = user_task, None, None, None
        self.events, self.session = [], {}


class AZTACSessionStart(BasePipelineElement):
    """Compiles the task scope from trusted inputs and exchanges it for a task-bound token.
    Runs before the agent reads any untrusted data."""

    def __init__(self, ctx: AZTACContext):
        self.ctx = ctx

    def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):
        ctx = self.ctx
        t0 = time.perf_counter()
        kwargs = {"suite": ctx.suite} if getattr(ctx.compiler, "name", "") == "llm" else {}
        scope = ctx.compiler.compile(ctx.suite.name, ctx.user_task, env, prompt=query, **kwargs)
        if ctx.perturb_fn is not None:
            scope = ctx.perturb_fn(scope)
        t1 = time.perf_counter()
        user_tok = ctx.stack.user_token()
        res = ctx.stack.exchange(user_tok, ctx.agent_id, f"task-{uuid.uuid4().hex[:8]}", scope)
        t2 = time.perf_counter()
        ctx.approver.set_task(ctx.suite.name, ctx.user_task, env)
        ctx.token, ctx.jti, ctx.scope = res["access_token"], res["jti"], scope
        ctx.session = {"compile_ms": (t1 - t0) * 1e3, "exchange_ms": (t2 - t1) * 1e3,
                       "scope_tools": [e["actions"][0] for e in scope if e["type"] == "agent_tool_invocation"]}
        return query, runtime, env, messages, extra_args


class AZTACToolsExecutor(ToolsExecutor):
    """Drop-in replacement for AgentDojo's ToolsExecutor that asks the gateway first."""

    def __init__(self, ctx: AZTACContext, tool_output_formatter=tool_result_to_str):
        super().__init__(tool_output_formatter)
        self.ctx = ctx

    def _result(self, tool_call, content="", error=None):
        return ChatToolResultMessage(role="tool", content=[text_content_block_from_string(content)],
                                     tool_call_id=tool_call.id, tool_call=tool_call, error=error)

    def query(self, query, runtime: FunctionsRuntime, env: Env = EmptyEnv(), messages: Sequence[ChatMessage] = [],
              extra_args: dict = {}):
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1]["tool_calls"]:
            return query, runtime, env, messages, extra_args
        ctx = self.ctx
        results = []
        for tool_call in messages[-1]["tool_calls"]:
            if tool_call.function not in (t.name for t in runtime.functions.values()):
                results.append(self._result(tool_call, error=f"Invalid tool {tool_call.function} provided."))
                continue
            for k, v in tool_call.args.items():
                if isinstance(v, str) and is_string_list(v):
                    tool_call.args[k] = literal_eval(v)
            args = dict(tool_call.args)

            t0 = time.perf_counter()
            d = ctx.stack.authorize(ctx.token, tool_call.function, args)
            rtt_ms = (time.perf_counter() - t0) * 1e3
            ev = {"tool": tool_call.function, "outcome": d["outcome"], "violations": d.get("violations", []),
                  "rtt_ms": rtt_ms, "decision_us": d.get("decision_us"), "final": None,
                  "revoked_now": d.get("revoked_now", False)}

            if d["outcome"] == NARROW:
                args = d["args"]
                tool_call.args.clear()
                tool_call.args.update(args)
            if d["outcome"] == STEP_UP:
                try:
                    approved = ctx.approver.approve(tool_call.function, args)
                except Exception:  # an approver that cannot judge the call rejects it
                    approved = False
                r = ctx.stack.resolve(d["challenge_id"], approved)
                ev["human"] = "approved" if approved else "rejected"
                ev["revoked_now"] = ev["revoked_now"] or r.get("revoked_now", False)
                if approved:
                    d = ctx.stack.redeem(ctx.token, d["challenge_id"], tool_call.function, args)

            if d["outcome"] in (ALLOW, NARROW):
                ev["final"] = "executed"
                out, err = runtime.run_function(env, tool_call.function, args)
                results.append(self._result(tool_call, self.output_formatter(out), err))
            else:
                ev["final"] = "blocked"
                results.append(self._result(
                    tool_call, error=f"Access denied by enterprise policy ({d['outcome']}): {d['reason']}"))
            ctx.events.append(ev)
        return query, runtime, env, [*messages, *results], extra_args


# ------------------------------------------------------- scripted compromised agent
class ScriptedCompromisedAgent(BasePipelineElement):
    """Deterministic worst-case agent: performs the user task AND every attacker action.

    Models a fully hijacked agent runtime (successful injection, malicious plugin or
    compromised framework). Defenses that live inside the agent runtime (prompt
    filtering, detectors, planners) have no effect by construction; only enforcement
    outside the runtime can stop these calls. Independent of any LLM.
    """

    name = "scripted-compromised"

    def __init__(self, executor: ToolsExecutor):
        self.executor = executor
        self.user_task = None
        self.injection_task = None

    def set_tasks(self, user_task, injection_task):
        self.user_task, self.injection_task = user_task, injection_task

    def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):
        snap = env.model_copy(deep=True)
        user_calls = list(self.user_task.ground_truth(snap))
        evil_calls = list(self.injection_task.ground_truth(snap)) if self.injection_task else []
        plan = user_calls[:1] + evil_calls + user_calls[1:]
        msgs = list(messages)
        for i, c in enumerate(plan):
            call = FunctionCall(function=c.function, args=dict(c.args), id=f"call_{i}")
            msgs.append(ChatAssistantMessage(role="assistant", content=[text_content_block_from_string("")],
                                             tool_calls=[call]))
            query, runtime, env, msgs, extra_args = self.executor.query(query, runtime, env, msgs, extra_args)
        msgs.append(ChatAssistantMessage(role="assistant", tool_calls=None,
                                         content=[text_content_block_from_string(self.user_task.GROUND_TRUTH_OUTPUT)]))
        return query, runtime, env, msgs, extra_args


# ------------------------------------------------------------- pipeline builders
def scripted_pipeline(ctx: AZTACContext | None):
    executor = AZTACToolsExecutor(ctx) if ctx else ToolsExecutor()
    agent = ScriptedCompromisedAgent(executor)
    elems = [InitQuery()] + ([AZTACSessionStart(ctx)] if ctx else []) + [agent]
    p = AgentPipeline(elems)
    p.name = "scripted-aztac" if ctx else "scripted-none"
    return p, agent


def llm_pipeline(llm: BasePipelineElement, system_message: str, ctx: AZTACContext | None, name: str):
    executor = AZTACToolsExecutor(ctx) if ctx else ToolsExecutor()
    elems = [SystemMessage(system_message), InitQuery()]
    if ctx:
        elems.append(AZTACSessionStart(ctx))
    elems += [llm, ToolsExecutionLoop([executor, llm])]
    p = AgentPipeline(elems)
    p.name = name
    return p
