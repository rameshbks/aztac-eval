"""Policy decision point (PDP) and continuous-verification risk engine.

Decision outcomes (graduated enforcement):
  ALLOW    - call is inside the task scope
  NARROW   - call is executed with unapproved list targets removed (e.g. extra cc/bcc)
  STEP_UP  - call needs out-of-band human approval (unpinned target or bound exceeded)
  DENY     - call is outside the task scope
  REVOKED  - token has been revoked; every call is refused

Enforcement modes:
  strict     - every violation is DENY (no human in the loop)
  graduated  - pinned-target violations DENY, list violations NARROW where possible,
               unpinned targets and bound violations STEP_UP

The PDP is deterministic and depends only on the signed token and the call, never on
the agent's reasoning or on content the agent has read.
"""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass, field

from .tool_meta import as_values, meta_for, target_args

ALLOW, NARROW, STEP_UP, DENY, REVOKED = "ALLOW", "NARROW", "STEP_UP", "DENY", "REVOKED"


@dataclass
class Decision:
    outcome: str
    reason: str
    args: dict | None = None  # rewritten args for NARROW
    violations: list[str] = field(default_factory=list)


def _suite_of(details: list[dict]) -> str | None:
    for e in details:
        if e.get("locations"):
            return e["locations"][0]
    return None


def decide(details: list[dict], tool: str, args: dict, mode: str = "graduated") -> Decision:
    suite = _suite_of(details)
    entry = next((e for e in details if e.get("type") == "agent_tool_invocation" and tool in e.get("actions", [])), None)
    rp = next((e for e in details if e.get("type") == "agent_read_policy"), {"mode": "scoped"})
    cls = meta_for(suite, tool)["class"]

    if entry is None:
        if cls == "read" and rp.get("mode") == "suite":
            return Decision(ALLOW, "read tool permitted by suite read policy")
        if cls != "read" and rp.get("unlisted_write") == "step_up" and mode == "graduated":
            return Decision(STEP_UP, f"tool '{tool}' not in task scope; human approval required",
                            violations=["tool_unlisted"])
        return Decision(DENY, f"tool '{tool}' not in task scope", violations=["tool_out_of_scope"])

    if cls == "read":
        return Decision(ALLOW, "read tool in task scope")

    constraints = entry.get("constraints", {})
    bounds = entry.get("bounds", {})
    pinned_bad, unpinned, narrowable = [], [], {}

    for arg in target_args(suite, tool, args):
        vals = as_values(args.get(arg), arg)
        if not vals:
            continue
        if arg not in constraints:
            unpinned.append(arg)
            continue
        allowed = set(constraints[arg])
        bad = [v for v in vals if v not in allowed]
        if not bad:
            continue
        good = [v for v in vals if v in allowed]
        if isinstance(args.get(arg), list) and good:
            narrowable[arg] = [x for x in args[arg] if as_values(x, arg)[0] in allowed]
        else:
            pinned_bad.append(arg)

    over_bound = [a for a, b in bounds.items() if isinstance(args.get(a), (int, float)) and float(args[a]) > b]

    violations = ([f"target_outside_scope:{a}" for a in pinned_bad + list(narrowable)]
                  + [f"unpinned_target:{a}" for a in unpinned] + [f"bound_exceeded:{a}" for a in over_bound])
    if not violations:
        return Decision(ALLOW, "call within task scope")

    if mode == "strict":
        return Decision(DENY, "; ".join(violations), violations=violations)

    if pinned_bad:
        return Decision(DENY, "; ".join(violations), violations=violations)
    if unpinned or over_bound:
        return Decision(STEP_UP, "; ".join(violations), violations=violations)
    new_args = dict(args)
    new_args.update(narrowable)
    return Decision(NARROW, "; ".join(violations), args=new_args, violations=violations)


class RiskEngine:
    """Per-token risk score; crossing the threshold revokes the token (continuous verification)."""

    WEIGHTS = {DENY: 1.0, "STEP_UP_REJECTED": 1.0, NARROW: 0.5}

    def __init__(self, threshold: float = 2.0):
        self.threshold = threshold if threshold is not None else math.inf
        self.scores: dict[str, float] = {}
        self._lock = threading.Lock()

    def record(self, jti: str, event: str) -> bool:
        """Returns True if this event pushed the token over the revocation threshold."""
        w = self.WEIGHTS.get(event, 0.0)
        if w == 0.0:
            return False
        with self._lock:
            before = self.scores.get(jti, 0.0)
            self.scores[jti] = before + w
            return before < self.threshold <= self.scores[jti]
