"""Optional Open Policy Agent PDP. Sends the same inputs as pdp.decide() to
policy/aztac.rego and maps the result back to a Decision."""

from __future__ import annotations

import httpx

from .pdp import Decision
from .tool_meta import TOOL_META


class OPAClient:
    def __init__(self, url: str | None):
        self.url = (url or "http://localhost:8181").rstrip("/")
        self.client = httpx.Client(timeout=2)

    def decide(self, details: list[dict], tool: str, args: dict, mode: str = "graduated") -> Decision:
        suite = next((e["locations"][0] for e in details if e.get("locations")), None)
        inp = {"details": details, "tool": tool, "args": args, "mode": mode,
               "meta": TOOL_META.get(suite, {}).get(tool, {"class": "read", "targets": [], "bounded": []})}
        r = self.client.post(f"{self.url}/v1/data/aztac/decision", json={"input": inp})
        r.raise_for_status()
        res = r.json()["result"]
        return Decision(res["outcome"], res.get("reason", ""), args=res.get("args"),
                        violations=res.get("violations", []))
