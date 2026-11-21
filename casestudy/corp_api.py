"""A small enterprise REST API (mail, files, payments) for the AZTAC case study.

It accepts a tool call only with one of two caller credentials:
  * CORP_GATEWAY_SECRET - held only by the AZTAC gateway, which forwards calls it has authorized;
  * CORP_STANDING_KEY   - a standing API key, as agents hold today; used only by the no-defense baseline.
The agent in the AZTAC configuration holds neither, so it can reach this API only through the gateway.

Run:  CORP_GATEWAY_SECRET=... CORP_STANDING_KEY=... CORP_ADMIN_KEY=... \
      python3 -m uvicorn casestudy.corp_api:app --host 0.0.0.0 --port 9000
"""
import copy
import os
import threading

from fastapi import FastAPI, Header, HTTPException

from casestudy.scenarios import seed

GATEWAY_SECRET = os.environ.get("CORP_GATEWAY_SECRET", "gateway-secret")
STANDING_KEY = os.environ.get("CORP_STANDING_KEY", "standing-key")
ADMIN_KEY = os.environ.get("CORP_ADMIN_KEY", "admin-key")

app = FastAPI(title="Corp API (case study)")
_lock = threading.Lock()
STATE = {"data": seed(None), "audit": []}


def _check(key):
    if key == GATEWAY_SECRET:
        return "gateway"
    if key == STANDING_KEY:
        return "standing-key"
    raise HTTPException(401, "caller not authorized")


@app.post("/tools/{tool}")
def call_tool(tool: str, args: dict, x_caller_key: str = Header(default="")):
    caller = _check(x_caller_key)
    d = STATE["data"]
    with _lock:
        STATE["audit"].append({"caller": caller, "tool": tool, "args": args})
        if tool == "list_inbox":
            return {"messages": d["inbox"]}
        if tool == "read_file":
            name = args.get("name", "")
            if name not in d["files"]:
                raise HTTPException(404, f"no file {name}")
            return {"name": name, "content": d["files"][name]}
        if tool == "list_transactions":
            return {"transactions": d["transactions"]}
        if tool == "send_email":
            to = args.get("to", "")
            d["sent"].append({"to": to if isinstance(to, str) else ",".join(to), "subject": args.get("subject", ""),
                              "body": args.get("body", "")})
            return {"status": "sent"}
        if tool == "share_file":
            d["shares"].append({"name": args.get("name", ""), "email": args.get("email", "")})
            return {"status": "shared"}
        if tool == "transfer":
            d["transfers"].append({"iban": str(args.get("iban", "")), "amount": args.get("amount", 0),
                                   "memo": args.get("memo", "")})
            return {"status": "transferred"}
    raise HTTPException(404, f"unknown tool {tool}")


@app.post("/admin/reset")
def reset(body: dict, x_admin_key: str = Header(default="")):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(403)
    with _lock:
        STATE["data"] = seed(body.get("injection"))
        STATE["audit"] = []
    return {"ok": True}


@app.get("/admin/state")
def state(x_admin_key: str = Header(default="")):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(403)
    with _lock:
        return copy.deepcopy(STATE)
