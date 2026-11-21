"""Security metadata for AgentDojo tools.

Each side-effecting tool is classified so the policy decision point (PDP) knows
which arguments identify *where* an action goes (targets) and which arguments
carry a magnitude that can be bounded (bounded).

Classes:
  read    - returns data, no side effects inside the trust boundary
  write   - changes state (send, create, delete, update)
  egress  - may move data outside the trust boundary even if it looks like a read
            (e.g. fetching an attacker-controlled URL leaks data in the query string)

Targets set to ["*"] mean every argument is pinned to task-approved values.
Tools not listed default to class "read" with no targets.
"""

from __future__ import annotations

import json
import re

TOOL_META: dict[str, dict[str, dict]] = {
    # Case study: an enterprise REST API reached through an agent framework (casestudy/).
    "corp": {
        "list_inbox": {"class": "read", "targets": [], "bounded": []},
        "read_file": {"class": "read", "targets": [], "bounded": []},
        "list_transactions": {"class": "read", "targets": [], "bounded": []},
        "send_email": {"class": "egress", "targets": ["to"], "bounded": []},
        "share_file": {"class": "egress", "targets": ["email"], "bounded": []},
        "transfer": {"class": "write", "targets": ["iban"], "bounded": ["amount"]},
    },
    "banking": {
        "send_money": {"class": "write", "targets": ["recipient"], "bounded": ["amount"]},
        "schedule_transaction": {"class": "write", "targets": ["recipient"], "bounded": ["amount"]},
        "update_scheduled_transaction": {"class": "write", "targets": ["id", "recipient"], "bounded": ["amount"]},
        "update_password": {"class": "write", "targets": ["*"], "bounded": []},
        "update_user_info": {"class": "write", "targets": ["*"], "bounded": []},
    },
    "workspace": {
        "send_email": {"class": "write", "targets": ["recipients", "cc", "bcc"], "bounded": []},
        "delete_email": {"class": "write", "targets": ["email_id"], "bounded": []},
        "create_calendar_event": {"class": "write", "targets": ["participants"], "bounded": []},
        "cancel_calendar_event": {"class": "write", "targets": ["event_id"], "bounded": []},
        "reschedule_calendar_event": {"class": "write", "targets": ["event_id"], "bounded": []},
        "add_calendar_event_participants": {"class": "write", "targets": ["event_id", "participants"], "bounded": []},
        "append_to_file": {"class": "write", "targets": ["file_id"], "bounded": []},
        "create_file": {"class": "write", "targets": [], "bounded": []},
        "delete_file": {"class": "write", "targets": ["file_id"], "bounded": []},
        "share_file": {"class": "write", "targets": ["file_id", "email"], "bounded": []},
    },
    "travel": {
        "send_email": {"class": "write", "targets": ["recipients", "cc", "bcc"], "bounded": []},
        "create_calendar_event": {"class": "write", "targets": ["participants"], "bounded": []},
        "cancel_calendar_event": {"class": "write", "targets": ["event_id"], "bounded": []},
        "reserve_hotel": {"class": "write", "targets": ["hotel"], "bounded": []},
        "reserve_car_rental": {"class": "write", "targets": ["company"], "bounded": []},
        "reserve_restaurant": {"class": "write", "targets": ["restaurant"], "bounded": []},
    },
    "slack": {
        "add_user_to_channel": {"class": "write", "targets": ["user", "channel"], "bounded": []},
        "send_direct_message": {"class": "write", "targets": ["recipient"], "bounded": []},
        "send_channel_message": {"class": "write", "targets": ["channel"], "bounded": []},
        "invite_user_to_slack": {"class": "write", "targets": ["user", "user_email"], "bounded": []},
        "remove_user_from_slack": {"class": "write", "targets": ["user"], "bounded": []},
        "get_webpage": {"class": "egress", "targets": ["url"], "bounded": []},
        "post_webpage": {"class": "egress", "targets": ["url"], "bounded": []},
    },
}

DEFAULT_META = {"class": "read", "targets": [], "bounded": []}


def meta_for(suite: str, tool: str) -> dict:
    return TOOL_META.get(suite, {}).get(tool, DEFAULT_META)


def is_side_effecting(suite: str, tool: str) -> bool:
    return meta_for(suite, tool)["class"] in ("write", "egress")


def target_args(suite: str, tool: str, args: dict) -> list[str]:
    targets = meta_for(suite, tool)["targets"]
    if targets == ["*"]:
        return sorted(args.keys())
    return targets


URL_ARGS = {"url"}
_URL_PREFIX = re.compile(r"^(https?://)?(www\.)?")


def as_values(v, arg: str | None = None) -> list:
    """Normalize an argument value to a list of comparable scalars.

    Lists (e.g. email recipients) are checked element-wise, so every recipient
    must be approved. None/empty means "no target supplied". URL arguments are
    compared in canonical form (RFC 3986 scheme/host case-insensitivity; the
    "http(s)://", "www." prefix and a single trailing "/" are not significant),
    so "https://www.site.com/" and "www.site.com" match, while a different host
    or path still does not.
    """
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return [_norm(x, arg) for x in v]
    return [_norm(v, arg)]


def _norm(x, arg: str | None = None):
    if isinstance(x, (dict, list, tuple)):
        # Structured values (e.g. an object where a name was expected) are compared as canonical JSON,
        # so they are hashable and never equal an approved plain value by accident.
        return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    if isinstance(x, str):
        x = x.strip().lower()
        if arg in URL_ARGS:
            x = _URL_PREFIX.sub("", x)
            x = x[:-1] if x.endswith("/") else x
        return x
    return x


# Format checks for pinned targets produced by an LLM compiler. A pin is accepted only if
# the value appears verbatim in the trusted request AND matches the argument's format,
# so a file name or a role ("landlord") is never accepted as a payment recipient.
_IBAN = re.compile(r"^[a-z]{2}[0-9]{2}[a-z0-9]{8,30}$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$")
_URL = re.compile(r"^(https?://)?[a-z0-9.-]+\.[a-z]{2,}(/\S*)?$")
TARGET_FORMATS: dict[tuple[str, str], re.Pattern] = {
    ("banking", "recipient"): _IBAN,
    ("corp", "to"): _EMAIL, ("corp", "email"): _EMAIL, ("corp", "iban"): _IBAN,
    ("workspace", "recipients"): _EMAIL, ("workspace", "cc"): _EMAIL, ("workspace", "bcc"): _EMAIL,
    ("workspace", "participants"): _EMAIL, ("workspace", "email"): _EMAIL,
    ("travel", "recipients"): _EMAIL, ("travel", "cc"): _EMAIL, ("travel", "bcc"): _EMAIL,
    ("travel", "participants"): _EMAIL,
    ("slack", "user_email"): _EMAIL, ("slack", "url"): _URL,
}


def valid_pin(suite: str, arg: str, value, prompt: str) -> bool:
    """Accept a compiler-proposed pin only if it is literally in the request and well-formed."""
    if isinstance(value, (int, float)):
        return str(value) in prompt
    v = _norm(value, arg)
    if not isinstance(v, str) or not v or v not in _norm(prompt, arg if arg in URL_ARGS else None):
        return False
    fmt = TARGET_FORMATS.get((suite, arg))
    return bool(fmt.match(v.replace(" ", ""))) if fmt else True
