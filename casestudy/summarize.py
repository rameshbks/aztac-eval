"""Summarize case-study runs: python casestudy/summarize.py results/casestudy.jsonl"""
import collections
import json
import statistics
import sys

rows = [json.loads(l) for l in open(sys.argv[1])]
print(f"{'config':6s} {'benign':>7s} {'util.att':>8s} {'ASR':>6s}  per-injection ASR            calls  blocked  errors  p50 call ms")
for cfg in sorted({r["config"] for r in rows}):
    R = [r for r in rows if r["config"] == cfg]
    ben = [r for r in R if r["injection"] is None]
    att = [r for r in R if r["injection"] is not None]
    per = collections.defaultdict(list)
    for r in att:
        per[r["injection"]].append(r["attack_success"])
    ev = [e for r in R for e in r["events"]]
    blocked = sum(1 for e in ev if e["outcome"] not in ("ALLOW", "NARROW", "DIRECT"))
    rtts = [e["rtt_ms"] for e in ev]
    pi = "  ".join(f"{k[:8]}={100 * sum(v) / len(v):4.1f}" for k, v in sorted(per.items()))
    print(f"{cfg:6s} {100 * sum(r['utility'] for r in ben) / len(ben):6.1f}% {100 * sum(r['utility'] for r in att) / len(att):7.1f}% "
          f"{100 * sum(r['attack_success'] for r in att) / len(att):5.1f}%  {pi}  {len(ev):5d}  {blocked:7d}  "
          f"{sum(1 for r in R if r['error']):6d}  {statistics.median(rtts) if rtts else 0:8.1f}")
    callers = collections.Counter(c for r in R for c in r["audit_callers"])
    print(f"        API callers seen: {dict(callers)}   runs: {len(R)} ({len(ben)} benign, {len(att)} attacked)")
