"""Summarize result files into the paper's tables (Markdown, CSV and LaTeX).

python experiments/aggregate.py results/e1.jsonl [more.jsonl ...] --label-by perturb --out results/summary
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from collections import defaultdict


def pct(xs):
    xs = [x for x in xs if x is not None]
    return 100.0 * sum(xs) / len(xs) if xs else float("nan")


def quantiles(xs):
    xs = sorted(x for x in xs if x is not None)
    if not xs:
        return (float("nan"),) * 3
    q = lambda p: xs[min(len(xs) - 1, int(round(p * (len(xs) - 1))))]
    return q(0.50), q(0.95), q(0.99)


def summarize(rows, label_by):
    groups = defaultdict(list)
    for r in rows:
        cfg = r.get("config", {})
        label = r["defense"] if r["defense"] != "aztac" else "aztac" + "".join(
            f"/{cfg.get(k)}" for k in label_by)
        groups[(r["suite"], label)].append(r)
        groups[("ALL", label)].append(r)
    out = []
    for (suite, label), rs in sorted(groups.items()):
        ben = [r for r in rs if r["injection_task"] is None]
        att = [r for r in rs if r["injection_task"] is not None]
        ev = [e for r in rs for e in r.get("events", [])]
        ben_blocked = [any(e["final"] == "blocked" for e in r.get("events", [])) for r in ben]
        stepups = [e for e in ev if e["outcome"] == "STEP_UP"]
        dec50, dec95, dec99 = quantiles([e.get("decision_us") for e in ev])
        rtt50, rtt95, rtt99 = quantiles([e.get("rtt_ms") for e in ev])
        ex50, ex95, _ = quantiles([r.get("session", {}).get("exchange_ms") for r in rs])
        cp50, cp95, _ = quantiles([r.get("session", {}).get("compile_ms") for r in rs])
        # end-to-end security overhead per task = scope compilation + token exchange + all authorization round trips
        ovh = [(r.get("session", {}).get("compile_ms") or 0) + (r.get("session", {}).get("exchange_ms") or 0)
               + sum(e.get("rtt_ms") or 0 for e in r.get("events", [])) for r in rs if r.get("session")]
        ov50, ov95, _ = quantiles(ovh)
        wall50, wall95, _ = quantiles([r.get("wall_s") for r in rs])
        out.append({
            "suite": suite, "defense": label, "n_benign": len(ben), "n_attack": len(att),
            "benign_utility_%": pct([r["utility"] for r in ben]),
            "utility_under_attack_%": pct([r["utility"] for r in att]),
            "ASR_official_%": pct([r["attack_success"] for r in att]),
            "ASR_executed_%": pct([r.get("attack_success_executed") for r in att]),
            "benign_runs_with_block_%": pct(ben_blocked),
            "stepups_per_run": len(stepups) / len(rs) if rs else 0.0,
            "runs_revoked_%": pct([any(e.get("revoked_now") for e in r.get("events", [])) for r in rs]) if ev else 0.0,
            "decision_us_p50": dec50, "decision_us_p95": dec95, "decision_us_p99": dec99,
            "authz_rtt_ms_p50": rtt50, "authz_rtt_ms_p95": rtt95, "authz_rtt_ms_p99": rtt99,
            "token_exchange_ms_p50": ex50, "token_exchange_ms_p95": ex95,
            "scope_compile_ms_p50": cp50, "scope_compile_ms_p95": cp95,
            "security_overhead_per_task_ms_p50": ov50, "security_overhead_per_task_ms_p95": ov95,
            "task_wall_s_p50": wall50, "task_wall_s_p95": wall95,
            "errors": sum(1 for r in rs if r.get("error")),
        })
    return out


def fmt(v):
    if isinstance(v, float):
        return "–" if v != v else f"{v:.1f}" if abs(v) >= 1 or v == 0 else f"{v:.3f}"
    return str(v)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("files", nargs="+")
    p.add_argument("--label-by", nargs="*", default=[])
    p.add_argument("--out", default="results/summary")
    a = p.parse_args()
    rows = [json.loads(l) for f in a.files for l in open(f)]
    table = summarize(rows, a.label_by)
    cols = list(table[0].keys())
    with open(a.out + ".csv", "w", newline="") as f:
        w = csv.DictWriter(f, cols)
        w.writeheader()
        w.writerows(table)
    md = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    md += ["| " + " | ".join(fmt(r[c]) for c in cols) + " |" for r in table]
    open(a.out + ".md", "w").write("\n".join(md) + "\n")
    key = ["suite", "defense", "benign_utility_%", "utility_under_attack_%", "ASR_official_%", "ASR_executed_%"]
    tex = ["\\begin{tabular}{llrrrr}", "\\hline",
           "Suite & Defense & Benign util. & Util. under attack & ASR (official) & ASR (executed) \\\\", "\\hline"]
    tex += [" & ".join(fmt(r[c]).replace("%", "\\%").replace("_", "\\_") for c in key) + " \\\\" for r in table]
    tex += ["\\hline", "\\end{tabular}"]
    open(a.out + ".tex", "w").write("\n".join(tex) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
