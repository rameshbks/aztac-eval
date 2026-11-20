"""Crash-tolerant CaMeL baseline runner for the AZTAC comparison (E2).

Same pipeline and log folder as CaMeL's main.py (so finished tasks are reused),
with two differences:
  1. An interpreter crash (e.g. RecursionError inside CaMeL) in one task no longer
     stops the run. The task is recorded as utility=False / attack not achieved and
     written to results_camel/crashes.jsonl so it can be reported separately.
  2. Attacks can be restricted to the exact (user, injection) pairs used for the
     AZTAC runs, read from the AZTAC results file (used for the sampled workspace suite).

Usage (PowerShell, inside the CaMeL folder):
  uv run --env-file .env run_camel_safe.py --model openai:gpt-4o-mini-2024-07-18 `
      --suites banking slack travel workspace --pairs-from C:\\aztac-eval\\results\\e2_gpt4omini.jsonl `
      --pairs-suites workspace
"""
import argparse
import json
import time
import traceback
from collections import defaultdict
from pathlib import Path

import openai
from agentdojo import attacks, benchmark, logging
from agentdojo.task_suite import get_suite
from agentdojo.task_suite.task_suite import TaskSuite

import camel.custom_yaml  # noqa: F401
from camel.interpreter.interpreter import MetadataEvalMode
from camel.models import make_tools_pipeline

OUT = Path("results_camel")
OUT.mkdir(exist_ok=True)
CRASHES = OUT / "crashes.jsonl"
_original_run = TaskSuite.run_task_with_pipeline


def _safe_run(self, agent_pipeline, user_task, injection_task, injections, *args, **kwargs):
    try:
        return _original_run(self, agent_pipeline, user_task, injection_task, injections, *args, **kwargs)
    except openai.OpenAIError:
        raise  # API/billing/rate errors must stop the run, not count as failures
    except Exception as e:  # interpreter crashes such as RecursionError
        rec = {"suite": self.name, "user_task": user_task.ID,
               "injection_task": injection_task.ID if injection_task else None,
               "error": repr(e)[:300], "where": traceback.format_exc()[-600:],
               "time": time.strftime("%Y-%m-%d %H:%M:%S")}
        with CRASHES.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
        print(f"[camel-safe] crash recorded: {rec['suite']} {rec['user_task']} "
              f"{rec['injection_task']} {type(e).__name__}", flush=True)
        # benign: AgentDojo convention security=True; attacked: injection goal not reached
        return False, injection_task is None


TaskSuite.run_task_with_pipeline = _safe_run


def load_pairs(path, suites, limit=None):
    pairs = defaultdict(lambda: defaultdict(list))
    seen = set()
    count = defaultdict(int)
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        if r["suite"] in suites and r["defense"] == "none" and r["injection_task"]:
            key = (r["suite"], r["user_task"], r["injection_task"])
            if key not in seen and (limit is None or count[r["suite"]] < limit):
                seen.add(key)
                count[r["suite"]] += 1
                pairs[r["suite"]][r["user_task"]].append(r["injection_task"])
    return pairs


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--model", required=True)
    p.add_argument("--suites", nargs="+", default=["banking", "slack", "travel", "workspace"])
    p.add_argument("--pairs-from", help="AZTAC results jsonl; reuse its sampled pairs")
    p.add_argument("--pairs-suites", nargs="*", default=["workspace"])
    p.add_argument("--pairs-limit", type=int, default=None,
                   help="use only the first N sampled pairs (in the AZTAC file's sampling order)")
    p.add_argument("--skip-benign", action="store_true")
    p.add_argument("--skip-attack", action="store_true")
    a = p.parse_args()

    sampled = load_pairs(a.pairs_from, set(a.pairs_suites), a.pairs_limit) if a.pairs_from else {}
    logdir = Path("./logs")
    attack_name = "important_instructions"
    summary = {}
    rows = []
    for sname in a.suites:
        pipeline = make_tools_pipeline(a.model, False, False, attack_name, "medium", None,
                                       sname, None, MetadataEvalMode.NORMAL, None)
        suite = get_suite("v1.2.2", sname)
        attack = attacks.load_attack(attack_name, suite, pipeline)
        s = {}
        with logging.OutputLogger(str(logdir)):
            if not a.skip_benign:
                res = benchmark.benchmark_suite_without_injections(pipeline, suite, logdir, force_rerun=False)
                u = res["utility_results"]
                s["benign_n"] = len(u)
                s["benign_utility"] = sum(u.values()) / len(u)
                for (ut, _), v in u.items():
                    rows.append({"suite": sname, "user_task": ut, "injection_task": None, "utility": bool(v)})
                print(f"{sname} - benign utility: {s['benign_utility']:.4f} ({sum(u.values())}/{len(u)})", flush=True)
            if not a.skip_attack:
                util, sec = {}, {}
                if sname in sampled:
                    for ut_id, its in sampled[sname].items():
                        uu, ss = benchmark.run_task_with_injection_tasks(
                            suite, pipeline, suite.get_user_task_by_id(ut_id), attack, logdir,
                            False, injection_tasks=its)
                        util.update(uu)
                        sec.update(ss)
                else:
                    for ut in suite.user_tasks.values():
                        uu, ss = benchmark.run_task_with_injection_tasks(
                            suite, pipeline, ut, attack, logdir, False)
                        util.update(uu)
                        sec.update(ss)
                s["attack_n"] = len(sec)
                s["utility_under_attack"] = sum(util.values()) / len(util)
                s["asr"] = sum(sec.values()) / len(sec)
                for k in sec:
                    rows.append({"suite": sname, "user_task": k[0], "injection_task": k[1],
                                 "utility": bool(util[k]), "attack_success": bool(sec[k])})
                print(f"{sname} - utility under attack: {s['utility_under_attack']:.4f}  "
                      f"ASR: {s['asr']:.4f} ({sum(sec.values())}/{len(sec)})", flush=True)
        summary[sname] = s
        (OUT / "summary.json").write_text(json.dumps(summary, indent=2))
        with (OUT / "rows.jsonl").open("w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")

    crashes = CRASHES.read_text().count("\n") if CRASHES.exists() else 0
    print(json.dumps(summary, indent=2))
    print(f"crashes recorded so far: {crashes}  (see {CRASHES})")


if __name__ == "__main__":
    main()
