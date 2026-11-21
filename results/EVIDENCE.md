# Evidence map

Each result in the paper and the file it comes from. All files are in `results/` unless noted.

| Paper item | What it shows | File(s) |
|---|---|---|
| Table II (E1) | Fully compromised agent, no defense vs. AZTAC, 949 attack pairs | `e1_graduated_oracle.jsonl`, `table_e1.md` |
| Multi-host E1 (Section VI-D) | Banking rerun with ATS and gateways on separate hosts | `e1_multihost_banking.jsonl`, `table_e1_multihost.md` |
| Table III (ablations) | No revocation, strict mode, scoped reads | `abl_no_revocation.jsonl`, `abl_strict.jsonl`, `abl_scoped_reads.jsonl`, `table_ablation.md` |
| Table III (E3) | Wrong scopes × approver behavior | `e3_*.jsonl`, `table_e3.md` |
| Table IV (E2) | Real gpt-4o-mini agents, 7 defenses, 4 suites | `e2_gpt4omini.jsonl` (4,802 runs), `table_e2_final.md` |
| Table IV, CaMeL row | CaMeL from its public code, 489 pairs | `camel/summary.json`, `camel/crashes.jsonl` |
| E4 (load) | Throughput and latency at 10/50/100 agents | `e4_load_multihost.json` (remote client), `e4_load_summary.md` (both runs) |
| Gateway-only baselines (Section VI-A) | Static per-tool policy; per-task tools without argument pins; AZTAC under the same settings | `static_role.jsonl`, `static_allowlist.jsonl`, `task_tools.jsonl`, `aztac_pins_approveall.jsonl` |
| E2 statistics | Task-clustered intervals, paired McNemar tests | `e2_clustered_stats.txt` (from `experiments/clustered_stats.py`) |
| Three-host replication (VI-F) | E1 and real-agent E2 with Keycloak across three hosts | `e1_keycloak_multihost.jsonl`, `table_e1_keycloak.md`, `e2_distributed.jsonl`, `table_e2_distributed.md` |
| Trust boundary (VI-F) | E1 rerun with ATS client authentication; compromised-runtime probes | `e1_clientauth_keycloak.jsonl`, `table_e1_clientauth.md`, `boundary.json` |
| E6 case study (VI-G) | Agents SDK agent, REST API behind the gateway | `casestudy.jsonl` |
| E5 (revocation) | Revocation delay across two gateways; network baseline | the E5 and baseline `.json` files |

Each line of a `.jsonl` file is one run: suite, user task, injection task (empty for benign runs),
defense, utility, attack success (official and executed), and every authorization decision with its
latency. The `table_*.md` files are produced from them by `experiments/aggregate.py`.

Rebuild any table, for example:

```
python experiments/aggregate.py results/e2_gpt4omini.jsonl --out results/table_e2_final
```
