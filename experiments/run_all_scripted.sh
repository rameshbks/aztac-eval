#!/usr/bin/env bash
# E1 + E3 + ablations with the scripted fully-compromised agent (no API key, ~30 min on 2 vCPU).
set -euo pipefail
cd "$(dirname "$0")/.."
R=results
mkdir -p $R
S="python experiments/run_scripted.py"

# E1: main result (no defense vs AZTAC, oracle scope, graduated, risk threshold 2)
[ -f $R/e1_graduated_oracle.jsonl ] || $S --out $R/e1_graduated_oracle.jsonl

# Ablations
$S --defenses aztac --risk-threshold inf --out $R/abl_no_revocation.jsonl
$S --defenses aztac --mode strict          --out $R/abl_strict.jsonl
$S --defenses aztac --read-mode scoped     --out $R/abl_scoped_reads.jsonl

# E3: scope-compilation errors x human approver behaviour
for P in over_broad_tools over_broad_targets; do
  for A in oracle approve_all reject_all; do
    $S --defenses aztac --perturb $P --approver $A --out $R/e3_${P}_${A}.jsonl
  done
done
$S --defenses aztac --perturb over_narrow --approver oracle --out $R/e3_over_narrow_oracle.jsonl

python experiments/aggregate.py $R/e1_graduated_oracle.jsonl --out $R/table_e1
python experiments/aggregate.py $R/e1_graduated_oracle.jsonl $R/abl_*.jsonl \
  --label-by mode risk_threshold read_mode --out $R/table_ablation
python experiments/aggregate.py $R/e3_*.jsonl --label-by perturb approver --out $R/table_e3
