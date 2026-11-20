# PowerShell version of run_all_scripted.sh (E1 + E3 + ablations, no API key needed).
# Run from the project folder:   .\experiments\run_all_scripted.ps1
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
$R = "results"
New-Item -ItemType Directory -Force -Path $R | Out-Null

function Run-Scripted([string[]]$CmdArgs) {
    python experiments/run_scripted.py @CmdArgs
    if ($LASTEXITCODE -ne 0) { throw "run_scripted.py failed: $CmdArgs" }
}

# E1: main result
if (-not (Test-Path "$R/e1_graduated_oracle.jsonl")) { Run-Scripted @("--out", "$R/e1_graduated_oracle.jsonl") }

# Ablations
Run-Scripted @("--defenses", "aztac", "--risk-threshold", "inf", "--out", "$R/abl_no_revocation.jsonl")
Run-Scripted @("--defenses", "aztac", "--mode", "strict", "--out", "$R/abl_strict.jsonl")
Run-Scripted @("--defenses", "aztac", "--read-mode", "scoped", "--out", "$R/abl_scoped_reads.jsonl")

# E3: scope errors x approver behaviour
foreach ($P in @("over_broad_tools", "over_broad_targets")) {
    foreach ($A in @("oracle", "approve_all", "reject_all")) {
        Run-Scripted @("--defenses", "aztac", "--perturb", $P, "--approver", $A, "--out", "$R/e3_${P}_${A}.jsonl")
    }
}
Run-Scripted @("--defenses", "aztac", "--perturb", "over_narrow", "--approver", "oracle", "--out", "$R/e3_over_narrow_oracle.jsonl")

# Tables
python experiments/aggregate.py "$R/e1_graduated_oracle.jsonl" --out "$R/table_e1"
$abl = Get-ChildItem "$R/abl_*.jsonl" | ForEach-Object { $_.FullName }
python experiments/aggregate.py "$R/e1_graduated_oracle.jsonl" @abl --label-by mode risk_threshold read_mode --out "$R/table_ablation"
$e3 = Get-ChildItem "$R/e3_*.jsonl" | ForEach-Object { $_.FullName }
python experiments/aggregate.py @e3 --label-by perturb approver --out "$R/table_e3"
Write-Host "Done. Tables are in $R\table_*.md"
