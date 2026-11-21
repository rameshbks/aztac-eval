#!/usr/bin/env bash
# Host 2 (enforcement + resource): two gateways and the case-study enterprise API. Run in its own codespace:
#   bash deploy/codespace_enforcement.sh <ATS_URL> <ATS_ADMIN_KEY> <CORP_SECRET_SEED>
# Gateway :8200 (theta = 3, real LLM agents, proxies to the API), gateway :8201 (theta = 2, E1),
# enterprise API :9000. Then make ports 8200, 8201 and 9000 Public in the Ports tab.
set -euo pipefail
ATS_URL="${1:?usage: bash deploy/codespace_enforcement.sh <ATS_URL> <ATS_ADMIN_KEY> <SEED>}"
ADMIN_KEY="${2:?}"; SEED="${3:?}"
DOMAIN="${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN:-app.github.dev}"
pip install -q -r requirements.txt
mkdir -p logs
CORP_GATEWAY_SECRET="gw-$SEED" CORP_STANDING_KEY="standing-$SEED" CORP_ADMIN_KEY="corpadmin-$SEED" \
  nohup python3 -m uvicorn casestudy.corp_api:app --host 0.0.0.0 --port 9000 --log-level warning > logs/corp.log 2>&1 &
ATS_URL="$ATS_URL" ATS_ADMIN_KEY="$ADMIN_KEY" RISK_THRESHOLD=2.0 \
  nohup python3 -m uvicorn aztac.http_apps:gateway_app --host 0.0.0.0 --port 8201 --log-level warning > logs/gw_e1.log 2>&1 &
sleep 2
echo "GW    = https://${CODESPACE_NAME}-8200.${DOMAIN}   (theta 3, real agents + case study)"
echo "GW_E1 = https://${CODESPACE_NAME}-8201.${DOMAIN}   (theta 2, E1)"
echo "CORP  = https://${CODESPACE_NAME}-9000.${DOMAIN}"
echo "Case-study keys: CORP_STANDING_KEY=standing-$SEED  CORP_ADMIN_KEY=corpadmin-$SEED"
ATS_URL="$ATS_URL" ATS_ADMIN_KEY="$ADMIN_KEY" RISK_THRESHOLD=3.0 \
UPSTREAM_URL=http://127.0.0.1:9000 UPSTREAM_SECRET="gw-$SEED" \
  python3 -m uvicorn aztac.http_apps:gateway_app --host 0.0.0.0 --port 8200 --log-level warning
