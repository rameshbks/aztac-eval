#!/usr/bin/env bash
# Host 1 (identity): Keycloak + Agent Token Service. Run in its own codespace:
#   bash deploy/codespace_identity.sh <ATS_ADMIN_KEY>
# Then make ports 8080 and 8100 Public in the Ports tab.
set -euo pipefail
ADMIN_KEY="${1:?usage: bash deploy/codespace_identity.sh <ATS_ADMIN_KEY>}"
DOMAIN="${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN:-app.github.dev}"
KC_PUBLIC="https://${CODESPACE_NAME}-8080.${DOMAIN}"
pip install -q -r requirements.txt
docker rm -f kc >/dev/null 2>&1 || true
docker run -d --name kc -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD="kc-$ADMIN_KEY" \
  -e KC_HOSTNAME="$KC_PUBLIC" -e KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true \
  -e KC_PROXY_HEADERS=xforwarded -e KC_HTTP_ENABLED=true \
  -v "$PWD/deploy/keycloak:/opt/keycloak/data/import:ro" \
  quay.io/keycloak/keycloak:26.0 start-dev --import-realm
echo "Waiting for Keycloak..."
until curl -sf http://localhost:8080/realms/aztac/.well-known/openid-configuration >/dev/null; do sleep 3; done
echo "Keycloak is up. Issuer: $KC_PUBLIC/realms/aztac"
echo "KC  = $KC_PUBLIC/realms/aztac/protocol/openid-connect/token"
echo "ATS = https://${CODESPACE_NAME}-8100.${DOMAIN}"
ATS_ADMIN_KEY="$ADMIN_KEY" \
SUBJECT_JWKS_URL=http://localhost:8080/realms/aztac/protocol/openid-connect/certs \
SUBJECT_ISSUER="$KC_PUBLIC/realms/aztac" SUBJECT_AUDIENCE=agent-platform \
  python3 -m uvicorn aztac.http_apps:ats_app --host 0.0.0.0 --port 8100 --log-level warning
