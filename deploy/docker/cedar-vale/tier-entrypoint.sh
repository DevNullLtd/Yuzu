#!/usr/bin/env bash
# Cedar & Vale demo — shared tier entrypoint.
#
# Runs in every tier container (frontend / app / db). Each tier co-hosts ITS
# service and a yuzu-agent in one container so the agent — sharing this
# container's network + PID namespace natively — sees this tier's listeners,
# connections, and processes. That is what makes the tier render in fleet-viz
# with the right tier (from its listener port) and the right connection tubes.
#
# Contract: invoked as `tier-entrypoint.sh <service-cmd...>`. We background the
# agent, then exec the service in the FOREGROUND so the service's lifecycle is
# the container's (service exit => container exit). tini (PID 1) reaps the
# backgrounded agent.
#
# DEMO ONLY: the agent runs as root here so its echo plugin can read every
# process's /proc entry. Do not copy this pattern to production — see
# docs/agent-privilege-model.md.
set -euo pipefail

: "${YUZU_ENROLLMENT_TOKEN:?set YUZU_ENROLLMENT_TOKEN}"
GATEWAY_ADDR="${YUZU_GATEWAY:-gateway:50051}"

echo "[tier-entrypoint] starting yuzu-agent (gateway=${GATEWAY_ADDR})"
yuzu-agent \
  --server "${GATEWAY_ADDR}" \
  --no-tls \
  --plugin-dir /usr/lib/yuzu/plugins \
  --data-dir /var/lib/yuzu-agent \
  --log-level info \
  --enrollment-token "${YUZU_ENROLLMENT_TOKEN}" &

echo "[tier-entrypoint] exec service: $*"
exec "$@"
