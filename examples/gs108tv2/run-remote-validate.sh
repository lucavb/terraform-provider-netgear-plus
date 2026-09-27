#!/usr/bin/env bash
# Runs on the LAN host after deploy-remote-validate.sh copies the bundle here.
set -euo pipefail

BUNDLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_CLI="${BUNDLE_DIR}/terraformrc.tfrc"
TF_BIN="${BUNDLE_DIR}/tofu"
DEBUG_BIN="${BUNDLE_DIR}/netgear-plus-debug"

SWITCH_HOST="${SWITCH_HOST:-10.0.2.8}"
SWITCH_PASSWORD="${SWITCH_PASSWORD:-}"
AGENT_MAC="${AGENT_MAC:-8c:3b:ad:2c:e9:7d}"
NSDP_IFACE="${NSDP_IFACE:-}"

if [[ -z "${SWITCH_PASSWORD}" ]]; then
  echo "error: SWITCH_PASSWORD required" >&2
  exit 1
fi

chmod +x "${TF_BIN}" "${DEBUG_BIN}" 2>/dev/null || true
find "${BUNDLE_DIR}/provider-mirror" -type f -name 'terraform-provider-*' -exec chmod +x {} + 2>/dev/null || true

export TF_CLI_CONFIG_FILE="${TF_CLI}"

NSDP_ARGS=(-agent-mac "${AGENT_MAC}" -password "${SWITCH_PASSWORD}" -model gs108tv2 -host "${SWITCH_HOST}")
if [[ -n "${NSDP_IFACE}" ]]; then
  NSDP_ARGS+=(-iface "${NSDP_IFACE}")
fi

echo "==> ping ${SWITCH_HOST}"
ping -c 1 -W 3 "${SWITCH_HOST}" || true

echo "==> NSDP identity"
"${DEBUG_BIN}" "${NSDP_ARGS[@]}" -op switch

echo "==> emweb startup-config"
"${DEBUG_BIN}" -host "${SWITCH_HOST}" -password "${SWITCH_PASSWORD}" -op config -out "${BUNDLE_DIR}/startup-config.cfg"
head -n 12 "${BUNDLE_DIR}/startup-config.cfg" | sed 's/^/    /'

cat >"${BUNDLE_DIR}/secrets.auto.tfvars" <<EOF
switch_password = "${SWITCH_PASSWORD}"
EOF

cd "${BUNDLE_DIR}"
rm -rf .terraform .terraform.lock.hcl terraform.tfstate terraform.tfstate.backup

echo "==> tofu init (filesystem mirror — local cross-compile)"
"${TF_BIN}" init -backend=false

echo "==> tofu apply (read-only data sources)"
"${TF_BIN}" apply -auto-approve -parallelism=1

echo "==> live validation OK"
