#!/usr/bin/env bash
# Staged VLAN + port apply on the bench GS108Tv2, then OpenTofu read/apply check.
set -euo pipefail

BUNDLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH_DIR="${BUNDLE_DIR}/live-bench"
DEBUG_BIN="${BUNDLE_DIR}/netgear-plus-debug"
TF_BIN="${BUNDLE_DIR}/tofu"
export TF_CLI_CONFIG_FILE="${BUNDLE_DIR}/terraformrc.tfrc"

SWITCH_HOST="${SWITCH_HOST:-10.0.2.8}"
SWITCH_PASSWORD="${SWITCH_PASSWORD:-}"
AGENT_MAC="${AGENT_MAC:-8c:3b:ad:2c:e9:7d}"
SERIAL="${SERIAL:-129SM7B5U01DA7}"
INGEST_WAIT_SEC="${INGEST_WAIT_SEC:-130}"

if [[ -z "${SWITCH_PASSWORD}" ]]; then
  echo "error: SWITCH_PASSWORD required" >&2
  exit 1
fi

cat >"${BUNDLE_DIR}/secrets.auto.tfvars" <<EOF
switch_password = "${SWITCH_PASSWORD}"
EOF

FACTORY_CFG="${BENCH_DIR}/factory-reverted.txt"
if [[ "${SKIP_FACTORY_RESTORE:-}" == "1" ]]; then
  echo "==> skip factory restore (SKIP_FACTORY_RESTORE=1)"
elif [[ -f "${FACTORY_CFG}" ]]; then
  echo "==> restore factory baseline (clean vlan database)"
  "${DEBUG_BIN}" -host "${SWITCH_HOST}" -password "${SWITCH_PASSWORD}" -timeout 60 \
    -op restore-config -file "${FACTORY_CFG}"
  echo "==> wait for post-restore ingest (${INGEST_WAIT_SEC}s; switch refuses logins while digesting)"
  remaining="${INGEST_WAIT_SEC}"
  while (( remaining > 0 )); do
    step=$(( remaining > 30 ? 30 : remaining ))
    sleep "${step}"
    remaining=$(( remaining - step ))
    echo "    ... ingest wait ${remaining}s remaining"
  done
fi

echo "==> apply VLAN state (startup-config stage)"
echo "    (driver waits up to ~90s before first verify, then polls up to 5m — not hung)"
"${DEBUG_BIN}" -host "${SWITCH_HOST}" -password "${SWITCH_PASSWORD}" -timeout 60 \
  -op apply-vlan-state -file "${BENCH_DIR}/vlan-spec.json"

echo "==> apply port settings (startup-config stage)"
echo "    (same post-restore wait semantics as VLAN apply)"
"${DEBUG_BIN}" -host "${SWITCH_HOST}" -password "${SWITCH_PASSWORD}" -timeout 60 \
  -op apply-port-settings -file "${BENCH_DIR}/port-spec.json"

cd "${BUNDLE_DIR}"
rm -f read-vlans.tf

cat >"${BENCH_DIR}/verify-read.tf" <<'EOF'
data "netgear_plus_vlan_state" "current" {}

output "vlan_after_apply" {
  value = {
    pvids = data.netgear_plus_vlan_state.current.pvids
    vlans = data.netgear_plus_vlan_state.current.vlan
  }
}
EOF

echo "==> tofu read-back (data sources)"
"${TF_BIN}" init -backend=false -input=false
cp "${BENCH_DIR}/verify-read.tf" .
"${TF_BIN}" apply -auto-approve -parallelism=1 -input=false

cat >"${BENCH_DIR}/manage.tf" <<EOF
resource "netgear_plus_vlan_state" "bench" {
  expected_serial_number = "${SERIAL}"
  allow_vlan_deletions   = false

  vlan {
    id = 1
    ports = {
      "1" = "untagged"
      "2" = "untagged"
      "5" = "untagged"
      "6" = "untagged"
      "7" = "untagged"
      "8" = "untagged"
    }
  }

  vlan {
    id = 10
    ports = {
      "3" = "untagged"
      "4" = "untagged"
    }
  }

  pvids = {
    "1" = 1
    "2" = 1
    "3" = 10
    "4" = 10
    "5" = 1
    "6" = 1
    "7" = 1
    "8" = 1
  }
}

resource "netgear_plus_port_config" "bench" {
  ports { port = 1 }
  ports { port = 2 }
  ports { port = 3 }
  ports { port = 4 }
  ports { port = 5 }
  ports {
    port    = 6
    enabled = false
  }
  ports { port = 7 }
  ports { port = 8 }
}
EOF

cp "${BENCH_DIR}/manage.tf" .

echo "==> tofu plan managed resources (expect no-op after debug apply)"
"${TF_BIN}" plan -parallelism=1 -detailed-exitcode -input=false || {
  code=$?
  if [[ "${code}" -eq 2 ]]; then
    echo "plan wants changes — running apply to converge"
    "${TF_BIN}" apply -auto-approve -parallelism=1 -input=false
  elif [[ "${code}" -ne 0 ]]; then
    exit "${code}"
  fi
}

echo "==> configure live test OK"
