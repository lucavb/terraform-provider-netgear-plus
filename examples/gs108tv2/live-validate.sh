#!/usr/bin/env bash
# Live smoke test for GS108Tv2 against a reachable switch (L3 host + NSDP).
# Safe by default: debug CLI probes + Terraform read-only data sources only.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKDIR="${ROOT}/examples/gs108tv2/.live-validate"
PROVIDER_DIR="${WORKDIR}/.providers"
TF_CLI="${WORKDIR}/terraformrc.tfrc"

SWITCH_HOST="${SWITCH_HOST:-10.0.2.8}"
SWITCH_PASSWORD="${SWITCH_PASSWORD:-}"
AGENT_MAC="${AGENT_MAC:-8c:3b:ad:2c:e9:7d}"
NSDP_IFACE="${NSDP_IFACE:-}"

usage() {
  cat <<'EOF'
Usage: SWITCH_PASSWORD=... ./live-validate.sh

Environment:
  SWITCH_HOST      Switch management IP (default: 10.0.2.8)
  SWITCH_PASSWORD  Admin password (required)
  AGENT_MAC        NSDP agent MAC (default: 8c:3b:ad:2c:e9:7d for bench GS108Tv2)
  NSDP_IFACE       Local NIC for NSDP (optional; default: first usable interface)
  APPLY_RESOURCES  If "1", also run tofu/terraform plan on full main.tf (may show changes)

Requires: go, terraform or tofu on PATH.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ -z "${SWITCH_PASSWORD}" ]]; then
  echo "error: set SWITCH_PASSWORD" >&2
  usage >&2
  exit 1
fi

TF_BIN=""
if command -v tofu >/dev/null 2>&1; then
  TF_BIN=tofu
elif command -v terraform >/dev/null 2>&1; then
  TF_BIN=terraform
else
  echo "error: need terraform or tofu on PATH" >&2
  exit 1
fi

mkdir -p "${PROVIDER_DIR}" "${WORKDIR}"

echo "==> build provider"
(
  cd "${ROOT}"
  go build -o "${PROVIDER_DIR}/terraform-provider-netgear-plus" .
)

cat >"${TF_CLI}" <<EOF
provider_installation {
  dev_overrides {
    "lucavb/netgear-plus" = "${PROVIDER_DIR}"
  }
  direct {
    exclude = ["lucavb/netgear-plus"]
  }
}
EOF

export TF_CLI_CONFIG_FILE="${TF_CLI}"

NSDP_ARGS=(-agent-mac "${AGENT_MAC}" -password "${SWITCH_PASSWORD}" -model gs108tv2 -host "${SWITCH_HOST}")
if [[ -n "${NSDP_IFACE}" ]]; then
  NSDP_ARGS+=(-iface "${NSDP_IFACE}")
fi

echo "==> ping switch (${SWITCH_HOST})"
if ! ping -c 1 -W 3 "${SWITCH_HOST}" >/dev/null 2>&1; then
  echo "warning: ping failed; continuing (ICMP may be blocked)" >&2
fi

echo "==> netgear-plus-debug: NSDP identity (-op switch)"
(
  cd "${ROOT}"
  go run ./cmd/netgear-plus-debug "${NSDP_ARGS[@]}" -op switch
)

echo "==> netgear-plus-debug: fetch startup-config (-op config)"
(
  cd "${ROOT}"
  go run ./cmd/netgear-plus-debug -host "${SWITCH_HOST}" -password "${SWITCH_PASSWORD}" -op config -out "${WORKDIR}/startup-config.cfg"
)
if [[ ! -s "${WORKDIR}/startup-config.cfg" ]]; then
  echo "error: startup-config download empty" >&2
  exit 1
fi
head -n 12 "${WORKDIR}/startup-config.cfg" | sed 's/^/    /'

cat >"${WORKDIR}/read-only.tf" <<EOF
terraform {
  required_providers {
    netgear = {
      source = "registry.terraform.io/lucavb/netgear-plus"
    }
  }
}

variable "switch_password" {
  type      = string
  sensitive = true
}

provider "netgear" {
  host      = "${SWITCH_HOST}"
  password  = var.switch_password
  model     = "gs108tv2"
  agent_mac = "${AGENT_MAC}"
}

data "netgear_plus_switch_config" "startup" {}

data "netgear_plus_switch" "target" {}

output "validation" {
  value = {
    firmware     = data.netgear_plus_switch_config.startup.system_software_version
    serial       = data.netgear_plus_switch.target.serial_number
    switch_mac   = data.netgear_plus_switch.target.mac_address
    config_bytes = length(data.netgear_plus_switch_config.startup.content)
  }
}
EOF

cat >"${WORKDIR}/secrets.auto.tfvars" <<EOF
switch_password = "${SWITCH_PASSWORD}"
EOF

(
  cd "${WORKDIR}"
  rm -rf .terraform .terraform.lock.hcl terraform.tfstate terraform.tfstate.backup
  "${TF_BIN}" init -backend=false
  "${TF_BIN}" apply -auto-approve -parallelism=1
)

if [[ "${APPLY_RESOURCES:-}" == "1" ]]; then
  echo "==> ${TF_BIN} plan full example (main.tf; may propose staged resource changes)"
  (
    cd "${ROOT}/examples/gs108tv2"
    cat >secrets.auto.tfvars <<EOF
switch_password = "${SWITCH_PASSWORD}"
EOF
    # Patch placeholders for this bench switch.
    sed -e "s|192.0.2.20|${SWITCH_HOST}|g" \
        -e "s|en0|${NSDP_IFACE:-}|g" \
        main.tf >"${WORKDIR}/full-example.tf"
    if [[ -n "${NSDP_IFACE}" ]]; then
      sed -i.bak "s|interface = \"\"|interface = \"${NSDP_IFACE}\"|g" "${WORKDIR}/full-example.tf" 2>/dev/null || true
    fi
    cp "${WORKDIR}/secrets.auto.tfvars" .
    TF_CLI_CONFIG_FILE="${TF_CLI}" "${TF_BIN}" init
    TF_CLI_CONFIG_FILE="${TF_CLI}" "${TF_BIN}" plan -parallelism=1
  )
fi

echo "==> live validation OK"
