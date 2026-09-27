#!/usr/bin/env bash
# Cross-compile linux/amd64 artifacts locally, scp to a LAN jump host, run validation.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EXAMPLE_DIR="${ROOT}/examples/gs108tv2"
STAGING="${EXAMPLE_DIR}/.deploy-staging"

REMOTE_HOST="${REMOTE_HOST:-root@casalta-lan.direct.sunbury.xyz}"
REMOTE_DIR="${REMOTE_DIR:-/tmp/netgear-plus-live-validate}"
GOOS="${GOOS:-linux}"
GOARCH="${GOARCH:-amd64}"

SWITCH_HOST="${SWITCH_HOST:-10.0.2.8}"
SWITCH_PASSWORD="${SWITCH_PASSWORD:-}"
AGENT_MAC="${AGENT_MAC:-8c:3b:ad:2c:e9:7d}"

TOFU_VERSION="${TOFU_VERSION:-1.9.0}"
DEV_PROVIDER_VERSION="${DEV_PROVIDER_VERSION:-0.0.0-dev}"

usage() {
  cat <<'EOF'
Usage: SWITCH_PASSWORD=... ./deploy-remote-validate.sh

Cross-compiles the provider + netgear-plus-debug, bundles OpenTofu, scp's to
REMOTE_HOST, and runs read-only live validation against the switch.

Environment:
  REMOTE_HOST       SSH target (default: root@casalta-lan.direct.sunbury.xyz)
  REMOTE_DIR        Remote bundle path (default: /tmp/netgear-plus-live-validate)
  SWITCH_HOST       (default: 10.0.2.8)
  SWITCH_PASSWORD   (required)
  AGENT_MAC         (default: 8c:3b:ad:2c:e9:7d)
  GOOS / GOARCH     (default: linux/amd64)
  TOFU_VERSION      OpenTofu release to bundle (default: 1.9.0)
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

rm -rf "${STAGING}"
mkdir -p "${STAGING}/.providers"

echo "==> cross-compile (${GOOS}/${GOARCH})"
(
  cd "${ROOT}"
  CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" \
    go build -o "${STAGING}/.providers/terraform-provider-netgear-plus" .
  CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" \
    go build -o "${STAGING}/netgear-plus-debug" ./cmd/netgear-plus-debug
)

MIRROR_PLATFORM="${GOOS}_${GOARCH}"
MIRROR_PLUGIN_DIR="${STAGING}/provider-mirror/registry.terraform.io/lucavb/netgear-plus/${DEV_PROVIDER_VERSION}/${MIRROR_PLATFORM}"
mkdir -p "${MIRROR_PLUGIN_DIR}"
cp "${STAGING}/.providers/terraform-provider-netgear-plus" \
  "${MIRROR_PLUGIN_DIR}/terraform-provider-netgear-plus_v${DEV_PROVIDER_VERSION}"

echo "==> bundle OpenTofu ${TOFU_VERSION}"
TOFU_ZIP="${STAGING}/tofu.zip"
TOFU_URL="https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}/tofu_${TOFU_VERSION}_${GOOS}_${GOARCH}.zip"
curl -fsSL -o "${TOFU_ZIP}" "${TOFU_URL}"
unzip -qo -j "${TOFU_ZIP}" tofu -d "${STAGING}"
rm -f "${TOFU_ZIP}"
chmod +x "${STAGING}/tofu"

cat >"${STAGING}/terraformrc.tfrc" <<EOF
provider_installation {
  filesystem_mirror {
    path = "${REMOTE_DIR}/provider-mirror"
  }
  direct {
    exclude = ["lucavb/netgear-plus"]
  }
}
EOF

cat >"${STAGING}/read-only.tf" <<EOF
terraform {
  required_providers {
    netgear = {
      source  = "registry.terraform.io/lucavb/netgear-plus"
      version = "${DEV_PROVIDER_VERSION}"
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

cp "${EXAMPLE_DIR}/run-remote-validate.sh" "${STAGING}/run-remote-validate.sh"
cp "${EXAMPLE_DIR}/run-remote-apply-test.sh" "${STAGING}/run-remote-apply-test.sh"
chmod +x "${STAGING}/run-remote-validate.sh" "${STAGING}/run-remote-apply-test.sh"
cp -R "${EXAMPLE_DIR}/live-bench" "${STAGING}/live-bench"
cp "${ROOT}/internal/testfixtures/gs108tv2/factory-reverted.txt" "${STAGING}/live-bench/factory-reverted.txt"

echo "==> scp to ${REMOTE_HOST}:${REMOTE_DIR}"
ssh "${REMOTE_HOST}" "rm -rf '${REMOTE_DIR}' && mkdir -p '${REMOTE_DIR}'"
scp -r "${STAGING}/." "${REMOTE_HOST}:${REMOTE_DIR}/"

REMOTE_ENV="SWITCH_HOST='${SWITCH_HOST}' SWITCH_PASSWORD='${SWITCH_PASSWORD}' AGENT_MAC='${AGENT_MAC}' SKIP_FACTORY_RESTORE='${SKIP_FACTORY_RESTORE:-}' INGEST_WAIT_SEC='${INGEST_WAIT_SEC:-}'"

if [[ "${LIVE_APPLY:-}" == "1" ]]; then
  echo "==> run staged configure test on remote"
  APPLY_CMD="${REMOTE_ENV} '${REMOTE_DIR}/run-remote-apply-test.sh'"
  if [[ "${SKIP_READ_VALIDATE:-}" != "1" ]]; then
    APPLY_CMD="${REMOTE_ENV} '${REMOTE_DIR}/run-remote-validate.sh' && ${APPLY_CMD}"
  fi
  ssh "${REMOTE_HOST}" "${APPLY_CMD}"
else
  echo "==> run validation on remote"
  ssh "${REMOTE_HOST}" \
    "${REMOTE_ENV} '${REMOTE_DIR}/run-remote-validate.sh'"
fi

echo "==> deploy + remote validation OK"
