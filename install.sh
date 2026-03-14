#!/usr/bin/env bash
set -euo pipefail

# Inner Warden installer (production trial profile)
#
# Default mode: downloads pre-built binaries from GitHub Releases (~10 s).
# Source mode:  INNERWARDEN_BUILD_FROM_SOURCE=1 — builds from source with cargo.
#
# One-liner:
#   curl -fsSL https://github.com/maiconburn/innerwarden/releases/latest/download/install.sh | sudo bash
#
# What this script does:
# - Downloads (or builds) sensor + agent + ctl binaries
# - Validates SHA-256 of downloaded binaries
# - Installs binaries to /usr/local/bin
# - Creates /etc/innerwarden/{config.toml,agent.toml,agent.env}
# - Creates systemd units for sensor + agent
# - Configures a SAFE trial mode:
#   * OpenAI analysis enabled
#   * responder.enabled = false (no skill execution)
#   * dry_run = true
#   * only block-ip-ufw in allowed_skills

GITHUB_REPO="maiconburn/innerwarden"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IW_USER="innerwarden"

BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/innerwarden"
DATA_DIR="/var/lib/innerwarden"

SENSOR_BIN="${BIN_DIR}/innerwarden-sensor"
AGENT_BIN="${BIN_DIR}/innerwarden-agent"

SENSOR_CONFIG="${CONFIG_DIR}/config.toml"
AGENT_CONFIG="${CONFIG_DIR}/agent.toml"
AGENT_ENV="${CONFIG_DIR}/agent.env"

SENSOR_UNIT="/etc/systemd/system/innerwarden-sensor.service"
AGENT_UNIT="/etc/systemd/system/innerwarden-agent.service"
AUDIT_RULE_FILE="/etc/audit/rules.d/innerwarden-shell-audit.rules"

log() {
  printf '[innerwarden-install] %s\n' "$*"
}

fail() {
  printf '[innerwarden-install] ERROR: %s\n' "$*" >&2
  exit 1
}

normalize_bool() {
  case "${1,,}" in
    1|true|yes|y|on)
      echo "true"
      ;;
    *)
      echo "false"
      ;;
  esac
}

prompt_yes_no() {
  local question="$1"
  local default_answer="$2" # yes|no
  local suffix answer normalized

  if [[ "${default_answer}" == "yes" ]]; then
    suffix="[Y/n]"
  else
    suffix="[y/N]"
  fi

  read -r -p "${question} ${suffix} " answer
  answer="${answer:-${default_answer}}"
  normalized="$(normalize_bool "${answer}")"
  [[ "${normalized}" == "true" ]]
}

if [[ "$(uname -s)" != "Linux" ]]; then
  fail "this installer currently supports Linux hosts only"
fi

if ! command -v systemctl >/dev/null 2>&1; then
  fail "systemctl not found; this installer requires systemd"
fi

if [[ "$(id -u)" -eq 0 ]]; then
  SUDO=""
elif command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
else
  fail "sudo not found and current user is not root"
fi

run_root() {
  if [[ -n "${SUDO}" ]]; then
    "${SUDO}" "$@"
  else
    "$@"
  fi
}

backup_if_exists() {
  local path="$1"
  if run_root test -f "$path"; then
    local backup
    backup="${path}.bak.$(date +%Y%m%d%H%M%S)"
    run_root cp "$path" "$backup"
    log "backup created: ${backup}"
  fi
}

install_from_stdin() {
  local target="$1"
  local mode="$2"
  local owner="$3"
  local group="$4"

  local tmp
  tmp="$(mktemp)"
  cat > "${tmp}"

  backup_if_exists "${target}"
  run_root install -o "${owner}" -g "${group}" -m "${mode}" "${tmp}" "${target}"
  rm -f "${tmp}"
}

OPENAI_API_KEY="${OPENAI_API_KEY:-}"
if [[ -z "${OPENAI_API_KEY}" ]]; then
  if [[ -t 0 ]]; then
    read -r -s -p "Enter OPENAI_API_KEY (sk-...): " OPENAI_API_KEY
    echo
  else
    fail "OPENAI_API_KEY not set. Export it before running in non-interactive mode."
  fi
fi

if [[ -z "${OPENAI_API_KEY}" ]]; then
  fail "OPENAI_API_KEY cannot be empty"
fi

ENABLE_EXEC_AUDIT="${INNERWARDEN_ENABLE_EXEC_AUDIT:-}"
ENABLE_EXEC_AUDIT_TTY="${INNERWARDEN_ENABLE_EXEC_AUDIT_TTY:-}"

if [[ -t 0 && -z "${ENABLE_EXEC_AUDIT}" ]]; then
  echo
  echo "Privacy notice:"
  echo "  Shell auditing can capture executed commands and, if enabled, terminal input."
  echo "  This may include sensitive or personal data."
  echo "  Enable only with explicit legal authorization from the host owner."
  if prompt_yes_no "Enable shell command audit trail (auditd EXECVE)?" "no"; then
    ENABLE_EXEC_AUDIT="true"
  else
    ENABLE_EXEC_AUDIT="false"
  fi
fi

ENABLE_EXEC_AUDIT="$(normalize_bool "${ENABLE_EXEC_AUDIT:-false}")"

if [[ "${ENABLE_EXEC_AUDIT}" == "true" ]]; then
  if [[ -t 0 && -z "${ENABLE_EXEC_AUDIT_TTY}" ]]; then
    if prompt_yes_no "Also ingest auditd TTY input records when available? (higher privacy impact)" "no"; then
      ENABLE_EXEC_AUDIT_TTY="true"
    else
      ENABLE_EXEC_AUDIT_TTY="false"
    fi
  fi
  ENABLE_EXEC_AUDIT_TTY="$(normalize_bool "${ENABLE_EXEC_AUDIT_TTY:-false}")"
else
  ENABLE_EXEC_AUDIT_TTY="false"
fi

BUILD_FROM_SOURCE="${INNERWARDEN_BUILD_FROM_SOURCE:-0}"

# ── Detect architecture ──────────────────────────────────────────────────────
detect_arch() {
  case "$(uname -m)" in
    x86_64)        echo "x86_64"  ;;
    aarch64|arm64) echo "aarch64" ;;
    *) fail "unsupported architecture: $(uname -m) — use INNERWARDEN_BUILD_FROM_SOURCE=1 to build locally" ;;
  esac
}

# ── Download a binary from GitHub Releases and validate its SHA-256 ──────────
download_asset() {
  local binary="$1"   # e.g. innerwarden-sensor
  local dest="$2"     # destination file path
  local version="$3"  # e.g. v0.2.0
  local arch="$4"     # x86_64 | aarch64

  local asset="${binary}-linux-${arch}"
  local base_url="https://github.com/${GITHUB_REPO}/releases/download/${version}"

  log "downloading ${asset}..."
  curl -fsSL --output "${dest}" "${base_url}/${asset}"

  if curl -fsSL "${base_url}/${asset}.sha256" | awk '{print $1}' > /tmp/iw-expected-sha256 2>/dev/null; then
    local expected actual
    expected="$(cat /tmp/iw-expected-sha256)"
    actual="$(sha256sum "${dest}" | awk '{print $1}')"
    rm -f /tmp/iw-expected-sha256
    if [[ "${expected}" != "${actual}" ]]; then
      fail "SHA-256 mismatch for ${asset}:\n  expected: ${expected}\n  got:      ${actual}"
    fi
    log "SHA-256 ok"
  else
    log "warning: no SHA-256 sidecar for ${asset} — skipping integrity check"
  fi
}

if [[ "${BUILD_FROM_SOURCE}" == "1" ]]; then
  # ── Build from source (development / unsupported arch) ──────────────────
  if ! command -v cargo >/dev/null 2>&1; then
    log "cargo not found. Installing rustup (user install)..."
    curl -sSf https://sh.rustup.rs | sh -s -- -y
  fi
  # shellcheck disable=SC1090
  source "${HOME}/.cargo/env"
  log "ensuring stable Rust toolchain..."
  rustup toolchain install stable >/dev/null
  rustup default stable >/dev/null
  cd "${ROOT_DIR}"
  log "building innerwarden-sensor + innerwarden-agent + innerwarden-ctl (release)..."
  cargo build --release -p innerwarden-sensor -p innerwarden-agent -p innerwarden-ctl
  IW_SENSOR_BIN="${ROOT_DIR}/target/release/innerwarden-sensor"
  IW_AGENT_BIN="${ROOT_DIR}/target/release/innerwarden-agent"
  IW_CTL_BIN="${ROOT_DIR}/target/release/innerwarden-ctl"
else
  # ── Download pre-built binaries from GitHub Releases (~10 s) ────────────
  if ! command -v curl >/dev/null 2>&1; then
    fail "curl is required to download binaries (apt install curl)"
  fi
  if ! command -v sha256sum >/dev/null 2>&1; then
    fail "sha256sum is required for integrity checks (apt install coreutils)"
  fi

  ARCH="$(detect_arch)"

  # Resolve version: env override or latest from GitHub API
  if [[ -n "${INNERWARDEN_VERSION:-}" ]]; then
    IW_VERSION="${INNERWARDEN_VERSION}"
  else
    log "fetching latest release version..."
    IW_VERSION="$(curl -fsSL \
      -H "Accept: application/vnd.github+json" \
      "${GITHUB_API}/releases/latest" \
      | grep '"tag_name"' | head -1 \
      | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
    [[ -n "${IW_VERSION}" ]] || fail "could not determine latest release version from GitHub API"
  fi

  log "installing InnerWarden ${IW_VERSION} for linux/${ARCH}"

  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "${TMP_DIR}"' EXIT

  download_asset "innerwarden-sensor" "${TMP_DIR}/innerwarden-sensor" "${IW_VERSION}" "${ARCH}"
  download_asset "innerwarden-agent"  "${TMP_DIR}/innerwarden-agent"  "${IW_VERSION}" "${ARCH}"
  download_asset "innerwarden-ctl"    "${TMP_DIR}/innerwarden-ctl"    "${IW_VERSION}" "${ARCH}"

  IW_SENSOR_BIN="${TMP_DIR}/innerwarden-sensor"
  IW_AGENT_BIN="${TMP_DIR}/innerwarden-agent"
  IW_CTL_BIN="${TMP_DIR}/innerwarden-ctl"
fi

NOLOGIN_BIN="$(command -v nologin || echo /usr/sbin/nologin)"
if ! id "${IW_USER}" >/dev/null 2>&1; then
  log "creating service user: ${IW_USER}"
  run_root useradd -r -s "${NOLOGIN_BIN}" "${IW_USER}"
fi

for grp in adm systemd-journal docker audit; do
  if getent group "${grp}" >/dev/null 2>&1; then
    run_root usermod -aG "${grp}" "${IW_USER}"
  fi
done

run_root mkdir -p "${CONFIG_DIR}" "${DATA_DIR}"
# Allow the service user to traverse/read config files without making them world-readable.
run_root chown root:"${IW_USER}" "${CONFIG_DIR}"
run_root chmod 750 "${CONFIG_DIR}"
run_root chown "${IW_USER}:${IW_USER}" "${DATA_DIR}"
run_root chmod 750 "${DATA_DIR}"

log "installing binaries to ${BIN_DIR}"
run_root install -o root -g root -m 755 "${IW_SENSOR_BIN}" "${SENSOR_BIN}"
run_root install -o root -g root -m 755 "${IW_AGENT_BIN}"  "${AGENT_BIN}"
run_root install -o root -g root -m 755 "${IW_CTL_BIN}"    "${BIN_DIR}/innerwarden-ctl"
run_root install -o root -g root -m 755 "${IW_CTL_BIN}"    "${BIN_DIR}/innerwarden"

HOST_ID="$(hostname -f 2>/dev/null || hostname)"

log "writing sensor config: ${SENSOR_CONFIG}"
install_from_stdin "${SENSOR_CONFIG}" 640 root "${IW_USER}" <<EOF
[agent]
host_id = "${HOST_ID}"

[output]
data_dir = "${DATA_DIR}"
write_events = true

[collectors.auth_log]
enabled = true
path = "/var/log/auth.log"

[collectors.journald]
enabled = true
units = ["sshd", "sudo"]

[collectors.exec_audit]
enabled = ${ENABLE_EXEC_AUDIT}
path = "/var/log/audit/audit.log"
include_tty = ${ENABLE_EXEC_AUDIT_TTY}

[collectors.docker]
enabled = false

[collectors.integrity]
enabled = true
poll_seconds = 60
paths = ["/etc/ssh/sshd_config", "/etc/sudoers"]

[detectors.ssh_bruteforce]
enabled = true
threshold = 8
window_seconds = 300

[detectors.sudo_abuse]
enabled = false
threshold = 3
window_seconds = 300
EOF

if [[ "${ENABLE_EXEC_AUDIT}" == "true" ]]; then
  log "shell command audit enabled (include_tty=${ENABLE_EXEC_AUDIT_TTY})"
  if run_root test -d /etc/audit/rules.d; then
    log "writing auditd rules: ${AUDIT_RULE_FILE}"
    install_from_stdin "${AUDIT_RULE_FILE}" 640 root root <<'EOF'
# Inner Warden shell command trail (installed with explicit consent)
-a always,exit -F arch=b64 -S execve -k innerwarden-shell-exec
-a always,exit -F arch=b32 -S execve -k innerwarden-shell-exec
EOF
    if command -v augenrules >/dev/null 2>&1; then
      if run_root augenrules --load >/dev/null 2>&1; then
        log "auditd rules loaded via augenrules"
      else
        log "WARNING: failed to load auditd rules via augenrules"
      fi
    elif command -v auditctl >/dev/null 2>&1; then
      if run_root auditctl -R "${AUDIT_RULE_FILE}" >/dev/null 2>&1; then
        log "auditd rules loaded via auditctl"
      else
        log "WARNING: failed to load auditd rules via auditctl"
      fi
    else
      log "WARNING: augenrules/auditctl not found; exec trail may remain disabled until auditd is configured"
    fi
  else
    log "WARNING: /etc/audit/rules.d not found; cannot install exec audit rules automatically"
  fi

  if [[ "${ENABLE_EXEC_AUDIT_TTY}" == "true" ]]; then
    log "TTY ingestion enabled in sensor config; host must emit auditd type=TTY records (e.g. via pam_tty_audit policy)"
  fi
fi

log "writing agent config: ${AGENT_CONFIG}"
install_from_stdin "${AGENT_CONFIG}" 640 root "${IW_USER}" <<EOF
[narrative]
enabled = true
keep_days = 7

[webhook]
enabled = false

[ai]
enabled = true
provider = "openai"
model = "gpt-4o-mini"
context_events = 20
confidence_threshold = 1.01
incident_poll_secs = 2

[honeypot]
mode = "demo"
bind_addr = "127.0.0.1"
port = 2222
http_port = 8080
duration_secs = 300
services = ["ssh"]
strict_target_only = true
allow_public_listener = false
max_connections = 64
max_payload_bytes = 512
isolation_profile = "strict_local"
require_high_ports = true
forensics_keep_days = 7
forensics_max_total_mb = 128
transcript_preview_bytes = 96
lock_stale_secs = 1800

[honeypot.sandbox]
enabled = false
runner_path = ""
clear_env = true

[honeypot.pcap_handoff]
enabled = false
timeout_secs = 15
max_packets = 120

[honeypot.containment]
mode = "process"
require_success = false
namespace_runner = "unshare"
namespace_args = ["--fork", "--pid", "--mount-proc"]
jail_runner = "bwrap"
jail_args = []
jail_profile = "standard"
allow_namespace_fallback = true

[honeypot.external_handoff]
enabled = false
command = "/usr/local/bin/iw-handoff"
args = ["--session-id", "{session_id}", "--target", "{target_ip}", "--metadata", "{metadata_path}", "--evidence", "{evidence_path}", "--pcap", "{pcap_path}"]
timeout_secs = 20
require_success = false
clear_env = true
allowed_commands = ["/usr/local/bin/iw-handoff"]
enforce_allowlist = false
signature_enabled = false
signature_key_env = "INNERWARDEN_HANDOFF_SIGNING_KEY"
attestation_enabled = false
attestation_key_env = "INNERWARDEN_HANDOFF_ATTESTATION_KEY"
attestation_prefix = "IW_ATTEST"
attestation_expected_receiver = ""

[honeypot.redirect]
enabled = false
backend = "iptables"

[responder]
enabled = false
dry_run = true
block_backend = "ufw"
allowed_skills = ["block-ip-ufw"]
EOF

log "writing environment file: ${AGENT_ENV}"
tmp_env="$(mktemp)"
printf 'OPENAI_API_KEY=%s\n' "${OPENAI_API_KEY}" > "${tmp_env}"
backup_if_exists "${AGENT_ENV}"
run_root install -o root -g "${IW_USER}" -m 640 "${tmp_env}" "${AGENT_ENV}"
rm -f "${tmp_env}"

log "writing systemd unit: ${SENSOR_UNIT}"
install_from_stdin "${SENSOR_UNIT}" 644 root root <<'EOF'
[Unit]
Description=Inner Warden - Sensor (host observability)
After=network.target syslog.target
Documentation=https://github.com/maiconburn/innerwarden

[Service]
Type=simple
User=innerwarden
Group=innerwarden
SupplementaryGroups=adm systemd-journal
ExecStart=/usr/local/bin/innerwarden-sensor --config /etc/innerwarden/config.toml
Restart=on-failure
RestartSec=5
TimeoutStopSec=10
KillSignal=SIGTERM
SendSIGKILL=yes
StandardOutput=journal
StandardError=journal
SyslogIdentifier=innerwarden-sensor
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/innerwarden
ReadOnlyPaths=/var/log /etc/innerwarden
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF

log "writing systemd unit: ${AGENT_UNIT}"
install_from_stdin "${AGENT_UNIT}" 644 root root <<'EOF'
[Unit]
Description=Inner Warden - Agent (AI analysis and audit)
After=network-online.target innerwarden-sensor.service
Wants=network-online.target
Requires=innerwarden-sensor.service
Documentation=https://github.com/maiconburn/innerwarden

[Service]
Type=simple
User=innerwarden
Group=innerwarden
EnvironmentFile=/etc/innerwarden/agent.env
ExecStart=/usr/local/bin/innerwarden-agent --data-dir /var/lib/innerwarden --config /etc/innerwarden/agent.toml
Restart=on-failure
RestartSec=5
TimeoutStopSec=10
KillSignal=SIGTERM
SendSIGKILL=yes
StandardOutput=journal
StandardError=journal
SyslogIdentifier=innerwarden-agent
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/innerwarden
ReadOnlyPaths=/etc/innerwarden
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF

log "reloading systemd and starting services..."
run_root systemctl daemon-reload
run_root systemctl enable innerwarden-sensor innerwarden-agent >/dev/null
run_root systemctl restart innerwarden-sensor
run_root systemctl restart innerwarden-agent

if ! run_root systemctl is-active --quiet innerwarden-sensor; then
  fail "innerwarden-sensor failed to start. Check: sudo journalctl -u innerwarden-sensor -n 200"
fi

if ! run_root systemctl is-active --quiet innerwarden-agent; then
  fail "innerwarden-agent failed to start. Check: sudo journalctl -u innerwarden-agent -n 200"
fi

log "installation complete."
log "services are running in SAFE trial mode (analysis-only):"
log "  responder.enabled = false"
log "  responder.dry_run = true"
echo
echo "Useful commands:"
echo "  innerwarden status                              — system overview"
echo "  innerwarden doctor                              — diagnose any issues"
echo "  innerwarden list                                — show available capabilities"
echo "  sudo systemctl status innerwarden-sensor --no-pager"
echo "  sudo systemctl status innerwarden-agent --no-pager"
echo "  sudo journalctl -u innerwarden-sensor -f --no-pager"
echo "  sudo journalctl -u innerwarden-agent -f --no-pager"
echo "  ls -lah ${DATA_DIR}"
echo
echo "To move to dry-run execution validation later:"
echo "  1) Edit ${AGENT_CONFIG}"
echo "  2) Set [responder] enabled = true (keep dry_run = true)"
echo "  3) sudo systemctl restart innerwarden-agent"
