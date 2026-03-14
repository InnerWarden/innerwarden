#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${ROOT_DIR}/docs/assets/preview-data"
OUT_DIR="${ROOT_DIR}/docs/assets/screenshots"
BIND="127.0.0.1:8788"
DASHBOARD_URL="http://preview:innerwarden-preview-passphrase-2026@${BIND}"
CHROME_BIN="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
PASSWORD_HASH='$argon2id$v=19$m=19456,t=2,p=1$zkSYFHj7cR64fRpjXfJixQ$mKfiEQLNmjcjm5fpuAF8AgZC5UI+XLVb10u9DE84cv4'

if [[ ! -x "${CHROME_BIN}" ]]; then
  echo "Google Chrome not found at ${CHROME_BIN}" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

cd "${ROOT_DIR}"
INNERWARDEN_DASHBOARD_USER=preview \
INNERWARDEN_DASHBOARD_PASSWORD_HASH="${PASSWORD_HASH}" \
~/.cargo/bin/cargo run -p innerwarden-agent -- \
  --data-dir "${DATA_DIR}" \
  --dashboard \
  --dashboard-bind "${BIND}" \
  > /tmp/innerwarden-dashboard-preview.log 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 30); do
  if curl --silent --fail --user preview:innerwarden-preview-passphrase-2026 "http://${BIND}/api/overview?date=2026-03-13" >/dev/null; then
    break
  fi
  sleep 1
done

curl --silent --fail --user preview:innerwarden-preview-passphrase-2026 "http://${BIND}/api/overview?date=2026-03-13" >/dev/null

"${CHROME_BIN}" --headless=new --disable-gpu --hide-scrollbars \
  --window-size=1440,1100 --virtual-time-budget=5000 \
  --screenshot="${OUT_DIR}/dashboard-overview.png" \
  "${DASHBOARD_URL}/?date=2026-03-13"

"${CHROME_BIN}" --headless=new --disable-gpu --hide-scrollbars \
  --window-size=1440,1400 --virtual-time-budget=6000 \
  --screenshot="${OUT_DIR}/dashboard-journey.png" \
  "${DASHBOARD_URL}/?date=2026-03-13&subject_type=ip&subject=203.0.113.10&window_seconds=300"

"${CHROME_BIN}" --headless=new --disable-gpu --hide-scrollbars \
  --window-size=1440,1400 --virtual-time-budget=6000 \
  --screenshot="${OUT_DIR}/dashboard-clusters.png" \
  "${DASHBOARD_URL}/?date=2026-03-13&pivot=detector&subject_type=detector&subject=ssh_bruteforce&window_seconds=300"

echo "Dashboard previews generated in ${OUT_DIR}"
