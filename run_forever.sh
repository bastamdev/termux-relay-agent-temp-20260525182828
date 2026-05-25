#!/data/data/com.termux/files/usr/bin/bash

set -Eeuo pipefail

SERVER_URL="${SERVER_URL:-}"
RELAY_SECRET="${RELAY_SECRET:-}"
AGENT_NAME="${AGENT_NAME:-termux-agent-1}"
POLL_SECONDS="${POLL_SECONDS:-2}"
PYTHON_BIN="${PYTHON_BIN:-python}"
LOG_DIR="${LOG_DIR:-$HOME/.vpn-relay-agent}"
LOG_FILE="${LOG_DIR}/agent.log"

if [[ -z "$SERVER_URL" ]]; then
    echo "SERVER_URL is required"
    exit 1
fi

if [[ -z "$RELAY_SECRET" ]]; then
    echo "RELAY_SECRET is required"
    exit 1
fi

mkdir -p "$LOG_DIR"

if command -v termux-wake-lock >/dev/null 2>&1; then
    termux-wake-lock || true
fi

cd "$(cd -- "$(dirname -- "$0")" && pwd)"

while true; do
    printf '[%s] starting standalone vpn relay agent\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
    "$PYTHON_BIN" agent.py \
        --server "$SERVER_URL" \
        --secret "$RELAY_SECRET" \
        --agent-name "$AGENT_NAME" \
        --poll-seconds "$POLL_SECONDS" >> "$LOG_FILE" 2>&1 || true
    printf '[%s] agent stopped, retrying in 5 seconds\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
    sleep 5
done