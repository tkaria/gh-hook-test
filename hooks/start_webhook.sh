#!/usr/bin/env bash
set -euo pipefail

# --- Configuration ---
REPO="tkaria/gh-hook-test"
PORT=5000
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# --- Generate or reuse webhook secret ---
if [ -z "${WEBHOOK_SECRET:-}" ]; then
    WEBHOOK_SECRET=$(openssl rand -hex 20)
    echo "Generated WEBHOOK_SECRET: $WEBHOOK_SECRET"
else
    echo "Using existing WEBHOOK_SECRET from environment."
fi
export WEBHOOK_SECRET

# --- Cleanup function ---
cleanup() {
    echo ""
    echo "Cleaning up..."
    [ -n "${FLASK_PID:-}" ] && kill "$FLASK_PID" 2>/dev/null && echo "  Stopped Flask server (PID $FLASK_PID)"
    [ -n "${NGROK_PID:-}" ] && kill "$NGROK_PID" 2>/dev/null && echo "  Stopped ngrok (PID $NGROK_PID)"
    if [ -n "${HOOK_ID:-}" ]; then
        echo "  Deleting GitHub webhook (ID $HOOK_ID)..."
        gh api -X DELETE "repos/$REPO/hooks/$HOOK_ID" 2>/dev/null && echo "  Webhook deleted." || echo "  Failed to delete webhook."
    fi
    echo "Done."
}
trap cleanup EXIT

# --- Check dependencies ---
for cmd in python3 ngrok gh; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd is not installed." >&2
        exit 1
    fi
done

python3 -c "import flask" 2>/dev/null || { echo "ERROR: flask not installed. Run: pip3 install flask" >&2; exit 1; }

# --- Start Flask server ---
echo "Starting Flask server on port $PORT..."
cd "$SCRIPT_DIR"
python3 webhook_server.py &
FLASK_PID=$!
sleep 2

if ! kill -0 "$FLASK_PID" 2>/dev/null; then
    echo "ERROR: Flask server failed to start." >&2
    exit 1
fi
echo "  Flask server running (PID $FLASK_PID)"

# --- Start ngrok ---
echo "Starting ngrok tunnel to port $PORT..."
ngrok http "$PORT" --log=stdout > /dev/null &
NGROK_PID=$!
sleep 3

if ! kill -0 "$NGROK_PID" 2>/dev/null; then
    echo "ERROR: ngrok failed to start." >&2
    exit 1
fi

# --- Get ngrok public URL ---
NGROK_URL=$(curl -s http://localhost:4040/api/tunnels | python3 -c "
import sys, json
data = json.load(sys.stdin)
tunnels = data.get('tunnels', [])
for t in tunnels:
    if t.get('proto') == 'https':
        print(t['public_url'])
        break
else:
    if tunnels:
        print(tunnels[0]['public_url'])
")

if [ -z "$NGROK_URL" ]; then
    echo "ERROR: Could not get ngrok URL." >&2
    exit 1
fi
echo "  ngrok URL: $NGROK_URL"

# --- Create GitHub webhook ---
WEBHOOK_URL="$NGROK_URL/webhook"
echo "Creating GitHub webhook on $REPO..."
HOOK_RESPONSE=$(gh api "repos/$REPO/hooks" \
    -f "name=web" \
    -f "config[url]=$WEBHOOK_URL" \
    -f "config[content_type]=json" \
    -f "config[secret]=$WEBHOOK_SECRET" \
    -f "events[]=pull_request" \
    -f "active=true")

HOOK_ID=$(echo "$HOOK_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "  Webhook created (ID: $HOOK_ID)"

# --- Summary ---
echo ""
echo "============================================================"
echo "  Webhook server is running!"
echo "============================================================"
echo "  Flask server : http://localhost:$PORT  (PID $FLASK_PID)"
echo "  ngrok tunnel : $NGROK_URL              (PID $NGROK_PID)"
echo "  Webhook URL  : $WEBHOOK_URL"
echo "  Webhook ID   : $HOOK_ID"
echo "  Repository   : $REPO"
echo ""
echo "  Health check : curl $NGROK_URL/health"
echo ""
echo "  Press Ctrl+C to stop and clean up."
echo "============================================================"

# --- Wait for Ctrl+C ---
wait
