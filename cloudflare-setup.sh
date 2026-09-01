#!/bin/bash
# ================================================================
# Islamabad Restaurant & Cafe — Cloudflare Tunnel Setup
# ================================================================
# This script installs cloudflared and creates a quick tunnel so
# your POS / ordering site is accessible from phones/tablets on
# ANY network (not just local WiFi).
#
# Run once:  bash cloudflare-setup.sh
# Then use:  bash cloudflare-run.sh
# ================================================================

set -e
echo ""
echo "=========================================="
echo "  Islamabad Restaurant & Cafe — Cloudflare Tunnel Setup"
echo "=========================================="
echo ""

OS=$(uname -s)

# ── 1. Install cloudflared ──────────────────────────────────────
if command -v cloudflared &>/dev/null; then
  echo "✓ cloudflared already installed ($(cloudflared --version))"
else
  echo "→ Installing cloudflared..."
  if [[ "$OS" == "Linux" ]]; then
    curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
         -o /usr/local/bin/cloudflared
    chmod +x /usr/local/bin/cloudflared
  elif [[ "$OS" == "Darwin" ]]; then
    if command -v brew &>/dev/null; then
      brew install cloudflared
    else
      curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-amd64.tgz | tar xz
      mv cloudflared /usr/local/bin/cloudflared
    fi
  else
    echo "Windows detected — download cloudflared.exe from:"
    echo "https://github.com/cloudflare/cloudflared/releases/latest"
    echo "Place cloudflared.exe in this folder then run:"
    echo "  cloudflared.exe tunnel --url http://localhost:5000"
    exit 0
  fi
  echo "✓ cloudflared installed"
fi

# ── 2. Create run script ────────────────────────────────────────
cat > cloudflare-run.sh << 'RUNSCRIPT'
#!/bin/bash
echo ""
echo "Starting Islamabad Restaurant & Cafe + Cloudflare Tunnel..."
echo ""

# Start Flask in background
cd "$(dirname "$0")"
source venv/bin/activate 2>/dev/null || true
python app.py &
FLASK_PID=$!
echo "Flask PID: $FLASK_PID"

sleep 2
echo ""
echo "Starting Cloudflare Tunnel (Quick Tunnel — no account needed)..."
echo ""
cloudflared tunnel --url http://localhost:5000 &
CF_PID=$!

echo ""
echo "================================================"
echo "  Your tunnel URL will appear above in ~5 seconds"
echo "  Share that URL with your tablets/phones"
echo "  Press CTRL+C to stop everything"
echo "================================================"
echo ""

trap "kill $FLASK_PID $CF_PID 2>/dev/null" EXIT
wait
RUNSCRIPT

chmod +x cloudflare-run.sh

# ── Windows bat file ───────────────────────────────────────────
cat > cloudflare-run.bat << 'WINSCRIPT'
@echo off
echo Starting Islamabad Restaurant ^& Cafe + Cloudflare Tunnel...
echo.
cd /d "%~dp0"
call venv\Scripts\activate.bat 2>nul
start "Flask Server" python app.py
timeout /t 2 /nobreak >nul
echo Starting Cloudflare Tunnel...
cloudflared.exe tunnel --url http://localhost:5000
WINSCRIPT

echo ""
echo "✓ Setup complete!"
echo ""
echo "To start your system + expose it online:"
echo ""
if [[ "$OS" == "Linux" || "$OS" == "Darwin" ]]; then
  echo "  bash cloudflare-run.sh"
else
  echo "  cloudflare-run.bat"
fi
echo ""
echo "After running, Cloudflare will give you a URL like:"
echo "  https://random-words-here.trycloudflare.com"
echo ""
echo "Use that URL on any phone/tablet/device — no port forwarding needed!"
echo ""
echo "Pages at that URL:"
echo "  /          → Customer ordering site"
echo "  /pos        → POS (staff)"
echo "  /kitchen    → Kitchen display"
echo "  /admin      → Admin panel"
echo ""
