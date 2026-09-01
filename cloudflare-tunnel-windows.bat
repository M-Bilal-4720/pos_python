@echo off
echo.
echo ==========================================
echo   Islamabad Restaurant ^& Cafe -- Cloudflare Quick Start
echo ==========================================
echo.
echo This opens your restaurant system on the internet
echo so ANY phone/tablet can access it.
echo.
echo Step 1: Make sure Flask is running (python app.py)
echo Step 2: Download cloudflared.exe from:
echo         https://github.com/cloudflare/cloudflared/releases/latest
echo         Place cloudflared.exe in this folder
echo.
echo Press any key to start tunnel (Flask must be running first)...
pause >nul

if not exist "cloudflared.exe" (
  echo.
  echo ERROR: cloudflared.exe not found in this folder!
  echo Download it from: https://github.com/cloudflare/cloudflared/releases/latest
  echo.
  pause
  exit /b 1
)

echo.
echo Starting Cloudflare tunnel...
echo Your public URL will appear below in a few seconds.
echo Share it with your tablets and phones!
echo.
echo Press CTRL+C to stop the tunnel.
echo.
cloudflared.exe tunnel --url http://localhost:5000
