@echo off
title Network Anomaly Detection — Demo Launcher
color 0A

echo.
echo  ╔══════════════════════════════════════════════════╗
echo  ║   Network Anomaly Detection System — DEMO       ║
echo  ║   Random Forest · CICIDS 2017 · P1 Elina        ║
echo  ╚══════════════════════════════════════════════════╝
echo.

:: ── Step 1: Clear the database for a clean demo ─────────────────────────────
echo [1/4] Clearing database...
python -c "import sqlite3; conn=sqlite3.connect('anomalies.db'); conn.execute('DELETE FROM anomalies'); conn.commit(); conn.close(); print('      OK — anomalies.db cleared')"
echo.

:: ── Step 2: Start Flask API in a new window ──────────────────────────────────
echo [2/4] Starting Flask API...
start "Flask API — port 5000" cmd /k "color 0B && echo Flask API starting... && python api/app.py"
timeout /t 2 /nobreak >nul
echo       OK — Flask running at http://127.0.0.1:5000
echo.

:: ── Step 3: Start traffic generator in a new window ─────────────────────────
echo [3/4] Starting traffic generator...
start "Traffic Generator" cmd /k "color 0C && echo Traffic generator starting... && python capture/traffic_generator.py"
timeout /t 2 /nobreak >nul
echo       OK — Normal traffic + attack bursts every 15-30s
echo.

:: ── Step 4: Open dashboard in browser ───────────────────────────────────────
echo [4/4] Opening dashboard...
start "" "%~dp0dashboard\index.html"
echo       OK — Dashboard opened in browser
echo.

echo  ══════════════════════════════════════════════════════
echo   Demo is live. Watch the spike chart for attack bursts.
echo   Close the two terminal windows to stop the demo.
echo  ══════════════════════════════════════════════════════
echo.
pause
