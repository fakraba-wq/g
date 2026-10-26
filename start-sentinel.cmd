@echo off
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Install Node.js 22 or later from https://nodejs.org and run this file again.
  pause
  exit /b 1
)
node -e "if(Number(process.versions.node.split('.')[0]) < 22) process.exit(1)"
if errorlevel 1 (
  echo Node.js 22 or later is required.
  pause
  exit /b 1
)
echo Open http://localhost:3000 in your browser after the server starts.
echo Keep this window open while using Sentinel. Press Ctrl+C to stop.
node server.js
pause
