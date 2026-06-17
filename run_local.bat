@echo off
title AI Shield Local Launcher
echo ==========================================
echo       🛡️ AI Shield Local Launcher 🛡️
echo ==========================================
echo.

echo [1/2] Launching Python Backend (FastAPI) on port 8000...
start "AI Shield Backend (FastAPI)" cmd /k "python -m uvicorn api_server:app --port 8000 --reload"

echo [2/2] Launching React Frontend (Vite) on port 5173...
start "AI Shield Frontend (Vite)" cmd /k "cd frontend && npm run dev"

echo.
echo ==========================================
echo ✅ Both servers are launching!
echo.
echo - Backend API:  http://localhost:8000
echo - Web Frontend: http://localhost:5173
echo ==========================================
echo.
pause
