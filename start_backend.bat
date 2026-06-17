@echo off
echo Starting AI Shield Backend Server...
python -m uvicorn api_server:app --port 8000 --reload
pause
