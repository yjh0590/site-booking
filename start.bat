@echo off
chcp 65001 >nul
cd /d "%~dp0"
title 콕콕 예약알림

where python >nul 2>nul || (
  echo [!] Python이 없어요. https://www.python.org/downloads/ 에서 설치해 주세요.
  echo     설치할 때 "Add python.exe to PATH"를 꼭 체크하세요.
  pause & exit /b 1
)

echo 필요한 패키지를 확인하는 중...
python -m pip install -q -r requirements.txt || (echo [!] 패키지 설치 실패 & pause & exit /b 1)

where cloudflared >nul 2>nul || if not exist "%ProgramFiles(x86)%\cloudflared\cloudflared.exe" (
  echo 폰 연결용 cloudflared를 설치하는 중... ^(처음 한 번만^)
  winget install --id Cloudflare.cloudflared -e --silent --accept-source-agreements --accept-package-agreements >nul
)

set PYTHONIOENCODING=utf-8
python server.py
pause
