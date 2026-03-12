@echo off
setlocal enabledelayedexpansion
:: Chuyen vao thu muc chua file bat de tranh loi System32 khi chay Admin
cd /d "%~dp0"
title ScanNetwork - Backend Server
echo ==========================================
echo    SCAN NETWORK PROJECT - RUNNER
echo ==========================================

:: ── Check for Admin ──────────────────────────────────────────────────────────
net session >nul 2>&1
if !errorLevel! == 0 (
    echo [v] Dang chay voi quyen Administrator.
) else (
    echo [!] Ban dang chay voi quyen User thuong.
    echo [?] Co muon chay lai voi quyen Administrator khong? ^(Y/N^)
    set /p choice="Lua chon: "
    if /i "!choice!"=="Y" (
        echo [+] Dang yeu cau quyen Admin...
        powershell -Command "Start-Process '%~f0' -Verb RunAs"
        exit /b
    ) else (
        echo [!] Tiep tuc voi quyen User ^(Mot so tinh nang quet se bi han che^).
    )
)

:: Kiem tra Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [LOI] Khong tim thay Python! Vui long cai dat Python va thu lai.
    pause
    exit /b
)

:: Kiem tra neu dang chay thi restart
echo.
echo [0/2] Kiem tra trang thai dich vu...
netstat -ano | findstr :5000 >nul 2>&1
if %errorlevel% equ 0 (
    echo [!] Phat hien ung dung dang chay tren cong 5000.
    echo [+] Dang tu dong dong phien cu de khoi dong lai...
    for /f "tokens=5" %%a in ('netstat -aon ^| findstr :5000 ^| findstr LISTENING') do (
        taskkill /F /PID %%a >nul 2>&1
    )
    timeout /t 2 /nobreak >nul
    echo [v] Da dong phien cu thanh cong.
) else (
    echo [v] Cong 5000 dang trong.
)

echo.
echo [1/2] Dang kiem tra thu vien...
set LIBRARIES=flask flask-cors python-nmap requests pytz

for %%i in (%LIBRARIES%) do (
    pip show %%i >nul 2>&1
    if errorlevel 1 (
        echo [+] Dang cai dat %%i...
        pip install %%i
    ) else (
        echo [v] %%i da duoc cai dat.
    )
)

echo.
echo [2/2] Dang khoi chay ung dung...
echo Truy cap tai: http://127.0.0.1:5000
echo Nhan Ctrl+C de dung server.
echo.

python app.py

if %errorlevel% neq 0 (
    echo.
    echo [LOI] Co loi xay ra khi chay ung dung.
)

pause
