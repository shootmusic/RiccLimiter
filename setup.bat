@echo off
title RiccLimiter Setup
color 0A
echo ========================================
echo      RICC LIMITER - WINDOWS SETUP
echo ========================================
echo.

:: Cek Admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Jalankan sebagai ADMINISTRATOR!
    echo.
    echo Klik kanan file ini, pilih "Run as Administrator"
    pause
    exit /b 1
)

echo [✓] Admin access OK
echo.

:: Cek Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [⚠️] PYTHON TIDAK TERINSTAL!
    echo.
    echo Download Python dari: https://python.org
    echo PASTIKAN centang "Add Python to PATH"
    echo.
    start https://python.org
    pause
    exit /b 1
) else (
    for /f "tokens=*" %%i in ('python --version') do set pyver=%%i
    echo [✓] %pyver%
)

:: Cek pip
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [⚠️] PIP TIDAK TERINSTAL!
    echo.
    pause
    exit /b 1
) else (
    echo [✓] Pip OK
)

:: Cek Npcap
if exist "C:\Program Files\Npcap" (
    echo [✓] Npcap terinstall
) else (
    echo.
    echo [⚠️] Npcap TIDAK TERINSTAL!
    echo.
    echo Npcap DIPERLUKAN untuk:
    echo - ARP Spoofing
    echo - Packet capture
    echo - DNS Spoofing
    echo.
    echo Download dari: https://npcap.com
    echo PASTIKAN pilih "Install in WinPcap API-compatible Mode"
    echo.
    start https://npcap.com
    echo.
    choice /C YN /M "Lanjutkan setup tanpa Npcap? (tidak disarankan)"
    if errorlevel 2 exit /b 1
)

:: Install requirements
echo.
echo [*] Menginstall dependencies Python...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [✗] Gagal install dependencies
    pause
    exit /b 1
) else (
    echo [✓] Dependencies OK
)

:: Buat shortcut di desktop
echo.
echo [*] Membuat shortcut...
powershell -Command "$WS = New-Object -ComObject WScript.Shell; $SC = $WS.CreateShortcut('%UserProfile%\Desktop\RiccLimiter.lnk'); $SC.TargetPath = 'python.exe'; $SC.Arguments = '""%CD%\ricclimiter_gui.py""'; $SC.WorkingDirectory = '%CD%'; $SC.IconLocation = 'python.exe,0'; $SC.Save()"
echo [✓] Shortcut dibuat di Desktop

:: Selesai
echo.
echo ========================================
echo      SETUP SELESAI!
echo ========================================
echo.
echo Cara menjalankan:
echo 1. Double klik shortcut di Desktop
echo 2. Atau jalankan: python ricclimiter_gui.py
echo.
echo PASTIKAN JALAN SEBAGAI ADMINISTRATOR!
echo.
pause
