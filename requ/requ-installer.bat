@echo off
title Bloodline OSINT - Requirements Installer

echo -----------------------------------------
echo   Bloodline OSINT Tool - Setup
echo -----------------------------------------
echo.

echo Python kontrol ediliyor...
python --version >nul 2>&1
IF ERRORLEVEL 1 (
    echo [HATA] Python yüklü degil!
    echo https://www.python.org adresinden yukleyin.
    pause
    exit
)

echo.
echo Pip guncelleniyor...
python -m pip install --upgrade pip

echo.
echo Gereksinimler yukleniyor...
python -m pip install -r requirements.txt

echo.
echo -----------------------------------------
echo Kurulum tamamlandi.
echo Uygulamayi calistirabilirsiniz.
echo -----------------------------------------
pause
