@echo off
title Sentinel Antivirus
color 0A

REM On récupère le dossier où se trouve ce script (peu importe où est le raccourci)
set "SCRIPT_DIR=%~dp0"

REM Vérification du venv
if not exist "%SCRIPT_DIR%.venv\Scripts\python.exe" (
    echo [Sentinel] Environnement virtuel introuvable. Installation...
    cd /d "%SCRIPT_DIR%"
    python -m venv .venv
    .venv\Scripts\pip install -r requirements.txt
)

REM Lancement en mode "sans console" (pythonw.exe)
echo [Sentinel] Démarrage de Sentinel...
start "" "%SCRIPT_DIR%.venv\Scripts\pythonw.exe" "%SCRIPT_DIR% main.py"

exit
