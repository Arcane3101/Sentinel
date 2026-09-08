@echo off
title Sentinel
cd /d "%~dp0"

REM Vérifier que le venv existe
if not exist ".venv\Scripts\python.exe" (
    echo [Sentinel] Creation de l'environnement virtuel...
    python -m venv .venv
    .venv\Scripts\pip install -r requirements.txt
)

REM Lancer l'app
.venv\Scripts\pythonw.exe main.py
