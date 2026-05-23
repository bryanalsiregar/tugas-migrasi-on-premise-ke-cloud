@echo off
cd /d "%~dp0"
set "IT_INVENTORY_DATA_DIR=%~dp0data"
set "IT_INVENTORY_PORT=8010"
start "" pythonw.exe "%~dp0app.pyw"
