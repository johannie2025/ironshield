@echo off
REM Supprime les tâches planifiées IronShield FIM (désinstallation).
REM Les erreurs sont ignorées : une tâche déjà absente n'est pas un échec.

schtasks /Delete /F /TN "IronShieldFIM-Agent" >nul 2>&1
schtasks /Delete /F /TN "IronShieldFIM-Updater" >nul 2>&1

exit /b 0
