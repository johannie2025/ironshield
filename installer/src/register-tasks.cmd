@echo off
REM Enregistre les tâches planifiées IronShield FIM.
REM %~dp0 = dossier contenant ce script (donc le dossier d'installation de
REM l'agent) : évite toute substitution de propriété MSI fragile, le
REM script se localise lui-même une fois installé.

schtasks /Create /F /SC ONSTART /RL HIGHEST /TN "IronShieldFIM-Agent" /TR "\"%~dp0ironshield-agent.exe\""
if errorlevel 1 exit /b 1

schtasks /Create /F /SC HOURLY /MO 6 /RL HIGHEST /TN "IronShieldFIM-Updater" /TR "\"%~dp0ironshield-updater.exe\""
if errorlevel 1 exit /b 1

schtasks /Run /TN "IronShieldFIM-Agent"

exit /b 0
