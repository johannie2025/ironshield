# Installeur unifié IronShield FIM (WiX v4)

Ce dossier construit un unique `.msi` qui embarque :
- `ironshield-agent.exe` (+ `VERSION`, `SHA256SUMS.txt`)
- `ironshield-updater.exe`
- Le GUI Tauri (`ironshield-gui.exe`)
- Deux tâches planifiées Windows :
  - `IronShieldFIM-Agent` (démarrage automatique au boot, exécution continue)
  - `IronShieldFIM-Updater` (vérification toutes les 6h)

## Prérequis

```powershell
dotnet tool install --global wix
wix extension add WixToolset.Util.wixext
```

## Build local

Les binaires doivent déjà être compilés (voir `build-agent.yml` et `build-gui.yml`).

```powershell
wix build installer/src/Product.wxs `
  -d ProductVersion=0.1.0 `
  -d AgentExePath=agent/ironshield-agent.exe `
  -d UpdaterExePath=agent/ironshield-updater.exe `
  -d Sha256SumsPath=agent/SHA256SUMS.txt `
  -d VersionPath=agent/VERSION `
  -d GuiExePath=gui/ironshield-gui.exe `
  -o IronShieldFIM-Setup.msi
```

En CI, `.github/workflows/build-installer.yml` récupère automatiquement les
artefacts des workflows agent/GUI puis exécute cette même commande.
