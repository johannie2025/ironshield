# IronShield FIM

Solution souveraine de monitoring d'intégrité de fichiers (FIM) et de
conformité d'entreprise — 100% user-space, sans composant kernel.

## Composants

| Dossier | Techno | Rôle |
|---|---|---|
| `api/` | PHP 8.2 / MySQL | Licensing, activation, collecte d'événements, alertes |
| `sql/` | MySQL | Schéma de la base |
| `scripts/` | PHP CLI | Génération de licences (hors webroot) |
| `agent/` | Rust (Windows) | Surveillance temps réel (`ReadDirectoryChangesW`), hash SHA-256, envoi API |
| `updater/` | Rust (Windows) | Vérification/téléchargement/application des mises à jour de l'agent |
| `shared/` | Rust | Types partagés agent ↔ updater |
| `src/`, `src-tauri/` | Tauri v2 + React/Tailwind | Dashboard (alertes, pouls d'intégrité) |
| `installer/` | WiX v4 | MSI unifié (agent + updater + GUI + tâches planifiées) |
| `tests/` | Bash + PHP | Tests unitaires et end-to-end |

## Déploiement — API (alwaysdata)

1. Créer la base MySQL, importer `sql/schema.sql`.
2. Configurer les variables d'environnement : `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASS`.
3. Pointer le vhost `wiseshield.alwaysdata.net` sur `api/`.
4. Secrets GitHub à créer : `ALWAYSDATA_HOST`, `ALWAYSDATA_USER`, `ALWAYSDATA_PASSWORD`.
5. Push sur `main` → déploiement automatique (`deploy-api.yml`).

Génération d'une licence en SSH sur alwaysdata :
```bash
php scripts/generate_license.php --client="Client X" --email=x@exemple.com --tier=pro --machines=5 --days=365
```

## Déploiement — Agent / Updater / GUI (GitHub Actions)

| Workflow | Déclencheur | Sortie |
|---|---|---|
| `build-agent.yml` | push sur `agent/`, `updater/`, `shared/`, tag `agent-v*` | `.exe` + `SHA256SUMS.txt` + `VERSION` |
| `build-gui.yml` | push sur `src/`, `src-tauri/`, tag `gui-v*` | `.msi` du dashboard seul |
| `build-installer.yml` | tag `setup-v*` ou déclenchement manuel | `IronShieldFIM-Setup.msi` unifié |
| `e2e-tests.yml` | quotidien ou manuel | Vérifie le flux activate → events → alerts |

### Procédure de release complète

```bash
git tag agent-v0.1.0 && git push origin agent-v0.1.0   # build + release agent/updater
git tag gui-v0.1.0   && git push origin gui-v0.1.0     # build + release GUI
git tag setup-v0.1.0 && git push origin setup-v0.1.0   # assemble le MSI unifié
```
Le workflow `build-installer.yml` télécharge automatiquement les assets des
releases `agent-v*` et `gui-v*` correspondantes puis produit
`IronShieldFIM-Setup.msi`, qui installe :
- l'agent + l'updater dans `Program Files\IronShield FIM\agent\`
- le GUI dans `Program Files\IronShield FIM\gui\`
- deux tâches planifiées Windows (`IronShieldFIM-Agent` au boot, `IronShieldFIM-Updater` toutes les 6h)

## Fonctionnement hors ligne

L'agent est conçu pour un contexte de connectivité instable :

| Fonction | Nécessite internet ? |
|---|---|
| Détection temps réel (FIM) | ❌ Non |
| Scan de fichiers (YARA + hashes) | ❌ Non — base locale embarquée |
| Scan automatique à l'insertion USB | ❌ Non |
| Mise en quarantaine (chiffrée, réversible) | ❌ Non |
| Journalisation locale (SQLite) | ❌ Non |
| Activation initiale de la licence | ✅ Oui (une seule fois, token mis en cache ensuite) |
| Envoi des événements au dashboard | ✅ Oui (mis en file d'attente sinon, synchronisé au retour du réseau) |
| Mise à jour des signatures YARA/hashes | ✅ Oui (best effort, non bloquant) |
| Mise à jour du binaire agent | ✅ Oui (best effort, non bloquant) |

Un poste jamais reconnecté au réseau continue donc de détecter, scanner les
clés USB et mettre en quarantaine les menaces avec sa base de signatures
locale — seul l'envoi des alertes vers le dashboard central est différé.

**Limite assumée :** l'auto-protection (`self_protect.rs`) est un watchdog
mutuel en espace utilisateur. Elle détecte et journalise un arrêt non
autorisé et relance l'agent, mais ne peut pas empêcher un administrateur
local malveillant de le désactiver — cela nécessiterait un composant noyau,
volontairement exclu de ce projet.

## Protections locales (sans internet)

| Menace | Module | Mécanisme |
|---|---|---|
| Ransomware | `ransomware_guard.rs` + `process_killer.rs` | Fichiers-leurres + débit anormal → verrouillage réseau **et terminaison des processus suspects récents** |
| PUP / Adware / hijackers | `pup_cleaner.rs` | Type AdwCleaner : hosts, extensions navigateur, raccourcis détournés, registre, proxy — scan au démarrage puis toutes les 12h |
| Vers (propagation USB) | `autorun_guard.rs` | Désactivation système de l'autorun + neutralisation de tout `autorun.inf` détecté |
| Malware persistant au démarrage | `persistence_scan.rs` | Audit des clés `Run`, tâches planifiées — signale les chemins suspects |
| Fichiers cachés / dissimulation | `hidden_files.rs` | Détection d'exécutables cachés hors zones systèmes + flux ADS NTFS |
| Virus/trojans (signatures) | `scanner.rs` | YARA + hashes, base locale embarquée |
| Exfiltration réseau | `firewall.rs` | Pilote le pare-feu Windows natif (pas de driver custom) |
| Support amovible infecté | `usb_watcher.rs` | Scan complet automatique à l'insertion |

**Sur le pare-feu :** IronShield ne réimplémente pas de moteur de filtrage
réseau — il pilote le pare-feu Windows natif (`netsh advfirewall`), déjà
certifié et présent sur toute installation. Un driver WFP custom
ajouterait une surface d'attaque sans bénéfice réel par rapport à cette
approche, qui reste 100% fonctionnelle hors ligne.

**Sur la réponse ransomware "musclée" :** en cas de détection confirmée
(fichier-leurre touché ou débit anormal), l'agent termine tous les
processus non-système démarrés dans les 5 dernières minutes (hors liste
blanche des processus Windows essentiels), en plus de couper le réseau.
C'est une réponse volontairement large plutôt qu'une corrélation fine
fichier↔processus, qui nécessiterait un composant kernel/ETW. Le
compromis assumé : mieux vaut relancer une application légitime que
perdre des fichiers utilisateur au chiffrement.

## Corrections apportées suite à l'audit de commercialisation

**Mode de réponse configurable (`response_mode` dans `config.toml`)** :
`alert_only` (défaut — détecte et journalise, n'agit jamais), `quarantine_only`,
`full` (quarantaine + réseau + kill de processus). **Le kill-switch n'est
plus jamais actif par défaut** — il doit être activé explicitement après
une période pilote sans faux positif.

**Journal d'audit dédié (`audit_log.rs`)** : chaque action automatique
(quarantaine, kill de processus, verrouillage réseau, neutralisation
autorun) est tracée avec raison et horodatage — indispensable pour traiter
une contestation client sérieusement.

**Allowlist à deux niveaux** :
- Locale (`config.toml`, toujours active même hors ligne)
- Distante (`whitelist_entries` en base, gérée par le support via
  `scripts/whitelist_add.php`, synchronisée par l'agent via `GET /api/config`)

Limite assumée : la synchronisation distante met à jour `config.toml` mais
prend effet au redémarrage de l'agent, pas à chaud (évite une race
condition plutôt que de la masquer).

**Pipeline de signatures réel** : l'updater tire désormais de vraies
sources publiques entretenues (YARA-Forge, abuse.ch MalwareBazaar) au lieu
des 3 règles d'exemple initiales. **Déploiement canari** intégré
(`IRONSHIELD_CANARY_PERCENT`) : une fraction du parc reçoit les mises à
jour de signatures avant diffusion large, pour limiter l'impact d'une
règle défectueuse.

**Rate limiter corrigé** : passage d'un `INSERT` par requête à un compteur
agrégé par bucket (`api_rate_buckets`), qui ne dégrade plus en écriture à
mesure que le parc grossit.

**Endpoint `/api/health`** pour le monitoring externe (uptime, alerting).

Ce qui reste non traité, assumé et documenté dans l'analyse précédente :
compilation/test réel sur Windows (à faire par vos soins), dashboard
multi-tenant fleet-view, portail self-service, escrow de clé de
quarantaine. Voir la conversation précédente pour le détail.

## Tests

```bash
php tests/unit.php                                          # unitaires (aucune dépendance)
E2E_API_BASE=https://wiseshield.alwaysdata.net/api \
E2E_LICENSE_KEY=XXXXX-XXXXX-XXXXX-XXXXX-XXXXX \
  ./tests/e2e.sh                                             # end-to-end contre l'API réelle
```

## Endpoints API

| Méthode | Route | Auth | Description |
|---|---|---|---|
| POST | `/api/activate` | aucune | Active une machine sur une licence |
| POST | `/api/events` | Bearer token machine | Envoie un lot d'événements FIM |
| GET | `/api/alerts` | Bearer token machine | Liste les alertes de la machine |
