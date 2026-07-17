#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// Backend Tauri volontairement minimal : toute la logique métier vit dans
// le frontend (fetch direct vers l'API HTTPS). Aucune commande Tauri
// privilégiée exposée = surface d'attaque IPC réduite au strict nécessaire.

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("erreur lors du lancement d'IronShield GUI");
}
