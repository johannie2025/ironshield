// Exemple de règles YARA embarquées avec l'agent (mode 100% hors ligne).
// Ce fichier est remplacé/enrichi par l'updater dès qu'une connexion est
// disponible (source recommandée : flux communautaires open-source de
// signatures YARA). Il reste pleinement utilisable sans connexion.

rule Suspicious_Double_Extension
{
    meta:
        description = "Fichier tentant de masquer son extension réelle (ex: facture.pdf.exe)"
        severity = "warning"
    strings:
        $ext1 = ".pdf.exe" nocase
        $ext2 = ".doc.exe" nocase
        $ext3 = ".jpg.exe" nocase
    condition:
        any of them
}

rule Suspicious_PowerShell_EncodedCommand
{
    meta:
        description = "Script contenant une commande PowerShell encodée en base64 (technique d'obfuscation courante)"
        severity = "warning"
    strings:
        $enc = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
    condition:
        any of them
}

rule Suspicious_Embedded_PE_In_Script
{
    meta:
        description = "Script texte contenant un en-tête d'exécutable Windows embarqué (MZ)"
        severity = "critical"
    strings:
        $mz = { 4D 5A 90 00 03 00 00 00 }
        $script_marker1 = "powershell" nocase
        $script_marker2 = "<script" nocase
    condition:
        $mz and (any of ($script_marker*))
}
