**Version:** 0.2.7 (PowerShell 5.1 or higher)  
**Author:** Andreas Hepp  
**Last Update:** 16/03/2023  
**Website:** www.psscripts.de

---

# easyADGroups
This script (`easyADgroup.ps1`) provides a GUI-based interface for managing Active Directory groups. It allows both simple single-group creation and advanced batch/series creation, including special modes for JIRA/Confluence group sets.

## Features
- **Create AD Groups** with various parameters (name prefix, separator, description, etc.)  
- **Batch Group Creation** using start/end number ranges  
- **Special Mode** for JIRA/Confluence group sets (additional suffixes from the INI)  
- **Group Type** selection (Security vs. Distribution)  
- **Group Scope** options (Global, Universal, DomainLocal)  
- **Automatic User Assignment** (adds selected users and optional fixed members from the INI)  
- **OU Filtering** and selection for precise group placement

## Requirements
- **Administrative Rights**  
  The script must be run as an administrator.
- **PowerShell 5.1** (or higher)  
  Ensures compatibility with the GUI elements and AD module.
- **Active Directory Module** for PowerShell  
  Required for creating and modifying groups. Make sure RSAT is installed if running on a client OS.
- **INI Configuration File** (`easyADGroups.ini`)  
  Contains various settings like default descriptions, suffixes, logging info, etc.

## Usage
1. Copy `easyADgroup.ps1` and `easyADGroups.ini` into the same directory.  
2. Run `easyADgroup.ps1` from a **PowerShell 5.1** (or higher) session with **administrator privileges**.  
3. The GUI will launch and allow you to specify:
   - **Group Names** (prefix, separator, optional numbering, description)  
   - **Group Type** (Security/Distribution)  
   - **Scope** (Global, Universal, DomainLocal)  
   - **Optional Special Mode** for JIRA/Confluence sets  
   - **Users** to add as members  
   - **OU** where the group(s) should be created  
4. Click **Preview** to see which group names will be created, then **Create** to perform the operation.

## License
This project is released under the [MIT License](https://opensource.org/licenses/MIT). You are free to use, modify, and redistribute this code.

## Contributions
Contributions, suggestions, and feedback are always welcome!  
Please open an issue or submit a pull request if you have any ideas or improvements.

---

# easyADgroup
Dieses Skript (`easyADgroup.ps1`) stellt eine GUI-basierte Oberfläche zur Verwaltung von Active-Directory-Gruppen bereit. Es ermöglicht sowohl die einfache Erstellung einzelner Gruppen als auch fortgeschrittene Serienerstellungen – inklusive eines Spezialmodus für JIRA/Confluence-Gruppensets.

## Funktionen
- **Erstellung von AD-Gruppen** mit verschiedenen Parametern (Name, Trenner, Beschreibung usw.)  
- **Serielle Gruppenerstellung** mittels Start-/Endnummern  
- **Spezialmodus** für JIRA/Confluence-Gruppen (weitere Suffixe aus der INI)  
- **Gruppentyp** wählen (Sicherheits- vs. Verteilergruppen)  
- **Gruppengeltungsbereich** (Global, Universal, DomainLocal)  
- **Automatische Benutzerzuweisung** (fügt ausgewählte Benutzer und optionale feste Mitglieder aus der INI hinzu)  
- **OU-Filterung** und Auswahl für präzise Platzierung der Gruppen

## Voraussetzungen
- **Administratorrechte**  
  Das Skript muss als Administrator ausgeführt werden.
- **PowerShell 5.1** (oder höher)  
  Sorgt für Kompatibilität mit den GUI-Elementen und dem AD-Modul.
- **Active Directory Modul** für PowerShell  
  Erforderlich, um Gruppen anzulegen und zu verwalten. Unter Windows-Clients müssen dafür ggf. die RSAT-Tools installiert sein.
- **INI-Konfigurationsdatei** (`easyADGroups.ini`)  
  Enthält verschiedene Einstellungen wie Standard-Beschreibungen, Suffixe, Logging-Informationen usw.

## Verwendung
1. Kopiere `easyADgroup.ps1` und `easyADGroups.ini` in dasselbe Verzeichnis.  
2. Starte `easyADgroup.ps1` in einer **PowerShell-5.1**- (oder höher) Sitzung mit **Administratorrechten**.  
3. Die GUI wird gestartet und ermöglicht dir:  
   - **Gruppennamen** (Prefix, Trenner, optionale Nummerierung, Beschreibung)  
   - **Gruppentyp** (Security/Distribution)  
   - **Geltungsbereich** (Global, Universal, DomainLocal)  
   - **Optionaler Spezialmodus** für JIRA/Confluence-Gruppen  
   - **Benutzer** als Mitglieder hinzuzufügen  
   - **OU** für die Platzierung der Gruppe(n)  
4. Über **Preview** kannst du prüfen, welche Gruppen erstellt werden, und anschließend über **Create** den Vorgang ausführen.

## Lizenz
Dieses Projekt wird unter der [MIT Lizenz](https://opensource.org/licenses/MIT) veröffentlicht. Du bist frei, den Code zu verwenden, anzupassen und weiterzuverbreiten.

## Beiträge
Beiträge, Vorschläge und Feedback sind immer willkommen!  
Erstelle gerne ein Issue oder einen Pull Request, wenn du Ideen oder Verbesserungen hast.
