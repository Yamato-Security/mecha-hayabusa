# Funktionen

## Datensatzoperationen

Verwalten Sie Datensätze, die für die Analyse verwendet werden.

- **get_dataset_status**  
  Ruft den Status des aktuell geladenen Datensatzes ab.

- **list_datasets**  
  Listet verfügbare CSV-Datensätze für die Analyse auf.  
  Unterstützt Paginierung.

- **switch_dataset**  
  Wechselt den aktiven Analysedatensatz zu einer angegebenen CSV-Datei.

- **unload_dataset**  
  Entlädt die aktuelle `logs`-Tabelle.

- **dataset_profile**  
  Ruft eine Zusammenfassung des Datensatzes ab, einschließlich:
  - Gesamtanzahl der Ereignisse
  - Zeitbereich
  - wichtigste Trends

  Unterstützt Paginierung.

---

## Abfrage & Suche

Durchsuchen und Abfragen von Protokolldaten.

- **run_sql**  
  Führt eine schreibgeschützte `SELECT`-Abfrage gegen die `logs`-Tabelle aus.  
  Enthält integrierte Sicherheitsbeschränkungen.

- **search_all_fields**  
  Führt Stichwortsuchen über alle Spalten oder angegebene Spalten durch.  
  Unterstützt Paginierung.

- **get_event_detail**  
  Ruft ein einzelnes Ereignis im erweiterten `Field / Value`-Format ab.  
  Unterstützt die Suche nach `RecordID` oder Abfragebedingungen.

---

## Zeitleiste & Analyse

Analysieren Sie Angriffsaktivitäten und Ereigniszeitleisten.

- **analyze_mitre_tactics**  
  Führt eine chronologische Analyse der Angriffsphasen durch, gruppiert nach **MITRE ATT&CK-Taktiken**.

- **analyze_host_timeline**  
  Extrahiert chronologische Ereignisse für einen bestimmten Host.  
  Nützlich für die **Verfolgung von Kompromittierungsketten**.

- **correlate_lateral_movement**  
  Korreliert laterale Bewegungsaktivitäten zwischen Hosts innerhalb eines angegebenen Zeitfensters.

- **summarize_events**  
  Aggregiert Protokollereignisse nach einem angegebenen Feld.

- **summarize_by_time_window**  
  Zählt Ereignisse nach Zeitfenster:
  - `1h`
  - `3h`
  - `6h`
  - `12h`
  - `1d`

- **analyze_rule_titles**  
  Aggregiert die Häufigkeit von `RuleTitle`-Vorkommen mit optionalen Filterbedingungen.

---

## Detail- & IOC-Analyse

Extrahieren und analysieren Sie Indikatoren aus Protokolldetails.

- **parse_details_field**  
  Extrahiert Schlüssel/Wert-Paare aus dem `Details`-Feld.  
  Unterstützt Auflistung und eindeutige Aggregation.

- **extract_iocs**  
  Extrahiert **Indikatoren für eine Kompromittierung (IOCs)** aus `Details` und `ExtraFieldInfo`, kategorisiert nach Typ.

- **decode_powershell_commands**  
  Dekodiert Base64-kodierte PowerShell-Befehle, die in Ereignissen gefunden werden.
