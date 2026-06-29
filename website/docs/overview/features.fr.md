# Fonctionnalités

## Opérations sur les jeux de données

Gérer les jeux de données utilisés pour l'analyse.

- **get_dataset_status**  
  Récupérer l'état du jeu de données actuellement chargé.

- **list_datasets**  
  Lister les jeux de données CSV disponibles pour l'analyse.  
  Prend en charge la pagination.

- **switch_dataset**  
  Basculer le jeu de données d'analyse actif vers un fichier CSV spécifié.

- **unload_dataset**  
  Décharger la table `logs` actuelle.

- **dataset_profile**  
  Récupérer un résumé du jeu de données, comprenant :
  - le nombre total d'événements
  - la plage temporelle
  - les principales tendances

  Prend en charge la pagination.

---

## Requête et recherche

Rechercher et interroger les données de journaux.

- **run_sql**  
  Exécuter une requête `SELECT` en lecture seule sur la table `logs`.  
  Inclut des contraintes de sécurité intégrées.

- **search_all_fields**  
  Effectuer des recherches par mots-clés dans toutes les colonnes ou des colonnes spécifiées.  
  Prend en charge la pagination.

- **get_event_detail**  
  Récupérer un événement unique au format développé `Field / Value`.  
  Prend en charge la recherche par `RecordID` ou par conditions de requête.

---

## Chronologie et analyse

Analyser l'activité d'attaque et les chronologies d'événements.

- **analyze_mitre_tactics**  
  Effectuer une analyse chronologique des phases d'attaque regroupées par **tactiques MITRE ATT&CK**.

- **analyze_host_timeline**  
  Extraire les événements chronologiques pour un hôte spécifique.  
  Utile pour le **suivi de la chaîne de compromission**.

- **correlate_lateral_movement**  
  Corréler l'activité de déplacement latéral entre les hôtes au sein d'une fenêtre temporelle spécifiée.

- **summarize_events**  
  Agréger les événements de journaux selon un champ spécifié.

- **summarize_by_time_window**  
  Compter les événements par fenêtre temporelle :
  - `1h`
  - `3h`
  - `6h`
  - `12h`
  - `1d`

- **analyze_rule_titles**  
  Agréger la fréquence des occurrences de `RuleTitle` avec des conditions de filtrage facultatives.

---

## Analyse des détails et des IOC

Extraire et analyser les indicateurs à partir des détails des journaux.

- **parse_details_field**  
  Extraire les paires clé/valeur du champ `Details`.  
  Prend en charge le listage et l'agrégation unique.

- **extract_iocs**  
  Extraire les **indicateurs de compromission (IOC)** de `Details` et `ExtraFieldInfo`, catégorisés par type.

- **decode_powershell_commands**  
  Décoder les commandes PowerShell encodées en Base64 trouvées dans les événements.
