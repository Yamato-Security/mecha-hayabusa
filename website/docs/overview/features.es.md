# Funcionalidades

## Operaciones con conjuntos de datos

Gestionar los conjuntos de datos utilizados para el análisis.

- **get_dataset_status**  
  Obtener el estado del conjunto de datos cargado actualmente.

- **list_datasets**  
  Listar los conjuntos de datos CSV disponibles para el análisis.  
  Admite paginación.

- **switch_dataset**  
  Cambiar el conjunto de datos de análisis activo a un archivo CSV especificado.

- **unload_dataset**  
  Descargar la tabla `logs` actual.

- **dataset_profile**  
  Obtener un resumen del conjunto de datos, que incluye:
  - recuento total de eventos
  - rango temporal
  - tendencias principales

  Admite paginación.

---

## Consulta y búsqueda

Buscar y consultar datos de registros.

- **run_sql**  
  Ejecutar una consulta `SELECT` de solo lectura sobre la tabla `logs`.  
  Incluye restricciones de seguridad integradas.

- **search_all_fields**  
  Realizar búsquedas por palabras clave en todas las columnas o en columnas especificadas.  
  Admite paginación.

- **get_event_detail**  
  Obtener un único evento en formato expandido `Field / Value`.  
  Admite la búsqueda por `RecordID` o por condiciones de consulta.

---

## Línea temporal y analítica

Analizar la actividad de ataque y las líneas temporales de eventos.

- **analyze_mitre_tactics**  
  Realizar un análisis cronológico de las fases de ataque agrupadas por **tácticas de MITRE ATT&CK**.

- **analyze_host_timeline**  
  Extraer eventos cronológicos para un host específico.  
  Útil para el **seguimiento de la cadena de compromiso**.

- **correlate_lateral_movement**  
  Correlacionar la actividad de movimiento lateral entre hosts dentro de una ventana temporal especificada.

- **summarize_events**  
  Agregar eventos de registro por un campo especificado.

- **summarize_by_time_window**  
  Contar eventos por ventana temporal:
  - `1h`
  - `3h`
  - `6h`
  - `12h`
  - `1d`

- **analyze_rule_titles**  
  Agregar la frecuencia de apariciones de `RuleTitle` con condiciones de filtrado opcionales.

---

## Análisis de detalles e IOC

Extraer y analizar indicadores a partir de los detalles de los registros.

- **parse_details_field**  
  Extraer pares clave/valor del campo `Details`.  
  Admite listado y agregación de valores únicos.

- **extract_iocs**  
  Extraer **Indicadores de Compromiso (IOC)** de `Details` y `ExtraFieldInfo`, categorizados por tipo.

- **decode_powershell_commands**  
  Decodificar comandos de PowerShell codificados en Base64 encontrados en los eventos.
