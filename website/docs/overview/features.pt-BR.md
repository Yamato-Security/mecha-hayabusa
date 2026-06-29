# Recursos

## Operações com Conjuntos de Dados

Gerencie os conjuntos de dados usados na análise.

- **get_dataset_status**  
  Recupera o status do conjunto de dados atualmente carregado.

- **list_datasets**  
  Lista os conjuntos de dados CSV disponíveis para análise.  
  Oferece suporte a paginação.

- **switch_dataset**  
  Alterna o conjunto de dados de análise ativo para um arquivo CSV especificado.

- **unload_dataset**  
  Descarrega a tabela `logs` atual.

- **dataset_profile**  
  Recupera um resumo do conjunto de dados, incluindo:
  - contagem total de eventos
  - intervalo de tempo
  - principais tendências

  Oferece suporte a paginação.

---

## Consulta e Pesquisa

Pesquise e consulte dados de log.

- **run_sql**  
  Executa uma consulta `SELECT` somente leitura na tabela `logs`.  
  Inclui restrições de segurança integradas.

- **search_all_fields**  
  Realiza pesquisas por palavra-chave em todas as colunas ou em colunas especificadas.  
  Oferece suporte a paginação.

- **get_event_detail**  
  Recupera um único evento em formato expandido `Field / Value`.  
  Oferece suporte a busca por `RecordID` ou condições de consulta.

---

## Linha do Tempo e Análise

Analise atividades de ataque e linhas do tempo de eventos.

- **analyze_mitre_tactics**  
  Realiza análise cronológica das fases de ataque agrupadas por **MITRE ATT&CK tactics**.

- **analyze_host_timeline**  
  Extrai eventos cronológicos para um host específico.  
  Útil para o **rastreamento de cadeias de comprometimento**.

- **correlate_lateral_movement**  
  Correlaciona atividades de movimento lateral entre hosts dentro de uma janela de tempo especificada.

- **summarize_events**  
  Agrega eventos de log por um campo especificado.

- **summarize_by_time_window**  
  Conta eventos por janela de tempo:
  - `1h`
  - `3h`
  - `6h`
  - `12h`
  - `1d`

- **analyze_rule_titles**  
  Agrega a frequência de ocorrências de `RuleTitle` com condições de filtragem opcionais.

---

## Análise de Detalhes e IOC

Extraia e analise indicadores a partir dos detalhes dos logs.

- **parse_details_field**  
  Extrai pares de chave/valor do campo `Details`.  
  Oferece suporte a listagem e agregação de valores únicos.

- **extract_iocs**  
  Extrai **Indicadores de Comprometimento (IOCs)** de `Details` e `ExtraFieldInfo`, categorizados por tipo.

- **decode_powershell_commands**  
  Decodifica comandos PowerShell codificados em Base64 encontrados nos eventos.
