# 기능

## 데이터셋 작업

분석에 사용되는 데이터셋을 관리합니다.

- **get_dataset_status**  
  현재 로드된 데이터셋의 상태를 조회합니다.

- **list_datasets**  
  분석에 사용할 수 있는 CSV 데이터셋을 나열합니다.  
  페이지네이션을 지원합니다.

- **switch_dataset**  
  활성 분석 데이터셋을 지정된 CSV 파일로 전환합니다.

- **unload_dataset**  
  현재 `logs` 테이블을 언로드합니다.

- **dataset_profile**  
  다음을 포함한 데이터셋 요약을 조회합니다:
  - 전체 이벤트 수
  - 시간 범위
  - 상위 추세

  페이지네이션을 지원합니다.

---

## 쿼리 및 검색

로그 데이터를 검색하고 쿼리합니다.

- **run_sql**  
  `logs` 테이블에 대해 읽기 전용 `SELECT` 쿼리를 실행합니다.  
  내장된 안전 제약 조건을 포함합니다.

- **search_all_fields**  
  모든 열 또는 지정된 열에 걸쳐 키워드 검색을 수행합니다.  
  페이지네이션을 지원합니다.

- **get_event_detail**  
  단일 이벤트를 확장된 `Field / Value` 형식으로 조회합니다.  
  `RecordID` 또는 쿼리 조건으로 조회할 수 있습니다.

---

## 타임라인 및 분석

공격 활동과 이벤트 타임라인을 분석합니다.

- **analyze_mitre_tactics**  
  **MITRE ATT&CK tactics**별로 그룹화된 공격 단계의 시간순 분석을 수행합니다.

- **analyze_host_timeline**  
  특정 호스트에 대한 시간순 이벤트를 추출합니다.  
  **침해 체인 추적**에 유용합니다.

- **correlate_lateral_movement**  
  지정된 시간 윈도우 내에서 호스트 간 측면 이동 활동을 상관 분석합니다.

- **summarize_events**  
  지정된 필드별로 로그 이벤트를 집계합니다.

- **summarize_by_time_window**  
  시간 윈도우별로 이벤트를 집계합니다:
  - `1h`
  - `3h`
  - `6h`
  - `12h`
  - `1d`

- **analyze_rule_titles**  
  선택적 필터링 조건과 함께 `RuleTitle` 발생 빈도를 집계합니다.

---

## 상세 및 IOC 분석

로그 세부 정보에서 지표를 추출하고 분석합니다.

- **parse_details_field**  
  `Details` 필드에서 키/값 쌍을 추출합니다.  
  목록화 및 고유 값 집계를 지원합니다.

- **extract_iocs**  
  `Details` 및 `ExtraFieldInfo`에서 **침해 지표(IOCs)**를 유형별로 분류하여 추출합니다.

- **decode_powershell_commands**  
  이벤트에서 발견된 Base64로 인코딩된 PowerShell 명령을 디코딩합니다.
