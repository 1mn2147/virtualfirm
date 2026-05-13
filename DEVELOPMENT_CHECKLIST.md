# MVP Improvement Checklist

현재 MVP는 정적 휴리스틱 기반 CLI와 JSON 산출물 골격을 제공한다. 아래 체크리스트는 실제 펌웨어 분석 자동화 도구로 확장하기 위한 개발 항목이다.

## 1. 펌웨어 전처리 강화

- [x] `file`, `readelf`, `objdump`, `xxd` 등 기본 분석 도구 결과를 `context.json`에 통합한다.
- [x] raw binary, ELF, Intel HEX, Motorola S-record 입력 포맷을 구분하고 로더를 분리한다.
  - [x] SquashFS 컨테이너는 `--extract-embedded`로 내부 ELF 후보를 추출/기록하고 Ghidra 분석 대상으로 선별한다.
  - [x] 내부 ELF 후보에 점수와 근거를 부여하고 `--ghidra-target`/`--ghidra-target-pattern`으로 분석 대상을 지정한다.
- [x] Cortex-M 벡터 테이블 파서를 구현해 초기 SP, Reset Handler, IRQ 핸들러 목록을 구조화한다.
- [x] 엔트로피를 전체 파일 단일 값이 아니라 섹션/윈도우 단위로 계산한다.
- [x] 압축/암호화 의심 구간을 오프셋 범위와 근거로 출력한다.
  - [x] `binwalk`가 식별한 DTB/SquashFS 같은 non-code 구간은 `firmware_segments`와 `analysis_warnings`에 기록한다.
- [x] MMIO 후보 추출 시 코드 영역과 문자열 영역을 분리해 오탐을 줄인다.
  - [x] `binwalk` non-code 구간은 휴리스틱 MMIO 스캔에서 제외해 컨테이너 이미지 오탐을 줄인다.
- [x] 아키텍처 감지를 `arm-cortex-m`, `mips`, `arm-linux`, `riscv`, `xtensa` 등으로 확장한다.

## 2. Headless 리버스 엔지니어링 연동

- [x] Ghidra Headless 실행 래퍼를 추가한다.
- [x] Ghidra 프로젝트 생성/재사용, 바이너리 import, processor 지정 옵션을 CLI에 추가한다.
- [x] Ghidra 스크립트로 함수 목록, call graph, 문자열 참조, MMIO xref를 추출한다.
- [x] Reset Handler와 초기화 함수 후보를 찾아 의사 코드 또는 디스어셈블리를 저장한다.
  - [x] 취약점 후보 함수 주변 disassembly와 가능한 decompiler C 출력을 `function_contexts`에 저장한다.
  - [x] decompiler 출력에서 source/sink/control 증거 스니펫을 추출해 `report.md`의 고위험 함수 근거로 요약한다.
- [x] IDA Pro가 설치된 환경에서는 IDA Headless 백엔드를 선택적으로 사용할 수 있게 한다.
- [x] 외부 도구가 없을 때는 현재 휴리스틱 백엔드로 graceful fallback한다.

## 3. RAG 데이터베이스 개선

- [x] `references/` 단순 텍스트 검색을 SQLite 또는 벡터 DB 기반 인덱스로 교체한다.
- [x] MCU별 메모리맵, 레지스터, 비트필드 정보를 구조화된 YAML/JSON 스키마로 저장한다.
- [x] STM32F1 외에 STM32F4, ESP32, nRF52 등 대표 타겟 레퍼런스를 추가한다.
- [x] PDF 데이터시트 ingestion 파이프라인을 만든다.
- [x] RAG 검색 결과에 page/section/source URL 또는 파일 위치를 포함한다.
- [x] 주소 범위 검색은 벡터 검색이 아니라 정밀 range lookup으로 처리한다.

## 4. LLM 추론 엔진 도입

- [x] 현재 deterministic inference 뒤에 LLM provider 인터페이스를 추가한다.
- [x] OpenAI API, 로컬 LLM, mock backend를 같은 인터페이스로 교체 가능하게 만든다.
- [x] LLM 입력에는 컨텍스트 크기 제한, 코드 주변부, RAG 근거, 크래시 로그를 명시적으로 포함한다.
  - [x] Ghidra source/sink/control 신호를 `vulnerability_candidates`로 요약해 LLM/수동 분석 입력을 강화한다.
  - [x] 고위험 함수의 decompiler source/sink/control 스니펫을 `function_contexts.evidence_snippets`로 제공한다.
- [x] LLM 출력은 JSON Schema로 검증한다.
- [x] 잘못된 JSON, 누락 필드, 낮은 confidence 응답에 대한 retry/repair 로직을 구현한다.
- [x] LLM 응답 원문과 파싱 결과를 별도 로그로 남긴다.
- [x] LLM 없이도 테스트 가능한 fixture 기반 추론 경로를 유지한다.

## 5. 에뮬레이션 래퍼 구현

- [x] Qiling 기반 실행 백엔드 어댑터를 추가한다.
- [x] `stub|qiling` 에뮬레이션 백엔드 선택 인터페이스를 추가한다.
- [x] QEMU 기반 실행 백엔드를 추가하거나 Qiling 한계가 있는 타겟에 대한 adapter를 설계한다.
- [x] `emulator_config.json`의 MMIO mapping을 실제 hook 등록으로 변환한다.
- [x] unmapped memory 접근 시 PC, LR, SP, registers, access type, address를 수집한다.
- [x] instruction count limit, max crash loop count를 설정 가능하게 한다.
- [x] wall-clock timeout을 설정 가능하게 한다.
- [x] UART 출력, semihosting, exit 조건을 캡처한다.
- [x] 실행 결과를 `emulation_result.json`과 `emulation.log`로 저장한다.

## 6. 피드백 루프 자동화

- [x] 에뮬레이션 크래시 로그를 LLM 또는 deterministic fallback에 전달하는 루프를 구현한다.
- [x] 새 MMIO mapping 제안을 기존 `emulator_config.json`에 병합하는 patcher를 만든다.
- [x] 동일 주소/동일 PC 반복 크래시를 감지해 무한 루프를 방지한다.
- [x] 각 iteration의 설정, 로그, 추론 결과를 `runs/<id>/iterations/<n>/`에 보존한다.
- [x] 성공 기준을 `boot reached`, `UART output`, `no crash for N instructions` 등으로 설정 가능하게 한다.
- [x] 자동 루프 종료 후 사람이 검토할 요약 리포트를 생성한다.

## 7. CLI/설정 UX 정리

- [x] `firmware-mvp analyze`를 `extract`, `infer`, `emulate` 단계로 분리한다.
- [x] `loop` 명령을 별도 단계로 추가한다.
- [x] `report` 명령을 별도 단계로 추가한다.
- [x] 전체 파이프라인 실행용 `run` 명령을 추가한다.
- [x] YAML 기반 프로젝트 설정 파일을 지원한다.
- [x] `--backend stub|qiling` 에뮬레이션 옵션을 추가한다.
- [x] `--analysis-backend heuristic|ghidra` 분석 옵션을 추가한다.
- [x] `--llm openai|local|mock` LLM 옵션을 추가한다.
- [x] 출력 디렉터리 구조와 파일명을 안정적인 스키마로 문서화한다.
- [x] 실패 시 exit code와 에러 메시지를 자동화 친화적으로 정리한다.

## 8. 테스트 자산과 품질 검증

- [x] 샘플 펌웨어 fixture를 raw binary, ELF, 고엔트로피 blob, MMIO-heavy blob으로 확장한다.
- [x] STM32F1 주소 분류 unit test를 추가한다.
- [x] extractor 오탐/누락 케이스 regression test를 추가한다.
- [x] RAG range lookup과 문서 검색 test를 추가한다.
- [x] LLM backend는 mock 응답으로 schema validation test를 작성한다.
- [x] Qiling/QEMU 통합 테스트는 Docker에서만 실행되도록 marker를 분리한다.
- [x] `pytest`, `ruff`, `mypy` 또는 `pyright`를 CI에 연결한다.

## 9. 컨테이너/개발 환경

- [x] Docker 이미지에 Ghidra 설치 옵션을 추가한다.
- [x] Qiling/QEMU 실행에 필요한 시스템 패키지를 Dockerfile에 추가한다.
- [x] 무거운 분석 도구는 base image와 dev image로 분리한다.
- [x] `docker compose`에 샘플 분석, 테스트, shell 서비스를 추가한다.
- [x] `.dockerignore`를 추가해 `.venv`, `runs`, 캐시가 build context에 들어가지 않게 한다.
- [x] 로컬 설치, Docker 설치, 외부 도구 설치 경로를 README에 분리해 문서화한다.

## 10. 산출물 스키마와 호환성

- [x] `context.json`, `inference.json`, `emulator_config.json`에 schema version을 추가한다.
- [x] JSON Schema 파일을 `schemas/`에 정의한다.
- [x] 산출물 validation 명령을 추가한다.
- [x] 이전 버전 산출물을 읽을 수 있는 migration 또는 compatibility layer를 설계한다.
- [x] report에는 입력 파일, 도구 버전, 실행 명령, timestamp를 포함한다.

## 11. 보안과 안전장치

- [x] 분석 대상 파일을 실행하지 않는 정적 단계와 실행 가능한 에뮬레이션 단계를 명확히 분리한다.
- [x] 외부 도구 호출 timeout과 최대 출력 크기를 모든 subprocess에 적용한다.
- [x] Docker 기본 실행은 read-only root filesystem 또는 제한된 volume을 사용하도록 검토한다.
- [x] LLM으로 전송되는 데이터에 secret/token이 섞이지 않도록 redaction hook을 둔다.
- [x] 사용자 제공 펌웨어와 분석 로그를 기본적으로 repo 밖 output dir에 저장할 옵션을 제공한다.

## 12. GUI 조작 UX 추가

- [x] CLI 명령(`analyze`, `extract`, `infer`, `emulate`, `loop`, `report`, `feedback`, `validate`, `init-sample`) 대부분을 GUI에서 실행할 수 있는 화면 구조를 설계한다.
- [x] 펌웨어 파일 선택, 디바이스 선택, 출력 디렉터리 선택, 백엔드 옵션 등 공통 실행 파라미터를 GUI 입력 폼으로 제공한다.
- [x] 전체 파이프라인 실행과 단계별 실행을 모두 지원하고, 각 단계의 진행 상태와 실패 원인을 GUI에서 확인할 수 있게 한다.
- [x] `context.json`, `inference.json`, `emulator_config.json`, `emulation_result.json`, `loop_summary.json`, `report.md`를 GUI에서 열람하고 주요 필드를 탐색할 수 있게 한다.
- [x] 에뮬레이션 옵션, probe address, loop iteration limit, timeout 같은 반복 조정 값을 GUI에서 수정 후 재실행할 수 있게 한다.
- [x] feedback 명령으로 가능한 MMIO mapping 제안/병합 작업을 GUI 워크플로로 제공한다.
- [x] validate 결과와 schema 오류를 파일/필드 단위로 표시한다.
- [x] GUI 실행도 기존 CLI와 동일한 내부 API를 호출하게 해 기능 중복 구현을 피한다.
- [x] GUI에서 생성된 실행 명령, 도구 버전, timestamp를 report 산출물에 남긴다.
- [x] 장기 실행 작업은 취소, 로그 스트리밍, 재시도 기능을 제공한다.
- [x] GUI 자동화 테스트 또는 최소 smoke test를 추가한다.

## 우선순위 제안

1. Ghidra Headless extractor를 먼저 붙인다.
2. MMIO range lookup을 구조화된 레퍼런스 DB로 바꾼다.
3. Qiling 백엔드와 unmapped MMIO 크래시 수집을 구현한다.
4. 피드백 루프를 deterministic fallback으로 먼저 완성한다.
5. GUI에서 호출할 수 있도록 CLI 내부 로직을 재사용 가능한 서비스/API 계층으로 정리한다. (완료)
6. 그 다음 LLM provider와 JSON Schema 검증을 추가한다.
