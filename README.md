# Firmware Analysis MVP

Firmware Analysis MVP는 펌웨어 파일에서 정적 컨텍스트를 추출하고, MMIO/주변기기 매핑을 추론하며, 에뮬레이션 설정과 실행 결과를 재현 가능한 JSON 산출물로 남기는 로컬 분석 도구입니다.

기본 경로는 네트워크와 상용 도구 없이 동작합니다. `binwalk`, Ghidra, IDA, Qiling, OpenAI, `pdftotext`는 설치되어 있을 때만 선택적으로 사용됩니다.

## 주요 기능

- raw binary, ELF, Intel HEX, Motorola S-record 입력 감지 및 로딩 메타데이터 기록
- 엔트로피 윈도우, 압축/암호화 의심 구간, 문자열 range, MMIO 후보 추출
- Cortex-M vector table, Reset Handler, IRQ/exception handler 후보 구조화
- `file`, `readelf`, `objdump`, `xxd`, `binwalk` 관측 결과를 `context.json`에 통합
- Ghidra/IDA Headless 선택 백엔드와 외부 도구 부재 시 graceful fallback
- Ghidra/IDA 분석 결과 기반 함수 목록, call graph, 문자열 참조, MMIO xref, 위험 함수 후보 통합
- SQLite 기반 경량 RAG 검색과 구조화된 MCU 메모리맵 range lookup
- deterministic/mock/OpenAI/local-reserved LLM provider 인터페이스
- LLM 응답 검증, retry/repair, raw/parsed audit 로그
- `stub`/`qiling` 에뮬레이션 백엔드, timeout, instruction limit, success criteria
- UART/semihosting/exit condition 캡처와 `emulation_result.json`/`emulation.log` 생성
- unmapped MMIO crash feedback loop와 자동 mapping patch
- PDF 데이터시트 ingestion(`pdftotext`) 및 RAG용 `.md`/`.txt` 생성
- machine-readable `--json` 출력, 산출물 validation, report 재생성
- 표준 라이브러리 HTTP GUI: 실행, 로그 확인, 취소, 재시도, 산출물 조회
- Docker/Compose 기반 격리 실행 구성

## 설치

### Python 패키지

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

선택 기능:

```bash
pip install -e ".[qiling]"   # Qiling backend
pip install -e ".[llm]"      # OpenAI provider
```

### 최소 실행

```bash
firmware-mvp init-sample --out samples/demo_firmware.bin
firmware-mvp analyze samples/demo_firmware.bin --device stm32f1 --out runs/demo
firmware-mvp validate runs/demo
```

설치 없이 Makefile 경로를 사용할 수도 있습니다.

```bash
make sample
make analyze
make test
```

## 빠른 사용 예시

### 전체 정적 분석

```bash
firmware-mvp analyze firmware.bin --device stm32f1 --out runs/my-run
```

### 단계별 실행

```bash
firmware-mvp extract firmware.bin --out runs/my-run
firmware-mvp infer runs/my-run/context.json --device stm32f1 --out runs/my-run
firmware-mvp emulate runs/my-run/emulator_config.json --out runs/my-run --backend stub --probe-address 0x40011000
firmware-mvp report runs/my-run
```

### 추출, 추론, 에뮬레이션 한 번에 실행

```bash
firmware-mvp run firmware.bin --device stm32f1 --out runs/my-run --backend stub --probe-address 0x40011000
```

### Feedback loop

```bash
firmware-mvp loop runs/my-run/emulator_config.json --out runs/my-loop --backend stub --probe-address 0x50000000
```

### 자동화용 JSON 출력

전역 `--json`은 명령 앞이나 뒤에 둘 수 있습니다. 출력은 `exit_code`, `artifacts`, `errors`를 포함합니다.

```bash
firmware-mvp --json analyze firmware.bin --device stm32f1 --out runs/ci-run
firmware-mvp validate runs/ci-run --json
```

### repo 밖 output root 사용

상대 `--out` 경로를 repo 밖으로 prefix하려면 전역 옵션이나 환경 변수를 사용합니다.

```bash
firmware-mvp --output-root /tmp/firmware-runs analyze firmware.bin --device stm32f1 --out demo
FIRMWARE_MVP_OUTPUT_ROOT=/tmp/firmware-runs firmware-mvp run firmware.bin --device stm32f1
```

## 주요 명령

```bash
firmware-mvp analyze <firmware> --device <device> --out <run-dir>
firmware-mvp run <firmware> --device <device> --out <run-dir> --backend stub|qiling
firmware-mvp extract <firmware> --out <run-dir>
firmware-mvp infer <run-dir>/context.json --device <device> --out <run-dir>
firmware-mvp emulate <run-dir>/emulator_config.json --out <run-dir> --backend stub|qiling
firmware-mvp loop <run-dir>/emulator_config.json --out <loop-dir>
firmware-mvp report <run-dir>
firmware-mvp validate <run-dir>
firmware-mvp feedback 0x40021018 --access read|write
firmware-mvp ingest-pdf datasheet.pdf --device <device> --out references/ingested
firmware-mvp init-sample --kind raw|elf|high-entropy|mmio-heavy --out samples/demo.bin
firmware-mvp gui --host 127.0.0.1 --port 8765
```

전체 옵션은 다음 명령으로 확인합니다.

```bash
firmware-mvp --help
firmware-mvp analyze --help
firmware-mvp emulate --help
```

## 설정 파일

전역 `--config`는 JSON 또는 단순 YAML map/section subset을 읽습니다. CLI에 명시한 값이 설정 파일보다 우선합니다.

```yaml
defaults:
  device: stm32f1
  references: references
analyze:
  out: runs/configured-demo
```

```bash
firmware-mvp --config firmware-mvp.yml analyze samples/demo_firmware.bin
```

## 산출물

기본 run directory에는 다음 파일이 생성됩니다.

| 파일 | 생성 명령 | 설명 |
| --- | --- | --- |
| `context.json` | `extract`, `analyze`, `run`, `infer` | 입력 포맷, 해시, 엔트로피, 문자열, MMIO 후보, 도구 관측, Ghidra/IDA/binwalk 요약 |
| `inference.json` | `infer`, `analyze`, `run` | 주변기기/MMIO 추론 결과와 RAG 근거 |
| `emulator_config.json` | `infer`, `analyze`, `run` | 에뮬레이션 backend용 MMIO mapping 설정 |
| `emulation_result.json` | `emulate`, `run` | 실행 상태, stop reason, success criteria, crash, UART/semihosting 캡처 |
| `emulation.log` | `emulate`, `run` | 자동화/디버깅용 텍스트 로그 |
| `loop_summary.json` | `loop` | feedback loop iteration 요약과 최종 config 경로 |
| `report.md` | 대부분 명령 | 사람이 읽는 분석 요약 |
| `llm_audit.json` | non-deterministic LLM 사용 시 | provider, validation, retry/fallback/failure 감사 로그 |

상세 계약은 다음 문서를 참고하세요.

- `docs/output-artifacts.md`
- `docs/artifact-compatibility.md`
- `schemas/*.schema.json`

## 선택 외부 도구

| 도구 | 사용 위치 | 비고 |
| --- | --- | --- |
| `binwalk` | 정적 분석 | 있으면 `firmware_segments`와 압축/파일시스템 후보가 보강됩니다. |
| `unsquashfs` | `--extract-embedded` | SquashFS 추출에 필요합니다. |
| Ghidra `analyzeHeadless` | `--analysis-backend ghidra` | `--ghidra-headless` 또는 PATH/GHIDRA_HOME으로 지정합니다. |
| IDA `idat64`/`ida64` | `--analysis-backend ida` | `--ida-headless`, `IDA_HEADLESS`, PATH 순으로 찾습니다. |
| Qiling | `--backend qiling` | `pip install -e ".[qiling]"` 필요. |
| OpenAI SDK | `--llm openai` | `pip install -e ".[llm]"`와 `OPENAI_API_KEY` 필요. |
| `pdftotext` | `ingest-pdf` | Ubuntu/Debian의 `poppler-utils` 패키지가 제공합니다. |

외부 도구가 없으면 기본적으로 휴리스틱/stub 경로로 계속 진행하거나 명확한 skipped/error 사유를 산출물에 남깁니다.

## Ghidra/IDA 분석

```bash
firmware-mvp analyze firmware.bin --device router --out runs/ghidra \
  --analysis-backend ghidra \
  --ghidra-headless /path/to/analyzeHeadless \
  --ghidra-processor MIPS:LE:32:default

firmware-mvp analyze firmware.bin --device router --out runs/ida \
  --analysis-backend ida \
  --ida-headless /path/to/idat64
```

컨테이너형 라우터 펌웨어처럼 전체 `.bin`이 DTB/SquashFS 이미지인 경우 `--extract-embedded`를 사용해 실행 파일 후보를 추출할 수 있습니다.

```bash
firmware-mvp analyze firmware.bin --device router --out runs/router \
  --analysis-backend ghidra \
  --extract-embedded \
  --ghidra-target-pattern '*firmware*|*.cgi'
```

Ghidra 분석이 성공하면 `vulnerability_candidates`, `function_contexts`, decompiler snippet, source/sink/control 신호가 `context.json`과 `report.md`에 반영됩니다. IDA backend는 IDAPython export 결과를 같은 내부 analysis shape으로 병합해 문자열, 함수, entry point, MMIO 참조를 보강합니다.

## PDF 데이터시트 ingestion

```bash
firmware-mvp ingest-pdf datasheets/stm32f1.pdf --device stm32f1 --out references/ingested
firmware-mvp analyze samples/demo_firmware.bin --device stm32f1 --references references --out runs/pdf-rag-demo
```

`ingest-pdf`는 `.txt`와 `.md`를 생성합니다. 생성 파일을 `references/` 아래에 두면 SQLite 기반 RAG 검색에 자동 포함됩니다.

## LLM provider

기본 provider는 네트워크가 필요 없는 `deterministic`입니다.

```bash
firmware-mvp infer runs/demo/context.json --device stm32f1 --out runs/demo --llm deterministic
firmware-mvp infer runs/demo/context.json --device stm32f1 --out runs/mock --llm mock --mock-response valid
firmware-mvp infer runs/demo/context.json --device stm32f1 --out runs/openai --llm openai
```

명시적으로 LLM provider를 선택한 경우 provider 호출, JSON 파싱, 필드 검증이 실패하면 기본적으로 nonzero로 실패하고 invalid output으로 `emulator_config.json`을 만들지 않습니다. deterministic fallback을 원하면 `--llm-fallback deterministic`을 명시하세요.

## 에뮬레이션 성공 기준

`emulate`와 `run`은 success criteria를 exit code에 반영할 수 있습니다.

```bash
firmware-mvp emulate runs/demo/emulator_config.json --out runs/demo \
  --success-criterion uart-output \
  --success-uart-contains 'Boot'

firmware-mvp emulate runs/demo/emulator_config.json --out runs/demo \
  --success-criterion no-crash-for-instructions \
  --instruction-limit 1000
```

지원 기준:

- `boot-reached`
- `uart-output`
- `no-crash-for-instructions`

`emulation_result.json`에는 항상 `success`, `success_criteria`, `exit_condition`, `uart_output`, `semihosting` 필드가 포함됩니다.

## GUI

```bash
firmware-mvp gui --host 127.0.0.1 --port 8765
```

브라우저에서 주요 CLI 명령을 실행하고 job 로그, 상태, 취소, 재시도, 산출물 조회를 사용할 수 있습니다. GUI job은 내부적으로 `python -m firmware_mvp.cli ...`를 호출하므로 CLI와 같은 산출물 계약을 공유합니다.

상세 설계와 smoke test 범위는 `docs/gui-design.md`에 정리되어 있습니다.

## Docker

```bash
docker compose build
docker compose run --rm sample
docker compose run --rm test
docker compose run --rm shell
```

Compose 서비스는 read-only root filesystem, `/tmp` tmpfs, read-only repo mount를 기본으로 사용합니다. 샘플 분석 결과는 named volume의 `/output/docker-demo`에 저장됩니다. `shell` 서비스에서도 실험 산출물은 `/output` 또는 `/tmp`에 저장하세요.

무거운 도구는 build arg로 선택합니다.

```bash
docker build --target dev --build-arg INSTALL_QEMU=1 --build-arg INSTALL_QILING=1 -t firmware-mvp:emu .
docker build --target dev --build-arg INSTALL_GHIDRA=1 -t firmware-mvp:ghidra .
docker compose run --rm integration-test
```

- `base` target: CLI 런타임과 정적 분석 도구
- `dev` target: 테스트 도구와 개발 산출물
- `INSTALL_QEMU=1`: QEMU system/user packages 추가
- `INSTALL_QILING=1`: Qiling Python extra 설치
- `INSTALL_GHIDRA=1`: Ghidra zip 다운로드 후 `analyzeHeadless` 링크 생성

IDA는 라이선스가 필요한 도구라 Docker 자동 설치 대상에서 제외합니다. PDF ingestion에 필요한 `pdftotext`도 기본 Dockerfile에는 포함하지 않았으므로, 컨테이너에서 `ingest-pdf`를 사용할 경우 `poppler-utils`를 추가한 파생 이미지를 사용하세요.

## 보안 및 데이터 취급

- 기본 분석/추론 경로는 로컬에서 동작합니다.
- `--llm openai`를 선택한 경우에만 외부 API 호출이 발생합니다.
- report에는 provider 상태와 검증 결과만 요약하며 raw provider response나 secret은 포함하지 않습니다.
- 사용자 제공 펌웨어와 분석 로그를 repo 밖에 저장하려면 `--output-root` 또는 `FIRMWARE_MVP_OUTPUT_ROOT`를 사용하세요.
- 외부 도구 실행에는 timeout과 출력 크기 제한을 적용합니다.

## 개발 및 검증

```bash
PYTHONPATH=src ruff check src tests
PYTHONPATH=src pytest -q
PYTHONPATH=src pytest -q -m docker_integration
```

일반 pytest 실행에서는 Docker 전용 Qiling/QEMU smoke test가 제외됩니다.

## 프로젝트 구조

```text
src/firmware_mvp/
  cli.py                # CLI 엔트리포인트
  compat.py             # 구버전 산출물 read-time 호환성 보정
  services.py           # CLI/GUI 공유 파이프라인 서비스 API
  extractor.py          # 펌웨어 컨텍스트 추출
  ghidra.py             # Ghidra Headless 래퍼
  ida.py                # IDA Headless 래퍼
  pdf_ingest.py         # PDF 데이터시트 텍스트/markdown 변환
  rag.py                # 로컬 문서 검색
  inference.py          # 주변기기/MMIO 추론
  emulator.py           # 에뮬레이터 설정 생성 및 피드백 모델
  emulator_backends.py  # stub/qiling 실행 백엔드
  gui.py                # stdlib HTTP GUI
  reporting.py          # report.md 생성
  validation.py         # 산출물 검증
  models.py             # JSON 직렬화 모델
references/
  stm32f1_memory_map.md
  memory_maps/*.json
schemas/
docs/
tests/
```

## 현재 범위

이 릴리스는 정적 분석, 선택적 Ghidra/IDA Headless, deterministic/mock/OpenAI 추론, stub/Qiling 실행 백엔드를 하나의 산출물 계약으로 묶은 로컬 분석 도구입니다. QEMU는 `docs/qemu-adapter-design.md`로 adapter 계약을 고정했으며, 실제 `--backend qemu` 실행기는 후속 구현 범위입니다.
