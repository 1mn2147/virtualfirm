# Firmware Analysis MVP

`plan1.md`의 1단계부터 4단계까지를 개발용 MVP로 구현한 펌웨어 분석 파이프라인입니다.

현재 MVP는 다음을 제공합니다.

- 펌웨어 파일 메타데이터, 엔트로피, 문자열, 의심 MMIO 주소 추출
- raw binary, ELF, Intel HEX, Motorola S-record 입력 포맷 감지와 로딩 메타데이터 기록
- Cortex-M, MIPS, ARM Linux, RISC-V, Xtensa 계열 아키텍처 힌트 감지
- Cortex-M vector table에서 초기 SP, Reset Handler, IRQ/exception handler 후보 구조화
- 전체 엔트로피와 window별 엔트로피 요약 기록
- binwalk와 high-entropy window 기반 압축/암호화 의심 구간 기록
- 문자열 literal range를 구조화하고 휴리스틱 MMIO 스캔에서 제외
- `file`, `readelf`, `objdump`, `xxd` 기본 도구 결과를 `context.json`에 통합
- `binwalk`가 설치된 경우 자동 분석 결과 병합
- `binwalk` 결과를 구조화된 펌웨어 세그먼트로 보존하고, DTB/SquashFS 같은 non-code 구간은 휴리스틱 MMIO 스캔에서 제외
- Ghidra 산출물에서 위험 함수, CGI 입력 문자열, 파일 쓰기 흐름을 `vulnerability_candidates`로 요약
- 취약점 후보 함수의 디스어셈블리, Ghidra decompiler C 출력, source/sink 증거 스니펫을 `function_contexts`와 `report.md`에 저장
- SQLite 인메모리 인덱스 기반의 경량 RAG 검색
- RAG 검색 결과에 `source_location` 파일:라인 위치 기록
- 구조화된 MCU 메모리맵 JSON 기반 MMIO range lookup
- STM32F1/STM32F4/ESP32/nRF52 대표 메모리맵 fixture
- 주변기기/MMIO 추론 결과를 정형 JSON으로 생성
- 에뮬레이터 래퍼용 매핑 설정 JSON 생성
- 산출물 스키마 버전과 run directory 검증 명령
- `extract`, `infer`, `emulate`, `run` 단계별 CLI
- deterministic/mock/OpenAI/local-reserved LLM 추론 provider 선택 인터페이스
- LLM/mock 추론 출력의 사전 검증, fail-closed 동작, 명시적 deterministic fallback
- LLM provider prompt에 MMIO/RAG/코드 컨텍스트와 기존 emulation/feedback crash artifact 요약 포함
- `llm_audit.json`과 `llm_attempts/` 기반의 provider 응답 감사 로그
- stub 에뮬레이션 결과와 unmapped MMIO 크래시 로그 생성
- `stub`/`qiling` 에뮬레이션 백엔드 선택 인터페이스
- unmapped MMIO 크래시 패치를 자동 병합하는 feedback loop
- 기존 산출물에서 `report.md`를 재생성하는 report 명령
- `--json` 기반 machine-readable CLI 결과 출력과 nonzero 오류 코드
- PDF 데이터시트를 RAG용 markdown/text로 변환하는 `ingest-pdf` 명령
- Docker 기반 개발 환경

## 빠른 시작

### 로컬 설치

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
firmware-mvp analyze samples/demo_firmware.bin --device stm32f1 --out runs/demo
```

`python3-venv`가 없는 최소 Ubuntu/Debian 환경에서는 다음처럼 설치 없이도 바로 실행할 수 있습니다.

```bash
make sample
make analyze
make test
```

결과 파일:

- `runs/demo/context.json`
- `runs/demo/inference.json`
- `runs/demo/emulator_config.json`
- `runs/demo/emulation_result.json` (`run` 또는 `emulate` 실행 시)
- `runs/demo/loop_summary.json` (`loop` 실행 시)
- `runs/demo/report.md`

안정적인 산출물 파일명과 run directory 계약은 `docs/output-artifacts.md`에 정리되어 있습니다.
구버전 산출물의 read-time compatibility 규칙은 `docs/artifact-compatibility.md`에 정리되어 있습니다.
GUI 화면/작업 API 설계와 smoke coverage는 `docs/gui-design.md`에 정리되어 있습니다.
QEMU backend는 현재 설계 문서(`docs/qemu-adapter-design.md`)로 인터페이스와 안전 경계를 고정해 두었고, 실제 실행 adapter는 후속 구현 항목입니다.

`context.json`에는 원본 파일 기준 `size_bytes`/`sha256`와 함께 `input_format`,
`loaded_base_address`, `loaded_size_bytes`, `loaded_ranges`가 기록됩니다. Intel HEX와
Motorola S-record는 주소 레코드를 평탄화한 loaded image를 대상으로 문자열/MMIO/엔트리포인트
휴리스틱을 실행합니다. Cortex-M으로 감지된 이미지는 `vector_table`에 초기 SP, Reset Handler,
exception/IRQ handler 후보를 함께 저장하고 `report.md`에 요약합니다.
`entropy_windows`는 loaded image를 4 KiB 단위로 나눈 엔트로피와 high-entropy 여부를 기록합니다.
`compressed_or_encrypted_ranges`는 binwalk가 찾은 압축/파일시스템 세그먼트와 high-entropy window를
범위와 근거로 요약합니다.
`string_ranges`는 ASCII literal의 오프셋 범위를 기록하며, 이 범위는 raw MMIO 후보 스캔에서 제외됩니다.

## 명령어

정적 단계와 실행 단계는 분리되어 있습니다. `extract`, `infer`, `analyze`는 펌웨어를 실행하지 않는 정적/추론 산출물을 만들고, `emulate`, `loop`, `run --backend ...`만 에뮬레이션 백엔드를 호출합니다.

```bash
firmware-mvp analyze <firmware.bin> --device <device-name> --out <output-dir>
firmware-mvp analyze <firmware.bin> --device <device-name> --out <output-dir> --analysis-backend ghidra --ghidra-headless /path/to/analyzeHeadless --ghidra-processor ARM:LE:32:Cortex
firmware-mvp analyze <firmware.bin> --device <device-name> --out <output-dir> --analysis-backend ida --ida-headless /path/to/idat64
firmware-mvp analyze <firmware.bin> --device <device-name> --out <output-dir> --analysis-backend ghidra --extract-embedded
firmware-mvp analyze <firmware.bin> --device <device-name> --out <output-dir> --analysis-backend ghidra --extract-embedded --ghidra-target home/httpd/cgi/firmware.cgi
firmware-mvp analyze <firmware.bin> --device <device-name> --out <output-dir> --analysis-backend ghidra --extract-embedded --ghidra-target-pattern '*firmware*|*.cgi'
firmware-mvp run <firmware.bin> --device <device-name> --out <output-dir> --backend stub
firmware-mvp extract <firmware.bin> --out <output-dir>
firmware-mvp infer <output-dir>/context.json --device <device-name> --out <output-dir>
firmware-mvp infer <output-dir>/context.json --device <device-name> --out <output-dir> --llm mock --mock-response valid
firmware-mvp infer <output-dir>/context.json --device <device-name> --out <output-dir> --llm mock --mock-response invalid-json --llm-fallback deterministic
firmware-mvp infer <output-dir>/context.json --device <device-name> --out <output-dir> --llm openai
firmware-mvp emulate <output-dir>/emulator_config.json --out <output-dir> --backend stub --probe-address 0x40011000
firmware-mvp emulate <output-dir>/emulator_config.json --out <output-dir> --backend qiling --rootfs <rootfs> --timeout-seconds 30
firmware-mvp emulate <output-dir>/emulator_config.json --out <output-dir> --success-criterion uart-output --success-uart-contains 'Boot'
firmware-mvp emulate <output-dir>/emulator_config.json --out <output-dir> --success-criterion no-crash-for-instructions --instruction-limit 1000
firmware-mvp loop <output-dir>/emulator_config.json --out <loop-output-dir> --backend stub --probe-address 0x50000000
firmware-mvp report <output-dir>
firmware-mvp init-sample --kind raw --out samples/demo_firmware.bin
firmware-mvp init-sample --kind elf --out samples/demo_firmware.elf
firmware-mvp init-sample --kind high-entropy --out samples/high_entropy.bin
firmware-mvp init-sample --kind mmio-heavy --out samples/mmio_heavy.bin
firmware-mvp feedback 0x40021018 --access write
firmware-mvp validate runs/demo
firmware-mvp ingest-pdf datasheets/stm32f1.pdf --device stm32f1 --out references/ingested
firmware-mvp gui --host 127.0.0.1 --port 8765
```

자동화/CI에서 사용할 때는 전역 `--json`을 명령 앞이나 뒤에 추가할 수 있습니다.
출력은 공통적으로 `exit_code`, `artifacts`, `errors` 필드를 포함하며, `feedback`은
제안 payload를 함께 포함합니다.

```bash
firmware-mvp --json analyze <firmware.bin> --device <device-name> --out <output-dir>
firmware-mvp validate runs/demo --json
```

사용자 제공 펌웨어 분석 산출물/로그를 repo 밖에 두려면 전역 `--output-root` 또는
`FIRMWARE_MVP_OUTPUT_ROOT`를 사용할 수 있습니다. 상대 `--out` 경로만 prefix되며,
절대 경로는 그대로 사용합니다.

```bash
firmware-mvp --output-root /tmp/firmware-runs analyze samples/demo_firmware.bin --device stm32f1 --out demo
FIRMWARE_MVP_OUTPUT_ROOT=/tmp/firmware-runs firmware-mvp run samples/demo_firmware.bin --device stm32f1
```

공통 실행 옵션은 `--config <file.yml>`로도 지정할 수 있습니다. 현재는 JSON 또는 단순 YAML map/section subset을 지원하며, CLI에 명시한 값이 설정 파일보다 우선합니다.

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

## Docker

```bash
docker compose build
docker compose run --rm firmware-mvp firmware-mvp analyze samples/demo_firmware.bin --device stm32f1 --out runs/docker-demo
docker compose run --rm sample
docker compose run --rm test
docker compose run --rm shell
```

Dockerfile은 `base`와 `dev` target으로 분리되어 있습니다. 기본 compose 서비스는 `dev`
target을 사용해 테스트 도구까지 설치하고, `base` target은 CLI 런타임/외부 정적 분석 도구만
포함합니다.

Compose 서비스는 기본적으로 read-only root filesystem, `/tmp` tmpfs, read-only repo mount를
사용합니다. 샘플 분석 결과는 repo 내부가 아니라 named volume의 `/output/docker-demo`에
저장됩니다.

Docker 이미지에는 Python 런타임, `binwalk`, `file`, `squashfs-tools`를 포함합니다. QEMU와
Ghidra는 무거운 선택 도구라 build arg로 켭니다.

```bash
docker build --target dev --build-arg INSTALL_QEMU=1 --build-arg INSTALL_QILING=1 -t firmware-mvp:emu .
docker build --target dev --build-arg INSTALL_GHIDRA=1 -t firmware-mvp:ghidra .
docker compose run --rm integration-test
```

`integration-test` 서비스는 `RUN_DOCKER_INTEGRATION=1`과 `pytest -m docker_integration`으로
Qiling/QEMU Docker-only smoke test만 실행합니다. 일반 `pytest` 실행에서는 해당 marker가
제외됩니다.

Ghidra build arg 기본값은 `GHIDRA_VERSION=12.0.4`, `GHIDRA_RELEASE_DATE=20260303`이며,
성공 시 `/usr/local/bin/analyzeHeadless` 링크를 생성합니다. IDA는 라이선스가 필요한 도구라
Docker 자동 설치 대상에서 제외되어 있습니다.

### 선택 외부 도구 설치

외부 분석 도구는 기본 파이썬 패키지와 분리된 선택 구성입니다.

- `binwalk`: 설치되어 있으면 `context.json.tool_observations.binwalk`와 `firmware_segments`에 결과가 병합됩니다. 없으면 skipped 상태로 계속 진행합니다.
- `unsquashfs`: `--extract-embedded` 사용 시 SquashFS 추출에 필요합니다. 없으면 embedded extraction observation에 skipped/failed 상태가 기록됩니다.
- `Ghidra`: `--analysis-backend ghidra` 사용 시 `analyzeHeadless`가 필요합니다. `--ghidra-headless /path/to/analyzeHeadless`로 명시하거나 PATH에 둡니다.
- `IDA Pro/Free`: `--analysis-backend ida` 사용 시 `idat64`/`ida64` 계열 headless executable이 필요합니다. `--ida-headless /path/to/idat64`로 명시하거나 `IDA_HEADLESS`/PATH에 둡니다.
- `Qiling`: `pip install -e ".[qiling]"`로 선택 설치합니다. `--backend qiling`을 선택하지 않으면 import되지 않습니다.
- `OpenAI`: `pip install -e ".[llm]"`와 `OPENAI_API_KEY`가 있을 때만 `--llm openai` 경로에서 사용됩니다.
- `pdftotext`: `ingest-pdf`에서 PDF 데이터시트를 RAG 검색 가능한 `.md`/`.txt`로 변환할 때 필요합니다. Ubuntu/Debian에서는 `poppler-utils` 패키지가 제공합니다.

로컬 실험에서 도구 경로가 여러 개라면 CLI 플래그(`--ghidra-headless`, `--rootfs`)로 run별로 고정하고, 산출물의 command/report와 `tool_observations`를 함께 보존하는 방식을 권장합니다.

Ghidra가 설치된 환경에서는 `analyze`, `run`, `extract`에서 `--analysis-backend ghidra`를 사용할 수 있습니다. Ghidra가 없거나 `analyzeHeadless`를 찾지 못하면 기존 휴리스틱 추출 결과를 유지하고 `context.json`의 `tool_observations.ghidra`에 skipped 상태를 남깁니다. 성공 시 함수 목록, call graph, 문자열 참조, MMIO xref, Reset Handler 후보 디스어셈블리를 같은 위치에 저장합니다.

IDA가 설치된 환경에서는 `analyze`, `run`, `extract`에서 `--analysis-backend ida`를 사용할 수 있습니다. IDA 실행 파일을 찾지 못하면 기존 휴리스틱 추출 결과를 유지하고 `context.json`의 `tool_observations.ida`에 skipped 상태를 남깁니다. 성공 시 IDAPython export 결과를 Ghidra와 같은 내부 analysis shape으로 병합해 문자열, entry point, MMIO 참조, 함수 목록을 보강합니다.

리눅스 라우터 펌웨어처럼 전체 이미지가 DTB/SquashFS 컨테이너인 경우 Ghidra가 전체 `.bin`에서 함수를 찾지 못할 수 있습니다. 이때 `context.json`의 `firmware_segments`와 `analysis_warnings`가 어떤 구간을 non-code로 판단했는지, 왜 MMIO 후보가 제한되었는지, 추출된 실행 파일/커널을 별도 분석해야 하는지를 기록합니다. `--extract-embedded`를 추가하면 `unsquashfs`로 SquashFS를 `runs/<id>/embedded/` 아래에 풀고 ELF 실행 파일/라이브러리/커널 모듈 후보를 `embedded_files`에 기록하며, 각 후보에는 `score`와 `score_reasons`가 포함됩니다. Ghidra 백엔드는 기본적으로 가장 점수가 높은 ELF 실행 파일을 분석 대상으로 사용합니다. 특정 파일을 분석하려면 `--ghidra-target`, glob으로 고르려면 `--ghidra-target-pattern`을 사용합니다.

Ghidra 분석이 성공하면 `context.json`에 `vulnerability_candidates`가 추가됩니다. 이는 확정 취약점이 아니라 `getenv`, `CONTENT_LENGTH`, `fopen`, `fwrite`, `/tmp/firmware`, `firmware/upgrade`, `check_csrf_attack` 같은 source/sink/control 신호를 묶은 정적 검토 후보입니다.

같은 Ghidra 실행에서 관심 함수의 주변 코드도 `function_contexts`에 저장합니다. 각 항목에는 함수명, entry point, 후보 카테고리, 검토 우선순위, flow signal, 선별 이유, 최대 120개 instruction의 disassembly, 그리고 Ghidra decompiler가 성공한 경우 C-like pseudocode가 포함됩니다. decompiler 출력에서 `getenv`, `fopen`, `fwrite`, `/tmp/`, `check_csrf_attack`, `httpcon_auth` 같은 source/sink/control 라인이 발견되면 `evidence_snippets`로 보존하고, `report.md`의 `High-Risk Function Evidence` 섹션에 요약합니다.

## LLM 추론 Provider

기본 추론은 여전히 네트워크가 필요 없는 deterministic 경로입니다. `infer`, `analyze`, `run`에서 `--llm deterministic|mock|openai|local`을 선택할 수 있습니다.

- `deterministic`: 기본값. 기존 휴리스틱 추론을 사용합니다.
- `mock`: 테스트/데모용 fixture provider입니다. `--mock-response valid|invalid-json|missing-field|low-confidence|provider-error` 또는 `--mock-response-path`로 성공/실패 경로를 재현합니다.
- `openai`: `pip install -e ".[llm]"`와 `OPENAI_API_KEY`가 있을 때만 사용합니다. 선택하지 않으면 OpenAI 패키지 import/API 호출이 발생하지 않습니다.
- `local`: 인터페이스 예약 상태이며 현재는 명확한 not-configured 오류를 반환합니다.

명시적으로 LLM provider를 선택한 경우 provider 호출, JSON 파싱, 필드 검증이 실패하면 기본적으로 nonzero로 실패하고 invalid output으로 `emulator_config.json`을 만들지 않습니다. 단, 누락된 `confidence`, 범위를 벗어난 confidence, 문자열 evidence처럼 안전하게 보정 가능한 shape 오류는 deterministic repair를 적용하고 `llm_audit.json`의 attempt에 `repair_applied`/`repair_notes`를 남깁니다. deterministic fallback을 원하면 `--llm-fallback deterministic`을 명시해야 합니다.

LLM/mock provider 실행은 다음 감사 산출물을 남깁니다.

- `llm_audit.json`: provider requested/used, validation status, retry/fallback/failure reason
- `llm_attempts/attempt-N.raw.txt`: provider raw response
- `llm_attempts/attempt-N.parsed.json`: 파싱 성공 시 JSON payload

`report.md`에는 provider와 검증 상태만 요약하고 raw response나 secret은 포함하지 않습니다.

## 에뮬레이션 성공 기준과 I/O 캡처

`emulate`와 `run`은 `--success-criterion`을 반복 지정해 완료 판단을 exit code에 반영할 수
있습니다. 지원 기준은 `boot-reached`, `uart-output`, `no-crash-for-instructions`입니다.
`uart-output`은 `--success-uart-contains <text>`와 함께 사용할 수 있습니다.

`emulation_result.json`은 항상 `success`, `success_criteria`, `exit_condition`,
`uart_output`, `semihosting` 필드를 포함합니다. 실제 Qiling/QEMU 어댑터가 UART/semihosting
hook을 제공하지 않는 경우 빈 배열로 남기며, 테스트/fixture는 emulator config의
`capture.uart_output`과 `capture.semihosting` 값을 통해 동일한 산출물 계약을 검증할 수
있습니다.

```bash
pip install -e ".[qiling]"
firmware-mvp emulate runs/demo/emulator_config.json --backend qiling --rootfs .
```

현재 Qiling extra는 Qiling 1.4.6의 Cortex-M 경로와 맞추기 위해 `unicorn==2.0.1.post1`, `setuptools<81`을 함께 고정합니다.

## 구조

```text
src/firmware_mvp/
  cli.py          # CLI 엔트리포인트
  services.py     # CLI/GUI가 공유할 파이프라인 서비스 API
  extractor.py    # 펌웨어 컨텍스트 추출
  rag.py          # 로컬 문서 검색
  inference.py    # 주변기기/MMIO 추론
  emulator.py     # 에뮬레이터 설정 생성 및 피드백 모델
  models.py       # JSON 직렬화 모델
references/
  stm32f1_memory_map.md
  memory_maps/stm32f1.json
schemas/
tests/
```

## MVP 경계

이 버전은 실제 LLM 호출과 Ghidra/IDA Headless 자동화를 안정적인 인터페이스 뒤에 둔 로컬 MVP입니다. 외부 도구가 없어도 파이프라인과 산출물 형식을 검증할 수 있고, 추후 `extractor.py`, `rag.py`, `inference.py`, `emulator.py` 내부 구현을 교체해 확장할 수 있습니다.
