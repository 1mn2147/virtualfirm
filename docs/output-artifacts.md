# Output Artifacts Contract

Firmware MVP commands write stable, file-based artifacts under a caller-selected run directory. JSON artifacts include `schema_version` where the payload is part of the project contract.

## Run directory layout

| Path | Producer | Required for `validate` | Purpose |
| --- | --- | --- | --- |
| `context.json` | `extract`, `analyze`, `run`, `infer` | yes for full run | Firmware metadata, loaded image metadata, strings, MMIO candidates, tool observations, Ghidra/binwalk summaries, vulnerability/function context signals. |
| `inference.json` | `infer`, `analyze`, `run` | yes for full run | Peripheral/MMIO inference findings plus RAG hits and assumptions. |
| `emulator_config.json` | `infer`, `analyze`, `run` | yes for full run | Backend-neutral emulator mapping configuration generated from inference findings. |
| `emulation_result.json` | `emulate`, `run` | optional | Backend execution result, mapped region count, stop reason, success criteria, UART/semihosting captures, exit condition, and crash object when applicable. |
| `emulation.log` | `emulate`, `run` | no | Text summary for automation logs and quick inspection. |
| `loop_summary.json` | `loop` | optional-only valid | Feedback-loop iterations, patch status, and final loop config path. |
| `emulator_config.loop.json` | `loop` | no | Emulator config after feedback-loop patching. |
| `llm_audit.json` | `infer`, `analyze`, `run` with non-deterministic provider | no | Provider requested/used, network flag, validation status, attempts, fallback/failure reason. |
| `llm_attempts/attempt-N.raw.txt` | provider inference | no | Raw provider response for attempt `N`. |
| `llm_attempts/attempt-N.parsed.json` | provider inference | no | Parsed provider JSON when parsing succeeds. |
| `report.md` | most commands via report writer | no | Human-readable summary regenerated from available artifacts. |
| `embedded/` | `--extract-embedded` | no | Extracted filesystem contents and Ghidra target candidates referenced from `context.json.embedded_files`. |
| `.ghidra/` | `--analysis-backend ghidra` | no | Local Ghidra project/cache directory. |

## Validation modes

- Full run validation requires `context.json`, `inference.json`, and `emulator_config.json`.
- Optional-only validation accepts directories containing only optional execution artifacts such as `emulation_result.json` or `loop_summary.json`.
- `report.md`, logs, LLM attempts, extracted files, and Ghidra projects are intentionally not required by `validate`.

## Compatibility rules

- Additive fields are preferred over renaming existing fields.
- Existing required top-level files and `schema_version` must remain stable for automation.
- Optional tool-specific observations belong under `context.json.tool_observations` unless they become a stable top-level contract.
- New provider/emulator attempts should use numbered or namespaced files rather than overwriting prior attempt evidence.
- Emulation artifacts include `timeout_seconds`, `success`, `success_criteria`, `exit_condition`, `uart_output`, and `semihosting` so automation can gate on boot/UART/no-crash criteria without parsing logs.
- Read-time compatibility normalization for older artifacts is documented in `docs/artifact-compatibility.md`.
