# QEMU Adapter Design

## Goal

Add a future `qemu` emulation backend without changing CLI/service contracts already used by `stub` and `qiling`.

## Entry points

- CLI: extend `--backend stub|qiling` to `--backend stub|qiling|qemu` once the adapter is implemented.
- Service: implement `QemuEmulationBackend` behind `get_emulation_backend()`.
- Contract: backend `run()` returns the same `emulation_result.json` shape as existing backends:
  - `schema_version`
  - `backend`
  - `device`
  - `status`
  - `stop_reason`
  - `instruction_count`
  - `instruction_limit`
  - `timeout_seconds`
  - `mapped_regions`
  - `crash`
  - `uart_output`
  - `semihosting`
  - `exit_condition`
  - `success`
  - `success_criteria`
  - optional `events`

## Target split

### MCU/raw firmware

Use QEMU system emulation only when a supported board/machine exists. Required config fields:

- `qemu.machine`
- `qemu.cpu`
- `qemu.load_address`
- `qemu.entry_point`
- `qemu.timeout_seconds`

Unsupported MCU targets should fail closed with an actionable `qemu_target_not_configured` result rather than guessing a machine.

### Linux/router firmware

For extracted ELF userland binaries, prefer user-mode QEMU (`qemu-mipsel`, `qemu-arm`, etc.) with a caller-provided rootfs. Required config fields:

- `qemu.user_binary`
- `qemu.arch`
- `qemu.rootfs`
- `qemu.env`
- `qemu.timeout_seconds`

The adapter must not execute arbitrary extracted binaries unless the user selected the execution backend and rootfs explicitly.

## Safety boundaries

- Always apply wall-clock timeout.
- Capture stdout/stderr with size caps.
- Run in a caller-selected output directory.
- Do not require privileged Docker by default.
- Treat network as disabled unless explicitly configured.

## MVP implementation steps

1. Add `qemu` to backend choices.
2. Add `QemuEmulationBackend` that detects missing qemu binaries and returns structured actionable errors.
3. Add config generation fields under `emulator_config.json.qemu` without disturbing `qiling` fields.
4. Add smoke tests for missing-binary/actionable-error path.
5. Add Docker-only integration tests for actual QEMU execution.

## Deferred work

- Full board profile library.
- Kernel/userland orchestration for complete router firmware boot.
- Peripheral modeling beyond current MMIO dummy mapping.
