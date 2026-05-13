# Firmware MVP GUI Design

The GUI is a lightweight stdlib HTTP surface started with:

```bash
firmware-mvp gui --host 127.0.0.1 --port 8765
```

## Screens

- **Execution parameters**: command selector for `analyze`, `extract`, `infer`,
  `emulate`, `loop`, `report`, `feedback`, `validate`, `init-sample`, and
  `ingest-pdf`; common inputs for firmware/path, device, output directory,
  analysis backend, emulation backend, probe address, loop iteration limit,
  timeout, and success criterion.
- **Feedback / Validate / Artifacts**: form guidance for feedback and validate
  workflows plus artifact selector for `context.json`, `inference.json`,
  `emulator_config.json`, `emulation_result.json`, `loop_summary.json`, and
  `report.md`.
- **Job status / logs**: JSON status area showing job id, argv, status,
  returncode, captured logs, and errors.

## Runtime model

- The GUI starts CLI jobs through `python -m firmware_mvp.cli` so it shares the
  same service contracts as CLI automation.
- Jobs are tracked in memory and expose status/logs through `/api/jobs/<id>`.
- `/api/jobs/<id>/cancel` terminates the running subprocess.
- `/api/jobs/<id>/retry` re-runs the same argv.
- `/api/artifact?run_dir=<dir>&name=<artifact>` returns artifact content for
  file/field-level inspection by the frontend.
- Successful jobs with an output `report.md` regenerate the report with
  `--source-command`, so GUI-generated command, tool version, and timestamp are
  retained in the report artifact.

## Smoke coverage

`tests/test_gui.py` verifies that the screen exposes the core workflows, a GUI
job can run and rewrite the report command, artifacts can be read, retry works,
and unsupported commands are rejected.
