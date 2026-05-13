# Artifact Compatibility Layer

The CLI accepts older run artifacts when fields were added additively after the
initial MVP schema. Compatibility normalization is intentionally read-time only:
it lets validation, reporting, and feedback-context loading consume legacy JSON
without rewriting the original files.

## Current migrations

- `emulation_result.json` without execution-gating fields receives:
  - `uart_output: []`
  - `semihosting: []`
  - `exit_condition` derived from `status` and `stop_reason`
  - `success_criteria: []`
  - `success: status != "crashed"`
- `emulator_config.json` without later runtime helper fields receives defaults
  for `qiling`, `feedback_schema`, `llm_feedback_prompt_template`, and
  `raw_findings`.

## Contract

- New fields should remain additive when possible.
- Compatibility lives in `firmware_mvp.compat.normalize_artifact_payload`.
- Validators and report readers normalize before checking required keys.
- The layer should not mask malformed current-version payloads; it only fills
  known omitted fields from older MVP artifacts.
