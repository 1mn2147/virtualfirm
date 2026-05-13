from __future__ import annotations

from pathlib import Path
from typing import Any
import json

from .compat import normalize_artifact_payload
from .models import SCHEMA_VERSION


RUN_FILES = {
    "context": "context.json",
    "inference": "inference.json",
    "emulator_config": "emulator_config.json",
}

OPTIONAL_RUN_FILES = {
    "emulation_result": "emulation_result.json",
    "loop_summary": "loop_summary.json",
}


REQUIRED_KEYS = {
    "context": {
        "schema_version",
        "path",
        "size_bytes",
        "sha256",
        "entropy",
        "architecture_hint",
        "encrypted_or_compressed_likely",
        "entry_point",
        "strings",
        "mmio_addresses",
        "tool_observations",
    },
    "inference": {"schema_version", "device", "findings", "rag_hits", "assumptions"},
    "emulator_config": {
        "schema_version",
        "device",
        "engine",
        "firmware",
        "qiling",
        "mappings",
        "feedback_schema",
        "llm_feedback_prompt_template",
        "raw_findings",
    },
    "emulation_result": {
        "schema_version",
        "backend",
        "device",
        "status",
        "stop_reason",
        "instruction_count",
        "instruction_limit",
        "mapped_regions",
        "crash",
        "uart_output",
        "semihosting",
        "exit_condition",
        "success",
    },
    "loop_summary": {
        "schema_version",
        "backend",
        "status",
        "stop_reason",
        "iterations",
        "final_config",
    },
}


def validate_run_dir(run_dir: Path) -> list[str]:
    errors: list[str] = []
    has_required_artifact = any((run_dir / filename).exists() for filename in RUN_FILES.values())
    has_optional_artifact = any((run_dir / filename).exists() for filename in OPTIONAL_RUN_FILES.values())
    if not has_required_artifact and has_optional_artifact:
        return _validate_optional_only(run_dir)

    for artifact, filename in RUN_FILES.items():
        path = run_dir / filename
        if not path.exists():
            errors.append(f"missing {filename}")
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"{filename} is not valid JSON: {exc}")
            continue
        payload = normalize_artifact_payload(artifact, payload)
        errors.extend(_validate_payload(artifact, filename, payload))
    for artifact, filename in OPTIONAL_RUN_FILES.items():
        path = run_dir / filename
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"{filename} is not valid JSON: {exc}")
            continue
        payload = normalize_artifact_payload(artifact, payload)
        errors.extend(_validate_payload(artifact, filename, payload))
    return errors


def _validate_optional_only(run_dir: Path) -> list[str]:
    errors: list[str] = []
    for artifact, filename in OPTIONAL_RUN_FILES.items():
        path = run_dir / filename
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"{filename} is not valid JSON: {exc}")
            continue
        payload = normalize_artifact_payload(artifact, payload)
        errors.extend(_validate_payload(artifact, filename, payload))
    return errors


def _validate_payload(artifact: str, filename: str, payload: dict[str, Any]) -> list[str]:
    errors = _validate_required_and_version(artifact, filename, payload)
    if artifact == "inference":
        errors.extend(_validate_findings(payload))
    if artifact == "emulator_config":
        errors.extend(_validate_mappings(payload))
    if artifact == "emulation_result":
        errors.extend(_validate_emulation_result(payload))
    if artifact == "loop_summary":
        errors.extend(_validate_loop_summary(payload))
    return errors


def validate_inference_payload(payload: dict[str, Any]) -> list[str]:
    """Validate an inference payload before dataclass conversion and emulator mapping.

    This intentionally enforces the project-local subset of
    ``schemas/inference.schema.json`` without adding a runtime JSON Schema
    dependency.
    """

    if not isinstance(payload, dict):
        return ["inference payload must be an object"]
    errors = _validate_required_and_version("inference", "inference payload", payload)
    if not isinstance(payload.get("device"), str) or not payload.get("device"):
        errors.append("inference payload device must be a non-empty string")
    if not isinstance(payload.get("findings"), list):
        errors.append("inference payload findings must be a list")
    else:
        errors.extend(_validate_finding_values(payload))
    if not isinstance(payload.get("rag_hits"), list):
        errors.append("inference payload rag_hits must be a list")
    else:
        errors.extend(_validate_rag_hits(payload))
    if not isinstance(payload.get("assumptions"), list) or not all(
        isinstance(item, str) for item in payload.get("assumptions", [])
    ):
        errors.append("inference payload assumptions must be a list of strings")
    return errors


def _validate_findings(payload: dict[str, Any]) -> list[str]:
    errors = []
    findings = payload.get("findings", [])
    if not isinstance(findings, list):
        return ["inference.json findings must be a list"]
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            errors.append(f"inference.json findings[{index}] must be an object")
            continue
        required = {"mmio_address", "type", "action", "value", "confidence", "evidence"}
        missing = required - finding.keys()
        if missing:
            errors.append(f"inference.json findings[{index}] missing: {', '.join(sorted(missing))}")
    return errors


def _validate_finding_values(payload: dict[str, Any]) -> list[str]:
    errors = []
    for index, finding in enumerate(payload.get("findings", [])):
        if not isinstance(finding, dict):
            errors.append(f"inference payload findings[{index}] must be an object")
            continue
        prefix = f"inference payload findings[{index}]"
        address = finding.get("mmio_address")
        if not isinstance(address, str) or not _is_hex(address):
            errors.append(f"{prefix} mmio_address must be a hex string")
        for key in ("type", "action", "value"):
            if not isinstance(finding.get(key), str) or not finding.get(key):
                errors.append(f"{prefix} {key} must be a non-empty string")
        value = finding.get("value")
        if isinstance(value, str) and not _is_hex(value):
            errors.append(f"{prefix} value must be a hex string")
        confidence = finding.get("confidence")
        if not _is_number(confidence) or not 0 <= float(confidence) <= 1:
            errors.append(f"{prefix} confidence must be a number between 0 and 1")
        evidence = finding.get("evidence")
        if not isinstance(evidence, list) or not all(isinstance(item, str) for item in evidence):
            errors.append(f"{prefix} evidence must be a list of strings")
    return errors


def _validate_rag_hits(payload: dict[str, Any]) -> list[str]:
    errors = []
    for index, hit in enumerate(payload.get("rag_hits", [])):
        if not isinstance(hit, dict):
            errors.append(f"inference payload rag_hits[{index}] must be an object")
            continue
        required = {"source", "score", "excerpt"}
        missing = required - hit.keys()
        if missing:
            errors.append(f"inference payload rag_hits[{index}] missing: {', '.join(sorted(missing))}")
        if not isinstance(hit.get("source"), str) or not hit.get("source"):
            errors.append(f"inference payload rag_hits[{index}] source must be a non-empty string")
        if not _is_integer(hit.get("score")):
            errors.append(f"inference payload rag_hits[{index}] score must be an integer")
        if not isinstance(hit.get("excerpt"), str):
            errors.append(f"inference payload rag_hits[{index}] excerpt must be a string")
        if "kind" in hit and not isinstance(hit.get("kind"), str):
            errors.append(f"inference payload rag_hits[{index}] kind must be a string")
        if "source_location" in hit and hit.get("source_location") is not None and not isinstance(
            hit.get("source_location"),
            str,
        ):
            errors.append(f"inference payload rag_hits[{index}] source_location must be a string or null")
    return errors


def _is_hex(value: str) -> bool:
    try:
        int(value, 16)
    except (TypeError, ValueError):
        return False
    return value.lower().startswith("0x")


def _is_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _is_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_required_and_version(
    artifact: str, filename: str, payload: dict[str, Any]
) -> list[str]:
    errors = []
    missing = REQUIRED_KEYS[artifact] - payload.keys()
    if missing:
        errors.append(f"{filename} missing keys: {', '.join(sorted(missing))}")
    if payload.get("schema_version") != SCHEMA_VERSION:
        errors.append(
            f"{filename} schema_version={payload.get('schema_version')!r}, expected {SCHEMA_VERSION!r}"
        )
    return errors


def _validate_mappings(payload: dict[str, Any]) -> list[str]:
    errors = []
    for index, mapping in enumerate(payload.get("mappings", [])):
        required = {"base", "size", "type", "default_read", "on_write", "source_mmio"}
        missing = required - mapping.keys()
        if missing:
            errors.append(
                f"emulator_config.json mappings[{index}] missing: {', '.join(sorted(missing))}"
            )
    return errors


def _validate_emulation_result(payload: dict[str, Any]) -> list[str]:
    status = payload.get("status")
    if status not in {"completed", "crashed"}:
        return [f"emulation_result.json status={status!r}, expected completed|crashed"]
    if status == "crashed" and not payload.get("crash"):
        return ["emulation_result.json crashed status requires crash object"]
    errors = []
    if not isinstance(payload.get("success"), bool):
        errors.append("emulation_result.json success must be a boolean")
    if not isinstance(payload.get("success_criteria"), list):
        errors.append("emulation_result.json success_criteria must be a list")
    if not isinstance(payload.get("uart_output"), list):
        errors.append("emulation_result.json uart_output must be a list")
    if not isinstance(payload.get("semihosting"), list):
        errors.append("emulation_result.json semihosting must be a list")
    if not isinstance(payload.get("exit_condition"), dict):
        errors.append("emulation_result.json exit_condition must be an object")
    return errors


def _validate_loop_summary(payload: dict[str, Any]) -> list[str]:
    status = payload.get("status")
    if status not in {"completed", "failed"}:
        return [f"loop_summary.json status={status!r}, expected completed|failed"]
    if not isinstance(payload.get("iterations"), list):
        return ["loop_summary.json iterations must be a list"]
    return []
