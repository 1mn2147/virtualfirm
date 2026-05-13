from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable
import json
import shutil

from .models import InferenceResult, SCHEMA_VERSION

SUCCESS_CRITERIA = {
    "boot-reached",
    "uart-output",
    "no-crash-for-instructions",
}


def build_emulator_config(
    inference: InferenceResult,
    firmware_path: str | None = None,
    entry_point: str | None = None,
    architecture_hint: str | None = None,
) -> dict[str, Any]:
    mappings = []
    for finding in inference.findings:
        address = int(finding.mmio_address, 16)
        base = address & ~0x3FF
        mappings.append(
            {
                "base": f"0x{base:08X}",
                "size": "0x400",
                "type": finding.type,
                "default_read": finding.value,
                "on_write": "store_and_continue",
                "source_mmio": finding.mmio_address,
            }
        )

    unique_mappings = {(item["base"], item["type"]): item for item in mappings}
    return {
        "schema_version": SCHEMA_VERSION,
        "device": inference.device,
        "engine": "qiling-or-qemu-wrapper",
        "firmware": {
            "path": firmware_path,
            "entry_point": entry_point,
            "architecture_hint": architecture_hint,
        },
        "qiling": {
            "rootfs": None,
            "load_address": "0x08000000",
        },
        "mappings": list(unique_mappings.values()),
        "feedback_schema": {
            "pc": "hex string",
            "access": "read|write",
            "address": "hex string",
            "registers": {"r0": "hex string"},
        },
        "llm_feedback_prompt_template": (
            "Emulation stopped on {access} at {address} from PC={pc}. "
            "Infer the peripheral register and propose a dummy value as JSON."
        ),
        "raw_findings": [asdict(finding) for finding in inference.findings],
    }


def propose_feedback_patch(address: str, access: str = "read") -> dict[str, Any]:
    value = int(address, 16)
    base = value & ~0x3FF
    return {
        "mmio_address": f"0x{value:08X}",
        "type": "MMIO",
        "action": "map_dummy_mmio",
        "value": "0x00000000",
        "emulator_mapping": {
            "base": f"0x{base:08X}",
            "size": "0x400",
            "default_read": "0x00000000",
            "on_write": "store_and_continue" if access == "write" else "ignore_and_continue",
        },
    }


def apply_feedback_patch(config: dict[str, Any], patch: dict[str, Any]) -> bool:
    mapping = dict(patch["emulator_mapping"])
    mapping["type"] = patch.get("type", "MMIO")
    mapping["source_mmio"] = patch["mmio_address"]
    mapping_key = (mapping["base"], mapping["type"])
    existing = {(item["base"], item["type"]) for item in config.get("mappings", [])}
    if mapping_key in existing:
        return False
    config.setdefault("mappings", []).append(mapping)
    config.setdefault("raw_findings", []).append(
        {
            "mmio_address": patch["mmio_address"],
            "type": patch.get("type", "MMIO"),
            "action": patch.get("action", "map_dummy_mmio"),
            "value": patch.get("value", "0x00000000"),
            "confidence": 0.5,
            "evidence": ["added by feedback loop after unmapped MMIO crash"],
            "peripheral_name": None,
            "reference_range": None,
            "reference_source": None,
        }
    )
    return True


def run_feedback_loop(
    emulator_config_path: Path,
    out: Path,
    probe_address: str | None,
    access: str,
    pc: str,
    max_iterations: int,
    instruction_limit: int = 100000,
    timeout_seconds: int = 30,
    runner: Callable[[Path, str | None, str, str, int, int], dict[str, Any]] | None = None,
    backend_name: str = "stub",
) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    working_config_path = out / "emulator_config.loop.json"
    shutil.copyfile(emulator_config_path, working_config_path)

    seen_crashes: set[tuple[str, str]] = set()
    iterations = []
    status = "completed"
    stop_reason = "completed"
    if runner is None:
        runner = run_emulation_stub

    for index in range(1, max_iterations + 1):
        iteration_dir = out / "iterations" / str(index)
        iteration_dir.mkdir(parents=True, exist_ok=True)
        result = runner(
            working_config_path,
            probe_address,
            access,
            pc,
            instruction_limit,
            timeout_seconds,
        )
        (iteration_dir / "emulation_result.json").write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        shutil.copyfile(working_config_path, iteration_dir / "emulator_config.json")

        iteration_summary = {
            "iteration": index,
            "status": result["status"],
            "stop_reason": result["stop_reason"],
            "config": str(iteration_dir / "emulator_config.json"),
            "result": str(iteration_dir / "emulation_result.json"),
            "patch_applied": False,
        }
        iterations.append(iteration_summary)

        if result["status"] != "crashed":
            status = "completed"
            stop_reason = result["stop_reason"]
            break

        crash = result["crash"]
        crash_key = (crash["pc"], crash["address"])
        if crash_key in seen_crashes:
            status = "failed"
            stop_reason = "repeated_crash"
            break
        seen_crashes.add(crash_key)

        config = json.loads(working_config_path.read_text(encoding="utf-8"))
        patch = crash.get("proposed_patch")
        if not patch:
            status = "failed"
            stop_reason = "no_patch_available"
            break
        patch_applied = apply_feedback_patch(config, patch)
        iteration_summary["patch_applied"] = patch_applied
        if not patch_applied:
            status = "failed"
            stop_reason = "duplicate_patch"
            break
        working_config_path.write_text(
            json.dumps(config, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    else:
        status = "failed"
        stop_reason = "max_iterations_reached"

    summary = {
        "schema_version": SCHEMA_VERSION,
        "backend": backend_name,
        "status": status,
        "stop_reason": stop_reason,
        "iterations": iterations,
        "final_config": str(working_config_path),
        "timeout_seconds": timeout_seconds,
    }
    (out / "loop_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return summary


def run_emulation_stub(
    emulator_config_path: Path,
    probe_address: str | None = None,
    access: str = "read",
    pc: str = "0x00000000",
    instruction_limit: int = 100000,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    config = json.loads(emulator_config_path.read_text(encoding="utf-8"))
    mappings = config.get("mappings", [])
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "backend": "stub",
        "device": config.get("device", "unknown"),
        "status": "completed",
        "stop_reason": "no_probe_address",
        "instruction_count": 0,
        "instruction_limit": instruction_limit,
        "timeout_seconds": timeout_seconds,
        "mapped_regions": len(mappings),
        "crash": None,
        "uart_output": _capture_list(config, "uart_output"),
        "semihosting": _capture_list(config, "semihosting"),
    }
    if timeout_seconds <= 0:
        result["status"] = "crashed"
        result["stop_reason"] = "wall_clock_timeout"
        result["crash"] = {
            "pc": _normalize_hex(pc),
            "access": "execute",
            "address": _normalize_hex(pc),
            "registers": {},
            "message": "stub backend wall-clock timeout before execution",
            "proposed_patch": None,
        }
        return result
    if not probe_address:
        return result

    address_value = int(probe_address, 16)
    mapped = _find_mapping(address_value, mappings)
    if mapped:
        result["status"] = "completed"
        result["stop_reason"] = "mapped_mmio_access"
        result["instruction_count"] = 1
        result["access"] = {
            "pc": _normalize_hex(pc),
            "access": access,
            "address": f"0x{address_value:08X}",
            "mapping": mapped,
        }
        return result

    result["status"] = "crashed"
    result["stop_reason"] = "unmapped_mmio"
    result["instruction_count"] = 1
    result["crash"] = {
        "pc": _normalize_hex(pc),
        "access": access,
        "address": f"0x{address_value:08X}",
        "registers": {
            "r0": "0x00000000",
            "r1": "0x00000000",
            "lr": "0x00000000",
            "sp": "0x00000000",
        },
        "message": "stub backend detected MMIO access outside configured mappings",
        "proposed_patch": propose_feedback_patch(f"0x{address_value:08X}", access),
    }
    return result


def finalize_emulation_result(
    result: dict[str, Any],
    success_criteria: tuple[str, ...] | list[str] = (),
    success_uart_contains: str | None = None,
) -> dict[str, Any]:
    result.setdefault("uart_output", [])
    result.setdefault("semihosting", [])
    result["exit_condition"] = {
        "type": result.get("stop_reason"),
        "status": result.get("status"),
        "crashed": result.get("status") == "crashed",
    }
    criteria = list(success_criteria)
    checks = [
        _evaluate_success_criterion(result, criterion, success_uart_contains)
        for criterion in criteria
    ]
    result["success_criteria"] = checks
    result["success"] = all(item["passed"] for item in checks) if checks else result.get("status") != "crashed"
    return result


def _evaluate_success_criterion(
    result: dict[str, Any],
    criterion: str,
    success_uart_contains: str | None,
) -> dict[str, Any]:
    if criterion == "boot-reached":
        passed = any(item.get("event") == "boot_reached" for item in result.get("events", []))
        return {"criterion": criterion, "passed": passed, "evidence": "events.boot_reached"}
    if criterion == "uart-output":
        output = "\n".join(str(item) for item in result.get("uart_output", []))
        passed = bool(output)
        evidence = "uart_output non-empty"
        if success_uart_contains:
            passed = success_uart_contains in output
            evidence = f"uart_output contains {success_uart_contains!r}"
        return {"criterion": criterion, "passed": passed, "evidence": evidence}
    if criterion == "no-crash-for-instructions":
        instruction_count = int(result.get("instruction_count") or 0)
        instruction_limit = int(result.get("instruction_limit") or 0)
        passed = result.get("status") != "crashed" and instruction_count >= instruction_limit
        return {
            "criterion": criterion,
            "passed": passed,
            "evidence": f"instruction_count={instruction_count} instruction_limit={instruction_limit}",
        }
    return {"criterion": criterion, "passed": False, "evidence": "unknown criterion"}


def _find_mapping(address: int, mappings: list[dict[str, Any]]) -> dict[str, Any] | None:
    for mapping in mappings:
        base = int(mapping["base"], 16)
        size = int(mapping["size"], 16)
        if base <= address < base + size:
            return mapping
    return None


def _capture_list(config: dict[str, Any], key: str) -> list[Any]:
    capture = config.get("capture", {})
    if isinstance(capture, dict) and isinstance(capture.get(key), list):
        return capture[key]
    test_io = config.get("test_io", {})
    if isinstance(test_io, dict) and isinstance(test_io.get(key), list):
        return test_io[key]
    return []


def _normalize_hex(value: str) -> str:
    return f"0x{int(value, 16):08X}"
