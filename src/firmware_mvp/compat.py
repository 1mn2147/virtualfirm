from __future__ import annotations

from copy import deepcopy
from typing import Any


def normalize_artifact_payload(artifact: str, payload: dict[str, Any]) -> dict[str, Any]:
    normalized = deepcopy(payload)
    if artifact == "emulation_result":
        _normalize_emulation_result(normalized)
    elif artifact == "emulator_config":
        _normalize_emulator_config(normalized)
    return normalized


def _normalize_emulation_result(payload: dict[str, Any]) -> None:
    status = payload.get("status")
    stop_reason = payload.get("stop_reason")
    payload.setdefault("uart_output", [])
    payload.setdefault("semihosting", [])
    payload.setdefault(
        "exit_condition",
        {
            "type": stop_reason,
            "status": status,
            "crashed": status == "crashed",
        },
    )
    payload.setdefault("success_criteria", [])
    payload.setdefault("success", status != "crashed")


def _normalize_emulator_config(payload: dict[str, Any]) -> None:
    payload.setdefault("qiling", {"rootfs": None, "load_address": "0x08000000"})
    payload.setdefault(
        "feedback_schema",
        {
            "pc": "hex string",
            "access": "read|write",
            "address": "hex string",
            "registers": {"r0": "hex string"},
        },
    )
    payload.setdefault(
        "llm_feedback_prompt_template",
        (
            "Emulation stopped on {access} at {address} from PC={pc}. "
            "Infer the peripheral register and propose a dummy value as JSON."
        ),
    )
    payload.setdefault("raw_findings", [])
