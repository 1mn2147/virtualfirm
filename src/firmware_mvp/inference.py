from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import copy
import json
import re

from .inference_providers import ProviderError, call_provider
from .models import FirmwareContext, InferenceResult, PeripheralFinding, RagHit, SCHEMA_VERSION
from .reference_db import PeripheralRange, lookup_address
from .validation import validate_inference_payload

_PROVIDER_CHOICES = {"deterministic", "mock", "openai", "local"}
_FALLBACK_CHOICES = {"none", "deterministic"}
_SECRET_PATTERN = re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,;]+")


@dataclass(frozen=True)
class InferenceOptions:
    provider: str = "deterministic"
    fallback: str = "none"
    max_retries: int = 1
    max_prompt_chars: int = 6000
    mock_response: str = "valid"
    mock_response_path: Path | None = None
    raw_log_enabled: bool = True
    timeout_seconds: int = 30
    max_raw_response_chars: int = 20000

    def __post_init__(self) -> None:
        if self.provider not in _PROVIDER_CHOICES:
            raise ValueError(f"provider must be one of {sorted(_PROVIDER_CHOICES)}")
        if self.fallback not in _FALLBACK_CHOICES:
            raise ValueError(f"fallback must be one of {sorted(_FALLBACK_CHOICES)}")
        if self.max_retries < 0:
            raise ValueError("max_retries must be >= 0")
        if self.max_prompt_chars <= 0:
            raise ValueError("max_prompt_chars must be > 0")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be > 0")
        if self.max_raw_response_chars <= 0:
            raise ValueError("max_raw_response_chars must be > 0")


@dataclass(frozen=True)
class InferenceExecution:
    result: InferenceResult | None
    audit: dict[str, Any] | None = None
    artifacts: dict[str, Path] | None = None
    errors: list[str] | None = None


def run_inference(
    context: FirmwareContext,
    device: str,
    rag_hits: list[RagHit],
    memory_ranges: list[PeripheralRange] | None = None,
    options: InferenceOptions | None = None,
    audit_dir: Path | None = None,
    feedback_artifacts: dict[str, Any] | None = None,
) -> InferenceExecution:
    options = options or InferenceOptions()
    memory_ranges = memory_ranges or []
    if options.provider == "deterministic":
        return InferenceExecution(
            result=infer_peripherals(context, device, rag_hits, memory_ranges),
            artifacts={},
            errors=[],
        )
    return _run_provider_inference(
        context,
        device,
        rag_hits,
        memory_ranges,
        options,
        audit_dir,
        feedback_artifacts or {},
    )


def infer_peripherals(
    context: FirmwareContext,
    device: str,
    rag_hits: list[RagHit],
    memory_ranges: list[PeripheralRange] | None = None,
) -> InferenceResult:
    memory_ranges = memory_ranges or []
    findings = []
    for address in context.mmio_addresses:
        value = int(address, 16)
        matched_range = lookup_address(value, memory_ranges)
        peripheral = _classify(value, matched_range)
        if peripheral == "UNKNOWN":
            continue
        findings.append(
            PeripheralFinding(
                mmio_address=address,
                type=peripheral,
                action=_default_action(peripheral),
                value=_default_value(peripheral, matched_range),
                confidence=_confidence(peripheral, rag_hits, matched_range),
                evidence=_evidence(address, peripheral, context, rag_hits, matched_range),
                peripheral_name=matched_range.name if matched_range else None,
                reference_range=matched_range.range_text if matched_range else None,
                reference_source=matched_range.source if matched_range else None,
            )
        )

    assumptions = [
        "External LLM is not required for this MVP; deterministic heuristics generate parseable JSON.",
        "Unrecognized MMIO addresses are omitted from emulator_config and should be added through feedback logs.",
    ]
    if memory_ranges:
        assumptions.append("MMIO classifications came from structured memory map range lookup first.")
    else:
        assumptions.append("No structured memory map was loaded; generic MMIO fallback was used.")
    if context.encrypted_or_compressed_likely:
        assumptions.append("High entropy suggests compressed or encrypted data; static findings may be incomplete.")

    return InferenceResult(device=device, findings=findings, rag_hits=rag_hits, assumptions=assumptions)


def build_inference_prompt(
    context: FirmwareContext,
    device: str,
    rag_hits: list[RagHit],
    memory_ranges: list[PeripheralRange],
    max_chars: int = 6000,
    feedback_artifacts: dict[str, Any] | None = None,
) -> str:
    lines = [
        "You are an embedded firmware reverse engineer.",
        "Return only JSON matching this shape:",
        '{"schema_version":"0.2.0","device":"...","findings":[{"mmio_address":"0x...","type":"UART|SPI|I2C|TIMER|GPIO|RCC|MMIO|CORE_SYSTEM","action":"map_dummy_mmio|map_core_system_stub|log_access","value":"0x00000000","confidence":0.0,"evidence":["..."],"peripheral_name":null,"reference_range":null,"reference_source":null}],"rag_hits":[],"assumptions":[]}',
        f"Device: {device}",
        f"Firmware path: {_redact(context.path)}",
        f"Architecture hint: {context.architecture_hint}",
        f"Entry point: {context.entry_point}",
        f"Entropy: {context.entropy}",
        "MMIO candidates:",
        ", ".join(context.mmio_addresses[:80]) or "none",
        "Strings:",
        _redact(" | ".join(context.strings[:40])),
    ]
    lines.append("Vulnerability candidates:")
    for item in context.vulnerability_candidates[:20]:
        evidence = item.get("evidence", [])
        first_evidence = evidence[0] if isinstance(evidence, list) and evidence else ""
        lines.append(
            "- "
            f"risk={item.get('risk')} "
            f"category={item.get('category')} "
            f"function={item.get('function')} "
            f"symbol={item.get('symbol')} "
            f"evidence={_redact(str(first_evidence))}"
        )
    lines.append("Function contexts:")
    for item in context.function_contexts[:8]:
        lines.append(
            "- "
            f"name={item.get('name')} "
            f"entry={item.get('entry_point')} "
            f"priority={item.get('review_priority')} "
            f"signals={','.join(str(signal) for signal in item.get('flow_signals', []))}"
        )
        for snippet in item.get("evidence_snippets", [])[:4]:
            if not isinstance(snippet, dict):
                continue
            lines.append(
                "  snippet "
                f"{snippet.get('signal')} line={snippet.get('line')} "
                f"text={_redact(str(snippet.get('text')))}"
            )
        decompiled = item.get("decompiled")
        if isinstance(decompiled, str) and decompiled.strip():
            excerpt = " ".join(decompiled.strip().splitlines()[:8])
            lines.append(f"  decompiled_excerpt={_redact(excerpt[:800])}")
    lines.append("Structured memory ranges:")
    for item in memory_ranges[:80]:
        lines.append(f"- {item.range_text} {item.name} type={item.type} source={item.source}")
    lines.append("RAG hits:")
    for hit in rag_hits[:20]:
        excerpt = _redact(hit.excerpt).replace("\n", " ")
        lines.append(
            f"- source={hit.source} location={hit.source_location} "
            f"score={hit.score} kind={hit.kind} excerpt={excerpt}"
        )
    _append_feedback_artifacts(lines, feedback_artifacts or {})
    prompt = "\n".join(lines)
    return prompt[:max_chars]


def _append_feedback_artifacts(lines: list[str], feedback_artifacts: dict[str, Any]) -> None:
    if not feedback_artifacts:
        return
    lines.append("Emulation feedback artifacts:")
    emulation_result = feedback_artifacts.get("emulation_result")
    if isinstance(emulation_result, dict):
        lines.append(
            "- emulation_result "
            f"status={emulation_result.get('status')} "
            f"stop_reason={emulation_result.get('stop_reason')}"
        )
        crash = emulation_result.get("crash")
        if isinstance(crash, dict):
            lines.append(
                "- crash "
                f"pc={crash.get('pc')} "
                f"access={crash.get('access')} "
                f"address={crash.get('address')}"
            )
            patch = crash.get("proposed_patch")
            if isinstance(patch, dict):
                lines.append(
                    "- proposed_patch "
                    f"address={patch.get('address')} "
                    f"type={patch.get('type')} "
                    f"action={patch.get('action')}"
                )

    loop_summary = feedback_artifacts.get("loop_summary")
    if isinstance(loop_summary, dict):
        iterations = loop_summary.get("iterations")
        iteration_count = len(iterations) if isinstance(iterations, list) else 0
        lines.append(
            "- loop_summary "
            f"status={loop_summary.get('status')} "
            f"iterations={iteration_count} "
            f"final_config={loop_summary.get('final_config')}"
        )
        if isinstance(iterations, list) and iterations:
            last = iterations[-1]
            if isinstance(last, dict):
                lines.append(
                    "- last_loop_iteration "
                    f"status={last.get('status')} "
                    f"stop_reason={last.get('stop_reason')} "
                    f"patch_applied={last.get('patch_applied')}"
                )


def _run_provider_inference(
    context: FirmwareContext,
    device: str,
    rag_hits: list[RagHit],
    memory_ranges: list[PeripheralRange],
    options: InferenceOptions,
    audit_dir: Path | None,
    feedback_artifacts: dict[str, Any],
) -> InferenceExecution:
    prompt = build_inference_prompt(
        context,
        device,
        rag_hits,
        memory_ranges,
        max_chars=options.max_prompt_chars,
        feedback_artifacts=feedback_artifacts,
    )
    audit = _new_audit(options)
    attempts_dir = audit_dir / "llm_attempts" if audit_dir and options.raw_log_enabled else None
    artifacts: dict[str, Path] = {}
    last_errors: list[str] = []

    for attempt in range(1, options.max_retries + 2):
        raw_text = ""
        parsed: dict[str, Any] | None = None
        validation_errors: list[str] = []
        failure_reason: str | None = None
        try:
            response = call_provider(options, prompt, context, device, rag_hits, memory_ranges)
            audit["provider_used"] = response.provider_used
            audit["network_performed"] = response.network_performed
            raw_text = response.raw_text[: options.max_raw_response_chars]
            parsed = json.loads(raw_text)
            validation_errors = validate_inference_payload(parsed)
            repair_notes: list[str] = []
            if validation_errors:
                repaired, repair_notes = _repair_inference_payload(parsed, device)
                if repair_notes:
                    repaired_errors = validate_inference_payload(repaired)
                    if not repaired_errors:
                        parsed = repaired
                        validation_errors = []
            if not validation_errors:
                try:
                    result = _inference_from_payload(parsed)
                except (KeyError, TypeError, ValueError) as exc:
                    validation_errors = [f"conversion_failed: {exc}"]
                    failure_reason = "conversion_failed"
                    last_errors = validation_errors
                else:
                    _record_attempt(
                        audit,
                        attempts_dir,
                        attempt,
                        raw_text,
                        parsed,
                        [],
                        None,
                        repair_applied=bool(repair_notes),
                        repair_notes=repair_notes,
                    )
                    audit["validation_status"] = "valid"
                    return InferenceExecution(
                        result=result,
                        audit=audit,
                        artifacts=_write_audit(audit_dir, audit, artifacts),
                        errors=[],
                    )
            if validation_errors and failure_reason is None:
                failure_reason = "validation_failed"
                last_errors = validation_errors
        except json.JSONDecodeError as exc:
            failure_reason = f"invalid_json: {exc}"
            last_errors = [failure_reason]
        except ProviderError as exc:
            failure_reason = f"provider_error: {exc}"
            last_errors = [str(exc)]
        _record_attempt(
            audit,
            attempts_dir,
            attempt,
            raw_text,
            parsed,
            validation_errors,
            failure_reason,
        )

    if options.fallback == "deterministic":
        result = infer_peripherals(context, device, rag_hits, memory_ranges)
        audit["provider_used"] = "deterministic"
        audit["validation_status"] = "fallback"
        audit["fallback_from"] = options.provider
        audit["fallback_reason"] = "; ".join(last_errors) or "provider output invalid"
        return InferenceExecution(
            result=result,
            audit=audit,
            artifacts=_write_audit(audit_dir, audit, artifacts),
            errors=[],
        )

    audit["validation_status"] = "invalid"
    audit["fallback_reason"] = "; ".join(last_errors) or "provider output invalid"
    return InferenceExecution(
        result=None,
        audit=audit,
        artifacts=_write_audit(audit_dir, audit, artifacts),
        errors=last_errors or ["provider output invalid"],
    )


def _inference_from_payload(payload: dict[str, Any]) -> InferenceResult:
    findings = []
    for item in payload.get("findings", []):
        finding_payload = {
            "mmio_address": item["mmio_address"],
            "type": item["type"],
            "action": item["action"],
            "value": item["value"],
            "confidence": float(item["confidence"]),
            "evidence": list(item["evidence"]),
            "peripheral_name": item.get("peripheral_name"),
            "reference_range": item.get("reference_range"),
            "reference_source": item.get("reference_source"),
        }
        findings.append(PeripheralFinding(**finding_payload))
    rag_hits = [RagHit(**hit) for hit in payload.get("rag_hits", [])]
    return InferenceResult(
        device=payload["device"],
        findings=findings,
        rag_hits=rag_hits,
        assumptions=list(payload.get("assumptions", [])),
        schema_version=payload.get("schema_version", SCHEMA_VERSION),
    )


def _repair_inference_payload(payload: dict[str, Any], device: str) -> tuple[dict[str, Any], list[str]]:
    """Apply narrow deterministic repairs to parsed provider JSON.

    This only fixes shape issues that are safe and auditable. Structural errors
    such as non-list findings or malformed RAG hits still fail closed.
    """

    repaired = copy.deepcopy(payload)
    notes: list[str] = []
    if not isinstance(repaired.get("schema_version"), str):
        repaired["schema_version"] = SCHEMA_VERSION
        notes.append("added schema_version")
    if not isinstance(repaired.get("device"), str) or not repaired.get("device"):
        repaired["device"] = device
        notes.append("added device")
    if not isinstance(repaired.get("assumptions"), list) or not all(
        isinstance(item, str) for item in repaired.get("assumptions", [])
    ):
        repaired["assumptions"] = []
        notes.append("normalized assumptions")
    if not isinstance(repaired.get("rag_hits"), list):
        repaired["rag_hits"] = []
        notes.append("normalized rag_hits")

    findings = repaired.get("findings")
    if isinstance(findings, list):
        for index, finding in enumerate(findings):
            if not isinstance(finding, dict):
                continue
            if "confidence" not in finding:
                finding["confidence"] = 0.5
                notes.append(f"findings[{index}] added default confidence")
            elif _is_number(finding.get("confidence")):
                confidence = float(finding["confidence"])
                clamped = min(1.0, max(0.0, confidence))
                if clamped != confidence:
                    finding["confidence"] = clamped
                    notes.append(f"findings[{index}] clamped confidence")
            evidence = finding.get("evidence")
            if isinstance(evidence, str):
                finding["evidence"] = [evidence]
                notes.append(f"findings[{index}] converted evidence string to list")
            elif "evidence" not in finding:
                finding["evidence"] = ["provider omitted evidence; deterministic repair added placeholder"]
                notes.append(f"findings[{index}] added placeholder evidence")
    return repaired, notes


def _new_audit(options: InferenceOptions) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "provider_requested": options.provider,
        "provider_used": None,
        "network_performed": False,
        "validation_status": "pending",
        "fallback_from": None,
        "fallback_reason": None,
        "attempts": [],
    }


def _record_attempt(
    audit: dict[str, Any],
    attempts_dir: Path | None,
    attempt: int,
    raw_text: str,
    parsed: dict[str, Any] | None,
    validation_errors: list[str],
    failure_reason: str | None,
    *,
    repair_applied: bool = False,
    repair_notes: list[str] | None = None,
) -> None:
    raw_path: Path | None = None
    parsed_path: Path | None = None
    if attempts_dir:
        attempts_dir.mkdir(parents=True, exist_ok=True)
        raw_path = attempts_dir / f"attempt-{attempt}.raw.txt"
        raw_path.write_text(raw_text, encoding="utf-8")
        if parsed is not None:
            parsed_path = attempts_dir / f"attempt-{attempt}.parsed.json"
            parsed_path.write_text(
                json.dumps(parsed, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
    audit["attempts"].append(
        {
            "attempt": attempt,
            "raw_response_path": str(raw_path.relative_to(attempts_dir.parent))
            if raw_path and attempts_dir
            else None,
            "parsed_response_path": str(parsed_path.relative_to(attempts_dir.parent))
            if parsed_path and attempts_dir
            else None,
            "validation_errors": validation_errors,
            "repair_applied": repair_applied,
            "repair_notes": repair_notes or [],
            "failure_reason": failure_reason,
        }
    )


def _write_audit(
    audit_dir: Path | None,
    audit: dict[str, Any],
    artifacts: dict[str, Path],
) -> dict[str, Path]:
    if not audit_dir:
        return artifacts
    audit_dir.mkdir(parents=True, exist_ok=True)
    audit_path = audit_dir / "llm_audit.json"
    audit_path.write_text(json.dumps(audit, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    artifacts["llm_audit"] = audit_path
    return artifacts


def _redact(value: str) -> str:
    return _SECRET_PATTERN.sub(lambda match: f"{match.group(1)}=<redacted>", value)


def _is_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _classify(address: int, matched_range: PeripheralRange | None) -> str:
    if matched_range:
        return matched_range.type
    if 0x40000000 <= address <= 0x5FFFFFFF:
        return "MMIO"
    if 0xE0000000 <= address <= 0xE00FFFFF:
        return "CORE_SYSTEM"
    return "UNKNOWN"


def _default_action(peripheral: str) -> str:
    if peripheral in {"UART", "SPI", "I2C", "TIMER", "GPIO", "RCC"}:
        return "map_dummy_mmio"
    if peripheral == "CORE_SYSTEM":
        return "map_core_system_stub"
    return "log_access"


def _default_value(peripheral: str, matched_range: PeripheralRange | None) -> str:
    if matched_range:
        return matched_range.default_read
    if peripheral == "UART":
        return "0x00000020"
    if peripheral == "RCC":
        return "0x00000000"
    return "0x00000000"


def _confidence(
    peripheral: str, rag_hits: list[RagHit], matched_range: PeripheralRange | None
) -> float:
    if matched_range:
        return 0.88
    if peripheral == "MMIO":
        return 0.45
    if rag_hits:
        return 0.78
    return 0.62


def _evidence(
    address: str,
    peripheral: str,
    context: FirmwareContext,
    rag_hits: list[RagHit],
    matched_range: PeripheralRange | None,
) -> list[str]:
    evidence = [f"{address} matched {peripheral} address range"]
    if matched_range:
        evidence.append(f"range={matched_range.range_text} name={matched_range.name}")
        evidence.append(f"reference={matched_range.source}")
    if context.architecture_hint != "unknown":
        evidence.append(f"architecture_hint={context.architecture_hint}")
    if rag_hits and not matched_range:
        evidence.append(f"reference={rag_hits[0].source}")
    return evidence
