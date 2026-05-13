from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import json

from .compat import normalize_artifact_payload
from .emulator import build_emulator_config, finalize_emulation_result, run_feedback_loop
from .emulator_backends import get_emulation_backend
from .extractor import extract_context
from .inference import InferenceOptions, run_inference
from .models import FirmwareContext, write_json
from .pdf_ingest import ingest_pdf_datasheet
from .rag import search_references
from .reference_db import load_memory_maps
from .reporting import write_report


@dataclass(frozen=True)
class AnalysisOptions:
    backend: str = "heuristic"
    ghidra_headless: Path | None = None
    ida_headless: Path | None = None
    ghidra_project_dir: Path | None = None
    ghidra_processor: str | None = None
    extract_embedded: bool = False
    ghidra_target: str | None = None
    ghidra_target_pattern: str | None = None


@dataclass(frozen=True)
class EmulationOptions:
    backend: str = "stub"
    rootfs: str | None = None
    probe_address: str | None = None
    access: str = "read"
    pc: str = "0x00000000"
    instruction_limit: int = 100000
    timeout_seconds: int = 30
    success_criteria: tuple[str, ...] = ()
    success_uart_contains: str | None = None


@dataclass(frozen=True)
class LoopOptions:
    backend: str = "stub"
    rootfs: str | None = None
    probe_address: str | None = None
    access: str = "read"
    pc: str = "0x00000000"
    max_iterations: int = 3
    instruction_limit: int = 100000
    timeout_seconds: int = 30


@dataclass(frozen=True)
class ServiceResult:
    exit_code: int
    artifacts: dict[str, Path] = field(default_factory=dict)
    payloads: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def analyze_firmware(
    firmware: Path,
    device: str,
    out: Path,
    references: Path,
    options: AnalysisOptions | None = None,
    inference_options: InferenceOptions | None = None,
) -> ServiceResult:
    if not firmware.exists():
        return _error(f"firmware not found: {firmware}")
    options = options or AnalysisOptions()
    out.mkdir(parents=True, exist_ok=True)

    context = _extract_context(firmware, out, options)
    rag_hits = search_references(context, device, references)
    memory_ranges = load_memory_maps(references, device)
    inference_run = run_inference(
        context,
        device,
        rag_hits,
        memory_ranges,
        inference_options,
        out,
        _load_feedback_artifacts(out),
    )
    if inference_run.result is None:
        artifacts = {"context": out / "context.json", **(inference_run.artifacts or {})}
        write_json(artifacts["context"], context)
        return ServiceResult(
            exit_code=1,
            artifacts=artifacts,
            errors=inference_run.errors or ["inference provider failed"],
        )
    inference = inference_run.result
    emulator_config = build_emulator_config(
        inference,
        context.path,
        context.entry_point,
        context.architecture_hint,
    )

    artifacts = {
        "context": out / "context.json",
        "inference": out / "inference.json",
        "emulator_config": out / "emulator_config.json",
        "report": out / "report.md",
        **(inference_run.artifacts or {}),
    }
    write_json(artifacts["context"], context)
    write_json(artifacts["inference"], inference)
    write_json(artifacts["emulator_config"], emulator_config)
    write_report(out)
    return ServiceResult(
        exit_code=0,
        artifacts=artifacts,
        payloads={
            "context": context,
            "inference": inference,
            "emulator_config": emulator_config,
        },
    )


def run_pipeline(
    firmware: Path,
    device: str,
    out: Path,
    references: Path,
    analysis_options: AnalysisOptions | None = None,
    emulation_options: EmulationOptions | None = None,
    inference_options: InferenceOptions | None = None,
) -> ServiceResult:
    analysis = analyze_firmware(firmware, device, out, references, analysis_options, inference_options)
    if analysis.exit_code != 0:
        return analysis
    emulation = emulate_config(out / "emulator_config.json", out, emulation_options)
    return _combine_results(analysis, emulation)


def extract_firmware_context(
    firmware: Path,
    out: Path,
    options: AnalysisOptions | None = None,
) -> ServiceResult:
    if not firmware.exists():
        return _error(f"firmware not found: {firmware}")
    options = options or AnalysisOptions()
    out.mkdir(parents=True, exist_ok=True)
    context = _extract_context(firmware, out, options)
    artifacts = {"context": out / "context.json"}
    write_json(artifacts["context"], context)
    return ServiceResult(exit_code=0, artifacts=artifacts, payloads={"context": context})


def infer_from_context(
    context_json: Path,
    device: str,
    out: Path,
    references: Path,
    inference_options: InferenceOptions | None = None,
) -> ServiceResult:
    if not context_json.exists():
        return _error(f"context not found: {context_json}")
    context = load_context(context_json)
    rag_hits = search_references(context, device, references)
    memory_ranges = load_memory_maps(references, device)
    out.mkdir(parents=True, exist_ok=True)
    inference_run = run_inference(
        context,
        device,
        rag_hits,
        memory_ranges,
        inference_options,
        out,
        _load_feedback_artifacts(context_json.parent, out),
    )
    if inference_run.result is None:
        context_artifact = out / "context.json"
        write_json(context_artifact, context)
        return ServiceResult(
            exit_code=1,
            artifacts={"context": context_artifact, **(inference_run.artifacts or {})},
            errors=inference_run.errors or ["inference provider failed"],
        )
    inference = inference_run.result
    emulator_config = build_emulator_config(
        inference,
        context.path,
        context.entry_point,
        context.architecture_hint,
    )

    artifacts = {
        "context": out / "context.json",
        "inference": out / "inference.json",
        "emulator_config": out / "emulator_config.json",
        "report": out / "report.md",
        **(inference_run.artifacts or {}),
    }
    write_json(artifacts["context"], context)
    write_json(artifacts["inference"], inference)
    write_json(artifacts["emulator_config"], emulator_config)
    write_report(out)
    return ServiceResult(
        exit_code=0,
        artifacts=artifacts,
        payloads={"inference": inference, "emulator_config": emulator_config},
    )


def emulate_config(
    emulator_config_json: Path,
    out: Path,
    options: EmulationOptions | None = None,
) -> ServiceResult:
    if not emulator_config_json.exists():
        return _error(f"emulator config not found: {emulator_config_json}")
    options = options or EmulationOptions()
    emulation_backend = get_emulation_backend(options.backend, options.rootfs)
    try:
        result = emulation_backend.run(
            emulator_config_json,
            options.probe_address,
            options.access,
            options.pc,
            options.instruction_limit,
            options.timeout_seconds,
        )
    except (RuntimeError, NotImplementedError) as exc:
        return _error(str(exc))
    result = finalize_emulation_result(
        result,
        options.success_criteria,
        options.success_uart_contains,
    )

    out.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "emulation_result": out / "emulation_result.json",
        "emulation_log": out / "emulation.log",
        "report": out / "report.md",
    }
    write_json(artifacts["emulation_result"], result)
    artifacts["emulation_log"].write_text(build_emulation_log(result), encoding="utf-8")
    write_report(out)
    exit_code = 1 if result["status"] == "crashed" or result.get("success") is False else 0
    return ServiceResult(exit_code=exit_code, artifacts=artifacts, payloads={"emulation": result})


def run_feedback_iterations(
    emulator_config_json: Path,
    out: Path,
    options: LoopOptions | None = None,
) -> ServiceResult:
    if not emulator_config_json.exists():
        return _error(f"emulator config not found: {emulator_config_json}")
    options = options or LoopOptions()
    emulation_backend = get_emulation_backend(options.backend, options.rootfs)
    try:
        summary = run_feedback_loop(
            emulator_config_json,
            out,
            options.probe_address,
            options.access,
            options.pc,
            options.max_iterations,
            options.instruction_limit,
            options.timeout_seconds,
            emulation_backend.run,
            emulation_backend.name,
        )
    except (RuntimeError, NotImplementedError) as exc:
        return _error(str(exc))

    artifacts = {
        "loop_summary": out / "loop_summary.json",
        "emulator_config_loop": out / "emulator_config.loop.json",
        "report": out / "report.md",
    }
    write_report(out)
    exit_code = 0 if summary["status"] == "completed" else 1
    return ServiceResult(exit_code=exit_code, artifacts=artifacts, payloads={"loop_summary": summary})


def create_sample_firmware(path: Path, kind: str = "raw") -> ServiceResult:
    path.parent.mkdir(parents=True, exist_ok=True)
    if kind == "raw":
        blob = _sample_raw_firmware()
    elif kind == "elf":
        blob = _sample_elf_firmware()
    elif kind == "high-entropy":
        blob = _sample_high_entropy_blob()
    elif kind == "mmio-heavy":
        blob = _sample_mmio_heavy_blob()
    else:
        return _error(f"unknown sample kind: {kind}")
    path.write_bytes(blob)
    return ServiceResult(exit_code=0, artifacts={"sample": path})


def ingest_pdf_reference(
    pdf: Path,
    out: Path,
    device: str = "unknown",
    pdftotext: Path | None = None,
) -> ServiceResult:
    result = ingest_pdf_datasheet(pdf, out, device=device, pdftotext=pdftotext)
    if result["status"] != "completed":
        return ServiceResult(exit_code=2, errors=[str(result.get("reason", "PDF ingestion failed"))])
    return ServiceResult(
        exit_code=0,
        artifacts={
            "text": Path(str(result["text"])),
            "markdown": Path(str(result["markdown"])),
        },
        payloads={"pdf_ingest": result},
    )


def _sample_raw_firmware() -> bytes:
    blob = bytearray()
    blob += (0x20001000).to_bytes(4, "little")
    blob += (0x08000101).to_bytes(4, "little")
    blob += b"STM32F1 demo firmware\x00USART init\x00RCC enable\x00"
    while len(blob) % 4:
        blob += b"\x00"
    for address in [0x40021018, 0x40010800, 0x40011000, 0x4001100C, 0xE000E010]:
        blob += address.to_bytes(4, "little")
    blob += bytes(range(64))
    return bytes(blob)


def _sample_elf_firmware() -> bytes:
    blob = bytearray(b"\x7fELF")
    blob += bytes([1, 1, 1, 0])  # 32-bit, little endian, current version, System V ABI.
    blob += b"\x00" * 8
    blob += b"ELF demo fixture\x00ARM Linux sample\x00"
    while len(blob) % 4:
        blob += b"\x00"
    blob += (0x40011000).to_bytes(4, "little")
    return bytes(blob)


def _sample_high_entropy_blob() -> bytes:
    return bytes(((index * 73 + 41) & 0xFF) for index in range(8192))


def _sample_mmio_heavy_blob() -> bytes:
    blob = bytearray(_sample_raw_firmware())
    for index in range(128):
        blob += (0x40000000 + index * 0x100).to_bytes(4, "little")
    return bytes(blob)


def load_context(path: Path) -> FirmwareContext:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return FirmwareContext(**payload)


def _load_feedback_artifacts(*dirs: Path) -> dict[str, Any]:
    artifacts: dict[str, Any] = {}
    for directory in dirs:
        for name in ("emulation_result", "loop_summary"):
            path = directory / f"{name}.json"
            if name in artifacts or not path.exists():
                continue
            try:
                artifacts[name] = normalize_artifact_payload(
                    name,
                    json.loads(path.read_text(encoding="utf-8")),
                )
            except json.JSONDecodeError:
                continue
    return artifacts


def build_emulation_log(result: dict[str, Any]) -> str:
    lines = [
        f"backend={result['backend']}",
        f"status={result['status']}",
        f"stop_reason={result['stop_reason']}",
        f"instruction_count={result['instruction_count']}",
        f"mapped_regions={result['mapped_regions']}",
        f"timeout_seconds={result.get('timeout_seconds')}",
        f"success={result.get('success')}",
        f"exit_condition={result.get('exit_condition', {}).get('type')}",
    ]
    for item in result.get("success_criteria", []):
        lines.append(
            f"success_criterion={item.get('criterion')} passed={item.get('passed')} "
            f"evidence={item.get('evidence')}"
        )
    for item in result.get("uart_output", []):
        lines.append(f"uart={item}")
    for item in result.get("semihosting", []):
        lines.append(f"semihosting={item}")
    if result.get("crash"):
        crash = result["crash"]
        lines.append(f"crash_pc={crash['pc']}")
        lines.append(f"crash_access={crash['access']}")
        lines.append(f"crash_address={crash['address']}")
    return "\n".join(lines) + "\n"


def _extract_context(firmware: Path, out: Path, options: AnalysisOptions) -> FirmwareContext:
    return extract_context(
        firmware,
        analysis_backend=options.backend,
        ghidra_headless=options.ghidra_headless,
        ida_headless=options.ida_headless,
        ghidra_project_dir=options.ghidra_project_dir or out / ".ghidra",
        ghidra_processor=options.ghidra_processor,
        extract_embedded=options.extract_embedded,
        embedded_extract_dir=out / "embedded",
        ghidra_target=options.ghidra_target,
        ghidra_target_pattern=options.ghidra_target_pattern,
    )


def _combine_results(first: ServiceResult, second: ServiceResult) -> ServiceResult:
    return ServiceResult(
        exit_code=second.exit_code,
        artifacts={**first.artifacts, **second.artifacts},
        payloads={**first.payloads, **second.payloads},
        errors=first.errors + second.errors,
    )


def _error(message: str, exit_code: int = 2) -> ServiceResult:
    return ServiceResult(exit_code=exit_code, errors=[message])
