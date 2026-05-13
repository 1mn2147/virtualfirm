from __future__ import annotations

from pathlib import Path
import argparse
import json
import os
import sys

from .emulator import SUCCESS_CRITERIA, propose_feedback_patch
from .gui import serve_gui
from .reporting import write_report
from .services import (
    AnalysisOptions,
    EmulationOptions,
    InferenceOptions,
    LoopOptions,
    ServiceResult,
    analyze_firmware,
    create_sample_firmware,
    emulate_config,
    extract_firmware_context,
    infer_from_context,
    ingest_pdf_reference,
    run_feedback_iterations,
    run_pipeline,
)
from .validation import validate_run_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="firmware-mvp")
    parser.add_argument("--config", type=Path, help="JSON/YAML project config file")
    parser.add_argument("--json", action="store_true", help="print machine-readable command result")
    parser.add_argument(
        "--output-root",
        type=Path,
        help="prefix relative output paths so firmware logs/artifacts can live outside the repo",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="run the MVP firmware analysis pipeline")
    analyze.add_argument("firmware", type=Path)
    analyze.add_argument("--device", default="unknown")
    analyze.add_argument("--out", type=Path, default=Path("runs/latest"))
    analyze.add_argument("--references", type=Path, default=Path("references"))
    _add_analysis_backend_args(analyze)
    _add_inference_args(analyze)

    run = subparsers.add_parser("run", help="run extract, infer, and emulation")
    run.add_argument("firmware", type=Path)
    run.add_argument("--device", default="unknown")
    run.add_argument("--out", type=Path, default=Path("runs/latest"))
    run.add_argument("--references", type=Path, default=Path("references"))
    _add_analysis_backend_args(run)
    _add_inference_args(run)
    run.add_argument("--probe-address")
    run.add_argument("--access", choices=["read", "write"], default="read")
    run.add_argument("--pc", default="0x00000000")
    run.add_argument("--backend", choices=["stub", "qiling"], default="stub")
    run.add_argument("--rootfs")
    run.add_argument("--instruction-limit", type=int, default=100000)
    run.add_argument("--timeout-seconds", type=int, default=30)
    _add_success_criteria_args(run)

    extract = subparsers.add_parser("extract", help="extract firmware context only")
    extract.add_argument("firmware", type=Path)
    extract.add_argument("--out", type=Path, default=Path("runs/latest"))
    _add_analysis_backend_args(extract)

    infer = subparsers.add_parser("infer", help="infer peripherals from context.json")
    infer.add_argument("context_json", type=Path)
    infer.add_argument("--device", default="unknown")
    infer.add_argument("--out", type=Path, default=Path("runs/latest"))
    infer.add_argument("--references", type=Path, default=Path("references"))
    _add_inference_args(infer)

    emulate = subparsers.add_parser("emulate", help="run emulator wrapper backend")
    emulate.add_argument("emulator_config_json", type=Path)
    emulate.add_argument("--out", type=Path, default=Path("runs/latest"))
    emulate.add_argument("--backend", choices=["stub", "qiling"], default="stub")
    emulate.add_argument("--rootfs")
    emulate.add_argument("--probe-address")
    emulate.add_argument("--access", choices=["read", "write"], default="read")
    emulate.add_argument("--pc", default="0x00000000")
    emulate.add_argument("--instruction-limit", type=int, default=100000)
    emulate.add_argument("--timeout-seconds", type=int, default=30)
    _add_success_criteria_args(emulate)

    loop = subparsers.add_parser("loop", help="run feedback loop for unmapped MMIO crashes")
    loop.add_argument("emulator_config_json", type=Path)
    loop.add_argument("--out", type=Path, default=Path("runs/latest-loop"))
    loop.add_argument("--probe-address")
    loop.add_argument("--access", choices=["read", "write"], default="read")
    loop.add_argument("--pc", default="0x00000000")
    loop.add_argument("--backend", choices=["stub", "qiling"], default="stub")
    loop.add_argument("--rootfs")
    loop.add_argument("--max-iterations", type=int, default=3)
    loop.add_argument("--instruction-limit", type=int, default=100000)
    loop.add_argument("--timeout-seconds", type=int, default=30)

    report = subparsers.add_parser("report", help="generate report.md from JSON artifacts")
    report.add_argument("run_dir", type=Path)
    report.add_argument("--source-command")

    sample = subparsers.add_parser("init-sample", help="create a tiny demo firmware blob")
    sample.add_argument("--out", type=Path, default=Path("samples/demo_firmware.bin"))
    sample.add_argument(
        "--kind",
        choices=["raw", "elf", "high-entropy", "mmio-heavy"],
        default="raw",
        help="sample fixture kind",
    )

    feedback = subparsers.add_parser("feedback", help="propose a config patch from an MMIO crash")
    feedback.add_argument("address")
    feedback.add_argument("--access", choices=["read", "write"], default="read")

    validate = subparsers.add_parser("validate", help="validate JSON artifacts in a run directory")
    validate.add_argument("run_dir", type=Path)

    ingest_pdf = subparsers.add_parser("ingest-pdf", help="convert a PDF datasheet into RAG text")
    ingest_pdf.add_argument("pdf", type=Path)
    ingest_pdf.add_argument("--out", type=Path, default=Path("references/ingested"))
    ingest_pdf.add_argument("--device", default="unknown")
    ingest_pdf.add_argument("--pdftotext", type=Path, help="path to poppler pdftotext executable")

    gui = subparsers.add_parser("gui", help="start the stdlib web GUI")
    gui.add_argument("--host", default="127.0.0.1")
    gui.add_argument("--port", type=int, default=8765)

    args = parser.parse_args(_argv_with_config_defaults(argv))
    _apply_output_root(args)
    if args.command == "analyze":
        return _analyze(
            args.firmware,
            args.device,
            args.out,
            args.references,
            args.analysis_backend,
            args.ghidra_headless,
            args.ida_headless,
            args.ghidra_project_dir,
            args.ghidra_processor,
            args.extract_embedded,
            args.ghidra_target,
            args.ghidra_target_pattern,
            _inference_options(args),
            args.json,
        )
    if args.command == "run":
        return _run(
            args.firmware,
            args.device,
            args.out,
            args.references,
            args.analysis_backend,
            args.ghidra_headless,
            args.ida_headless,
            args.ghidra_project_dir,
            args.ghidra_processor,
            args.extract_embedded,
            args.ghidra_target,
            args.ghidra_target_pattern,
            args.probe_address,
            args.access,
            args.pc,
            args.backend,
            args.rootfs,
            args.instruction_limit,
            args.timeout_seconds,
            tuple(args.success_criterion or ()),
            args.success_uart_contains,
            _inference_options(args),
            args.json,
        )
    if args.command == "extract":
        return _extract(
            args.firmware,
            args.out,
            args.analysis_backend,
            args.ghidra_headless,
            args.ida_headless,
            args.ghidra_project_dir,
            args.ghidra_processor,
            args.extract_embedded,
            args.ghidra_target,
            args.ghidra_target_pattern,
            args.json,
        )
    if args.command == "infer":
        return _infer(
            args.context_json,
            args.device,
            args.out,
            args.references,
            _inference_options(args),
            args.json,
        )
    if args.command == "emulate":
        return _emulate(
            args.emulator_config_json,
            args.out,
            args.probe_address,
            args.access,
            args.pc,
            args.instruction_limit,
            args.timeout_seconds,
            args.backend,
            args.rootfs,
            tuple(args.success_criterion or ()),
            args.success_uart_contains,
            args.json,
        )
    if args.command == "loop":
        return _loop(
            args.emulator_config_json,
            args.out,
            args.probe_address,
            args.access,
            args.pc,
            args.max_iterations,
            args.instruction_limit,
            args.timeout_seconds,
            args.backend,
            args.rootfs,
            args.json,
        )
    if args.command == "report":
        path = write_report(args.run_dir, args.source_command)
        if args.json:
            _print_command_json(0, artifacts={"report": path})
        else:
            print(f"wrote {path}")
        return 0
    if args.command == "init-sample":
        return _init_sample(args.out, args.kind, args.json)
    if args.command == "feedback":
        payload = propose_feedback_patch(args.address, args.access)
        if args.json:
            _print_command_json(0, payload=payload)
        else:
            print(json.dumps(payload, indent=2))
        return 0
    if args.command == "validate":
        errors = validate_run_dir(args.run_dir)
        exit_code = 1 if errors else 0
        if args.json:
            _print_command_json(exit_code, errors=errors)
            return exit_code
        if errors:
            for error in errors:
                print(f"error: {error}")
            return 1
        print(f"validated {args.run_dir}")
        return 0
    if args.command == "ingest-pdf":
        result = ingest_pdf_reference(args.pdf, args.out, args.device, args.pdftotext)
        if args.json:
            _print_result_json(result)
        else:
            _print_errors(result)
            _print_artifacts(result, "text", "markdown")
        return result.exit_code
    if args.command == "gui":
        serve_gui(args.host, args.port)
        return 0
    return 2


def _argv_with_config_defaults(argv: list[str] | None) -> list[str] | None:
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    raw_argv = _normalize_global_json_flag(raw_argv)
    config_path = _config_path_from_argv(raw_argv)
    if not config_path:
        return raw_argv
    config = _load_project_config(config_path)
    command = _command_from_argv(raw_argv)
    if not command:
        return raw_argv
    defaults = _config_defaults_for_command(config, command)
    if not defaults:
        return raw_argv
    return _inject_default_args(raw_argv, defaults)


def _normalize_global_json_flag(argv: list[str]) -> list[str]:
    if "--json" not in argv:
        return argv
    without_json = [item for item in argv if item != "--json"]
    return ["--json", *without_json]


def _config_path_from_argv(argv: list[str]) -> Path | None:
    for index, item in enumerate(argv):
        if item == "--config" and index + 1 < len(argv):
            return Path(argv[index + 1])
        if item.startswith("--config="):
            return Path(item.split("=", 1)[1])
    return None


def _command_from_argv(argv: list[str]) -> str | None:
    skip_next = False
    for item in argv:
        if skip_next:
            skip_next = False
            continue
        if item in _GLOBAL_OPTIONS_WITH_VALUES:
            skip_next = True
            continue
        if _is_global_option_with_inline_value(item):
            continue
        if not item.startswith("-"):
            return item
    return None


def _load_project_config(path: Path) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = _parse_simple_yaml(text)
    if not isinstance(payload, dict):
        raise SystemExit(f"error: config must be an object: {path}")
    return payload


def _parse_simple_yaml(text: str) -> dict[str, object]:
    result: dict[str, object] = {}
    current_section: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if not line.startswith(" ") and line.endswith(":"):
            current_section = line[:-1].strip().replace("-", "_")
            result[current_section] = {}
            continue
        if ":" not in line:
            continue
        key, raw_value = line.split(":", 1)
        key = key.strip().replace("-", "_")
        value = _parse_config_scalar(raw_value.strip())
        if raw_line.startswith(" ") and current_section:
            section = result.setdefault(current_section, {})
            if isinstance(section, dict):
                section[key] = value
        else:
            result[key] = value
            current_section = None
    return result


def _parse_config_scalar(value: str) -> object:
    if value in {"true", "True"}:
        return True
    if value in {"false", "False"}:
        return False
    if value in {"null", "None", "~"}:
        return None
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    try:
        return int(value)
    except ValueError:
        return value


def _config_defaults_for_command(config: dict[str, object], command: str) -> dict[str, object]:
    defaults = {}
    for section_name in ("defaults", command.replace("-", "_")):
        section = config.get(section_name)
        if isinstance(section, dict):
            defaults.update(section)
    return defaults


def _inject_default_args(argv: list[str], defaults: dict[str, object]) -> list[str]:
    present = _present_options(argv)
    injected: list[str] = []
    for key, value in defaults.items():
        option = "--" + str(key).replace("_", "-")
        if option in present or value is None:
            continue
        if isinstance(value, bool):
            if value:
                injected.append(option)
            continue
        injected.extend([option, str(value)])
    if not injected:
        return argv
    for index, item in enumerate(argv):
        if item == "--config":
            command_index = _command_index(argv)
            if command_index is not None:
                return [*argv[: command_index + 1], *injected, *argv[command_index + 1 :]]
            return [*argv[: index + 2], *injected, *argv[index + 2 :]]
        if item.startswith("--config="):
            command_index = _command_index(argv)
            if command_index is not None:
                return [*argv[: command_index + 1], *injected, *argv[command_index + 1 :]]
            return [*argv[: index + 1], *injected, *argv[index + 1 :]]
    return [*injected, *argv]


def _present_options(argv: list[str]) -> set[str]:
    return {item.split("=", 1)[0] for item in argv if item.startswith("--")}


def _command_index(argv: list[str]) -> int | None:
    skip_next = False
    for index, item in enumerate(argv):
        if skip_next:
            skip_next = False
            continue
        if item in _GLOBAL_OPTIONS_WITH_VALUES:
            skip_next = True
            continue
        if _is_global_option_with_inline_value(item):
            continue
        if not item.startswith("-"):
            return index
    return None


_GLOBAL_OPTIONS_WITH_VALUES = {"--config", "--output-root"}


def _is_global_option_with_inline_value(item: str) -> bool:
    return any(item.startswith(option + "=") for option in _GLOBAL_OPTIONS_WITH_VALUES)


def _apply_output_root(args: argparse.Namespace) -> None:
    output_root = args.output_root or os.getenv("FIRMWARE_MVP_OUTPUT_ROOT")
    if not output_root or not hasattr(args, "out"):
        return
    out = args.out
    if isinstance(out, Path) and not out.is_absolute():
        args.out = Path(output_root) / out


def _add_analysis_backend_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--analysis-backend",
        choices=["heuristic", "ghidra", "ida"],
        default="heuristic",
        help="context extraction backend",
    )
    parser.add_argument("--ghidra-headless", type=Path, help="path to Ghidra analyzeHeadless")
    parser.add_argument("--ida-headless", type=Path, help="path to IDA headless executable (idat64)")
    parser.add_argument("--ghidra-project-dir", type=Path, help="directory for Ghidra projects")
    parser.add_argument("--ghidra-processor", help="Ghidra processor id, e.g. ARM:LE:32:Cortex")
    parser.add_argument(
        "--extract-embedded",
        action="store_true",
        help="extract recognized embedded filesystems and record executable analysis targets",
    )
    parser.add_argument(
        "--ghidra-target",
        help="embedded target path/name to analyze with Ghidra; default is auto",
    )
    parser.add_argument(
        "--ghidra-target-pattern",
        help="glob pattern for embedded Ghidra target, e.g. '*firmware*|*.cgi'",
    )


def _add_inference_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--llm",
        choices=["deterministic", "mock", "openai", "local"],
        default="deterministic",
        help="inference provider; deterministic is offline default",
    )
    parser.add_argument(
        "--llm-fallback",
        choices=["none", "deterministic"],
        default="none",
        help="explicit fallback after a selected LLM provider fails",
    )
    parser.add_argument("--llm-retries", type=int, default=1, help="bounded provider retries")
    parser.add_argument("--llm-max-prompt-chars", type=int, default=6000)
    parser.add_argument("--llm-timeout", type=int, default=30)
    parser.add_argument("--llm-max-raw-response-chars", type=int, default=20000)
    parser.add_argument(
        "--mock-response",
        choices=["valid", "invalid-json", "missing-field", "low-confidence", "provider-error"],
        default="valid",
        help="mock provider fixture case",
    )
    parser.add_argument("--mock-response-path", type=Path, help="raw mock provider response file")


def _add_success_criteria_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--success-criterion",
        action="append",
        choices=sorted(SUCCESS_CRITERIA),
        help=(
            "success gate for emulation exit code; repeat for multiple gates "
            "(boot-reached, uart-output, no-crash-for-instructions)"
        ),
    )
    parser.add_argument(
        "--success-uart-contains",
        help="substring required by --success-criterion uart-output",
    )


def _inference_options(args: argparse.Namespace) -> InferenceOptions:
    return InferenceOptions(
        provider=args.llm,
        fallback=args.llm_fallback,
        max_retries=args.llm_retries,
        max_prompt_chars=args.llm_max_prompt_chars,
        mock_response=args.mock_response,
        mock_response_path=args.mock_response_path,
        timeout_seconds=args.llm_timeout,
        max_raw_response_chars=args.llm_max_raw_response_chars,
    )


def _analyze(
    firmware: Path,
    device: str,
    out: Path,
    references: Path,
    analysis_backend: str = "heuristic",
    ghidra_headless: Path | None = None,
    ida_headless: Path | None = None,
    ghidra_project_dir: Path | None = None,
    ghidra_processor: str | None = None,
    extract_embedded: bool = False,
    ghidra_target: str | None = None,
    ghidra_target_pattern: str | None = None,
    inference_options: InferenceOptions | None = None,
    json_output: bool = False,
) -> int:
    result = analyze_firmware(
        firmware,
        device,
        out,
        references,
        AnalysisOptions(
            backend=analysis_backend,
            ghidra_headless=ghidra_headless,
            ida_headless=ida_headless,
            ghidra_project_dir=ghidra_project_dir,
            ghidra_processor=ghidra_processor,
            extract_embedded=extract_embedded,
            ghidra_target=ghidra_target,
            ghidra_target_pattern=ghidra_target_pattern,
        ),
        inference_options,
    )
    if json_output:
        _print_result_json(result)
    else:
        _print_errors(result)
        _print_artifacts(result, "context", "inference", "emulator_config", "llm_audit", "report")
    return result.exit_code


def _run(
    firmware: Path,
    device: str,
    out: Path,
    references: Path,
    analysis_backend: str,
    ghidra_headless: Path | None,
    ida_headless: Path | None,
    ghidra_project_dir: Path | None,
    ghidra_processor: str | None,
    extract_embedded: bool,
    ghidra_target: str | None,
    ghidra_target_pattern: str | None,
    probe_address: str | None,
    access: str,
    pc: str,
    backend: str,
    rootfs: str | None,
    instruction_limit: int,
    timeout_seconds: int,
    success_criteria: tuple[str, ...],
    success_uart_contains: str | None,
    inference_options: InferenceOptions | None,
    json_output: bool = False,
) -> int:
    result = run_pipeline(
        firmware,
        device,
        out,
        references,
        AnalysisOptions(
            backend=analysis_backend,
            ghidra_headless=ghidra_headless,
            ida_headless=ida_headless,
            ghidra_project_dir=ghidra_project_dir,
            ghidra_processor=ghidra_processor,
            extract_embedded=extract_embedded,
            ghidra_target=ghidra_target,
            ghidra_target_pattern=ghidra_target_pattern,
        ),
        EmulationOptions(
            backend=backend,
            rootfs=rootfs,
            probe_address=probe_address,
            access=access,
            pc=pc,
            instruction_limit=instruction_limit,
            timeout_seconds=timeout_seconds,
            success_criteria=success_criteria,
            success_uart_contains=success_uart_contains,
        ),
        inference_options,
    )
    if json_output:
        _print_result_json(result)
    else:
        _print_errors(result)
        _print_artifacts(
            result,
            "context",
            "inference",
            "emulator_config",
            "llm_audit",
            "emulation_result",
            "emulation_log",
            "report",
        )
    return result.exit_code


def _extract(
    firmware: Path,
    out: Path,
    analysis_backend: str = "heuristic",
    ghidra_headless: Path | None = None,
    ida_headless: Path | None = None,
    ghidra_project_dir: Path | None = None,
    ghidra_processor: str | None = None,
    extract_embedded: bool = False,
    ghidra_target: str | None = None,
    ghidra_target_pattern: str | None = None,
    json_output: bool = False,
) -> int:
    result = extract_firmware_context(
        firmware,
        out,
        AnalysisOptions(
            backend=analysis_backend,
            ghidra_headless=ghidra_headless,
            ida_headless=ida_headless,
            ghidra_project_dir=ghidra_project_dir,
            ghidra_processor=ghidra_processor,
            extract_embedded=extract_embedded,
            ghidra_target=ghidra_target,
            ghidra_target_pattern=ghidra_target_pattern,
        ),
    )
    if json_output:
        _print_result_json(result)
    else:
        _print_errors(result)
        _print_artifacts(result, "context")
    return result.exit_code


def _infer(
    context_json: Path,
    device: str,
    out: Path,
    references: Path,
    inference_options: InferenceOptions | None = None,
    json_output: bool = False,
) -> int:
    result = infer_from_context(context_json, device, out, references, inference_options)
    if json_output:
        _print_result_json(result)
    else:
        _print_errors(result)
        _print_artifacts(result, "context", "inference", "emulator_config", "llm_audit", "report")
    return result.exit_code


def _emulate(
    emulator_config_json: Path,
    out: Path,
    probe_address: str | None,
    access: str,
    pc: str,
    instruction_limit: int,
    timeout_seconds: int,
    backend: str,
    rootfs: str | None,
    success_criteria: tuple[str, ...],
    success_uart_contains: str | None,
    json_output: bool = False,
) -> int:
    result = emulate_config(
        emulator_config_json,
        out,
        EmulationOptions(
            backend=backend,
            rootfs=rootfs,
            probe_address=probe_address,
            access=access,
            pc=pc,
            instruction_limit=instruction_limit,
            timeout_seconds=timeout_seconds,
            success_criteria=success_criteria,
            success_uart_contains=success_uart_contains,
        ),
    )
    if json_output:
        _print_result_json(result)
    else:
        _print_errors(result)
        _print_artifacts(result, "emulation_result", "emulation_log", "report")
    return result.exit_code


def _loop(
    emulator_config_json: Path,
    out: Path,
    probe_address: str | None,
    access: str,
    pc: str,
    max_iterations: int,
    instruction_limit: int,
    timeout_seconds: int,
    backend: str,
    rootfs: str | None,
    json_output: bool = False,
) -> int:
    result = run_feedback_iterations(
        emulator_config_json,
        out,
        LoopOptions(
            backend=backend,
            rootfs=rootfs,
            probe_address=probe_address,
            access=access,
            pc=pc,
            max_iterations=max_iterations,
            instruction_limit=instruction_limit,
            timeout_seconds=timeout_seconds,
        ),
    )
    if json_output:
        _print_result_json(result)
    else:
        _print_errors(result)
        _print_artifacts(result, "loop_summary", "emulator_config_loop", "report")
    return result.exit_code


def _init_sample(path: Path, kind: str, json_output: bool = False) -> int:
    result = create_sample_firmware(path, kind)
    if json_output:
        _print_result_json(result)
    else:
        _print_errors(result)
        if "sample" in result.artifacts:
            print(f"created {result.artifacts['sample']}")
    return result.exit_code


def _print_errors(result: ServiceResult) -> None:
    for error in result.errors:
        print(f"error: {error}")


def _print_artifacts(result: ServiceResult, *keys: str) -> None:
    for key in keys:
        path = result.artifacts.get(key)
        if path:
            print(f"wrote {path}")


def _print_result_json(result: ServiceResult) -> None:
    _print_command_json(
        result.exit_code,
        artifacts=result.artifacts,
        errors=result.errors,
    )


def _print_command_json(
    exit_code: int,
    artifacts: dict[str, Path] | None = None,
    errors: list[str] | None = None,
    payload: object | None = None,
) -> None:
    document: dict[str, object] = {
        "exit_code": exit_code,
        "artifacts": {key: str(value) for key, value in (artifacts or {}).items()},
        "errors": errors or [],
    }
    if payload is not None:
        document["payload"] = payload
    print(
        json.dumps(
            document,
            indent=2,
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
