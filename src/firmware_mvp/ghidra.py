from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import os
import shutil
import subprocess


DEFAULT_GHIDRA_TIMEOUT_SECONDS = 300


def run_ghidra_headless(
    firmware: Path,
    project_dir: Path,
    *,
    analyze_headless: Path | None = None,
    processor: str | None = None,
    timeout_seconds: int = DEFAULT_GHIDRA_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    executable = _resolve_analyze_headless(analyze_headless)
    if executable is None:
        return {
            "status": "skipped",
            "reason": "analyzeHeadless not found",
            "hint": "install Ghidra or pass --ghidra-headless /path/to/analyzeHeadless",
        }

    project_dir.mkdir(parents=True, exist_ok=True)
    project_name = f"{_safe_project_name(firmware.stem)}_analysis"
    output_json = project_dir / f"{firmware.stem}.ghidra_context.json"
    script_path = Path(__file__).with_name("ghidra_export_context.py")

    command = [
        executable,
        str(project_dir),
        project_name,
        "-import",
        str(firmware),
        "-overwrite",
    ]
    if processor:
        command.extend(["-processor", processor])
    command.extend(
        [
            "-scriptPath",
            str(script_path.parent),
            "-postScript",
            script_path.name,
            str(output_json),
        ]
    )

    try:
        completed = subprocess.run(
            command,
            check=False,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "failed",
            "reason": f"analyzeHeadless timed out after {timeout_seconds}s",
            "command": _redact_command(command),
        }
    except OSError as exc:
        return {
            "status": "failed",
            "reason": str(exc),
            "command": _redact_command(command),
        }

    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()
    result: dict[str, Any] = {
        "status": "completed" if completed.returncode == 0 else "failed",
        "returncode": completed.returncode,
        "project_dir": str(project_dir),
        "project_name": project_name,
        "output_json": str(output_json),
        "command": _redact_command(command),
        "stdout": stdout[:8000],
        "stderr": stderr[:8000],
    }

    if completed.returncode != 0:
        result["reason"] = "analyzeHeadless exited with a non-zero status"
        return result
    if not output_json.exists():
        result["status"] = "failed"
        result["reason"] = "Ghidra script did not write its JSON output"
        return result

    try:
        analysis = json.loads(output_json.read_text(encoding="utf-8"))
        result["analysis"] = analysis
        if isinstance(analysis, dict):
            result["summary"] = _summarize_analysis(analysis)
    except json.JSONDecodeError as exc:
        result["status"] = "failed"
        result["reason"] = f"Ghidra JSON output is invalid: {exc}"
    return result


def _resolve_analyze_headless(analyze_headless: Path | None) -> str | None:
    if analyze_headless:
        return str(analyze_headless) if analyze_headless.exists() else None
    if found := shutil.which("analyzeHeadless"):
        return found
    ghidra_home = os.environ.get("GHIDRA_HOME")
    if ghidra_home:
        candidate = Path(ghidra_home) / "support" / "analyzeHeadless"
        if candidate.exists():
            return str(candidate)
    return None


def _safe_project_name(value: str) -> str:
    safe = "".join(char if char.isalnum() or char in {"_", "-"} else "_" for char in value)
    return safe or "firmware"


def _redact_command(command: list[str]) -> list[str]:
    return list(command)


def _summarize_analysis(analysis: dict[str, Any]) -> dict[str, int]:
    return {
        "entry_points": _count_list(analysis.get("entry_points")),
        "functions": _count_list(analysis.get("functions")),
        "call_graph_edges": _count_list(analysis.get("call_graph")),
        "strings": _count_list(analysis.get("strings")),
        "string_references": _count_list(analysis.get("string_references")),
        "mmio_references": _count_list(analysis.get("mmio_references")),
        "mmio_xrefs": _count_list(analysis.get("mmio_xrefs")),
        "reset_handler_candidates": _count_list(analysis.get("reset_handler_candidates")),
    }


def _count_list(value: object) -> int:
    return len(value) if isinstance(value, list) else 0
