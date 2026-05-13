from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import os
import shutil
import subprocess


DEFAULT_IDA_TIMEOUT_SECONDS = 300


def run_ida_headless(
    firmware: Path,
    work_dir: Path,
    *,
    ida_headless: Path | None = None,
    timeout_seconds: int = DEFAULT_IDA_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    executable = _resolve_ida_headless(ida_headless)
    if executable is None:
        return {
            "status": "skipped",
            "reason": "IDA headless executable not found",
            "hint": "install IDA Pro/Free and pass --ida-headless /path/to/idat64",
        }

    work_dir.mkdir(parents=True, exist_ok=True)
    output_json = work_dir / f"{firmware.stem}.ida_context.json"
    script_path = Path(__file__).with_name("ida_export_context.py")
    command = [
        executable,
        "-A",
        f"-S{script_path} {output_json}",
        str(firmware),
    ]

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
            "reason": f"IDA headless timed out after {timeout_seconds}s",
            "command": list(command),
        }
    except OSError as exc:
        return {"status": "failed", "reason": str(exc), "command": list(command)}

    result: dict[str, Any] = {
        "status": "completed" if completed.returncode == 0 else "failed",
        "returncode": completed.returncode,
        "work_dir": str(work_dir),
        "output_json": str(output_json),
        "command": list(command),
        "stdout": completed.stdout.strip()[:8000],
        "stderr": completed.stderr.strip()[:8000],
    }
    if completed.returncode != 0:
        result["reason"] = "IDA headless exited with a non-zero status"
        return result
    if not output_json.exists():
        result["status"] = "failed"
        result["reason"] = "IDA script did not write its JSON output"
        return result

    try:
        analysis = json.loads(output_json.read_text(encoding="utf-8"))
        result["analysis"] = analysis
        if isinstance(analysis, dict):
            result["summary"] = _summarize_analysis(analysis)
    except json.JSONDecodeError as exc:
        result["status"] = "failed"
        result["reason"] = f"IDA JSON output is invalid: {exc}"
    return result


def _resolve_ida_headless(ida_headless: Path | None) -> str | None:
    if ida_headless:
        return str(ida_headless) if ida_headless.exists() else None
    env_path = os.environ.get("IDA_HEADLESS")
    if env_path and Path(env_path).exists():
        return env_path
    for name in ("idat64", "idat", "ida64", "ida"):
        if found := shutil.which(name):
            return found
    return None


def _summarize_analysis(analysis: dict[str, Any]) -> dict[str, int]:
    return {
        "entry_points": _count_list(analysis.get("entry_points")),
        "functions": _count_list(analysis.get("functions")),
        "call_graph_edges": _count_list(analysis.get("call_graph")),
        "strings": _count_list(analysis.get("strings")),
        "string_references": _count_list(analysis.get("string_references")),
        "mmio_references": _count_list(analysis.get("mmio_references")),
        "mmio_xrefs": _count_list(analysis.get("mmio_xrefs")),
    }


def _count_list(value: object) -> int:
    return len(value) if isinstance(value, list) else 0
