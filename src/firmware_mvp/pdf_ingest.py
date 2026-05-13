from __future__ import annotations

from pathlib import Path
from typing import Any
import shutil
import subprocess


def ingest_pdf_datasheet(
    pdf: Path,
    out_dir: Path,
    *,
    device: str = "unknown",
    pdftotext: Path | None = None,
    timeout_seconds: int = 60,
) -> dict[str, Any]:
    executable = _resolve_pdftotext(pdftotext)
    if executable is None:
        return {
            "status": "skipped",
            "reason": "pdftotext not found",
            "hint": "install poppler-utils or pass --pdftotext /path/to/pdftotext",
        }
    if not pdf.exists():
        return {"status": "failed", "reason": f"PDF not found: {pdf}"}

    out_dir.mkdir(parents=True, exist_ok=True)
    text_path = out_dir / f"{pdf.stem}.txt"
    markdown_path = out_dir / f"{pdf.stem}.md"
    command = [executable, "-layout", str(pdf), str(text_path)]
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
            "reason": f"pdftotext timed out after {timeout_seconds}s",
            "command": command,
        }
    except OSError as exc:
        return {"status": "failed", "reason": str(exc), "command": command}

    if completed.returncode != 0:
        return {
            "status": "failed",
            "reason": "pdftotext exited with a non-zero status",
            "returncode": completed.returncode,
            "stdout": completed.stdout[:8000],
            "stderr": completed.stderr[:8000],
            "command": command,
        }
    if not text_path.exists():
        return {"status": "failed", "reason": "pdftotext did not write output", "command": command}

    text = text_path.read_text(encoding="utf-8", errors="ignore")
    markdown_path.write_text(_to_markdown(pdf, device, text), encoding="utf-8")
    return {
        "status": "completed",
        "pdf": str(pdf),
        "device": device,
        "text": str(text_path),
        "markdown": str(markdown_path),
        "bytes": len(text.encode("utf-8")),
        "command": command,
    }


def _resolve_pdftotext(pdftotext: Path | None) -> str | None:
    if pdftotext:
        return str(pdftotext) if pdftotext.exists() else None
    return shutil.which("pdftotext")


def _to_markdown(pdf: Path, device: str, text: str) -> str:
    cleaned_lines = [line.rstrip() for line in text.splitlines()]
    cleaned = "\n".join(cleaned_lines).strip()
    return (
        f"# Datasheet Ingest: {pdf.name}\n\n"
        f"- Source PDF: `{pdf}`\n"
        f"- Device: `{device}`\n"
        "- Ingested by: `firmware-mvp ingest-pdf`\n\n"
        "## Extracted Text\n\n"
        f"{cleaned}\n"
    )
