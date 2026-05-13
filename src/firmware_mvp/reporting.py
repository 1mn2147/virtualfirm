from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import json

from . import __version__
from .compat import normalize_artifact_payload


def write_report(run_dir: Path, command: str | None = None) -> Path:
    report = build_report(run_dir, command)
    path = run_dir / "report.md"
    path.write_text(report, encoding="utf-8")
    return path


def build_report(run_dir: Path, command: str | None = None) -> str:
    context = _read_optional_json(run_dir / "context.json", "context")
    inference = _read_optional_json(run_dir / "inference.json", "inference")
    emulator_config = _read_optional_json(run_dir / "emulator_config.json", "emulator_config")
    emulation_result = _read_optional_json(run_dir / "emulation_result.json", "emulation_result")
    loop_summary = _read_optional_json(run_dir / "loop_summary.json", "loop_summary")
    llm_audit = _read_optional_json(run_dir / "llm_audit.json")

    lines = [
        "# Firmware MVP Report",
        "",
        f"- Generated: `{datetime.now(timezone.utc).isoformat()}`",
        f"- Tool version: `{__version__}`",
        f"- Run directory: `{run_dir}`",
    ]
    if command:
        lines.append(f"- Command: `{command}`")

    if context:
        lines.extend(
            [
                f"- Firmware: `{context.get('path')}`",
                f"- Size: {context.get('size_bytes')} bytes",
                f"- SHA256: `{context.get('sha256')}`",
                f"- Input format: `{context.get('input_format', 'raw-binary')}`",
                f"- Loaded image: base=`{context.get('loaded_base_address')}` "
                f"size={context.get('loaded_size_bytes')}",
                f"- Architecture hint: `{context.get('architecture_hint')}`",
                f"- Entropy: {context.get('entropy')}",
                f"- Entry point: `{context.get('entry_point')}`",
                f"- MMIO candidates: {len(context.get('mmio_addresses', []))}",
            ]
        )
        segments = context.get("firmware_segments", [])
        if segments:
            lines.append(f"- Firmware segments: {len(segments)}")
        embedded = context.get("embedded_files", [])
        if embedded:
            lines.append(f"- Embedded analysis targets: {len(embedded)}")
        warnings = context.get("analysis_warnings", [])
        if warnings:
            lines.append(f"- Analysis warnings: {len(warnings)}")
        entropy_windows = context.get("entropy_windows", [])
        if entropy_windows:
            high_entropy_count = sum(1 for item in entropy_windows if item.get("high_entropy"))
            lines.append(
                f"- Entropy windows: {len(entropy_windows)}"
                + (f" ({high_entropy_count} high)" if high_entropy_count else "")
            )
        suspicious_ranges = context.get("compressed_or_encrypted_ranges", [])
        if suspicious_ranges:
            lines.append(f"- Compressed/encrypted suspect ranges: {len(suspicious_ranges)}")
        string_ranges = context.get("string_ranges", [])
        if string_ranges:
            lines.append(f"- String ranges excluded from MMIO scan: {len(string_ranges)}")
        vuln_candidates = context.get("vulnerability_candidates", [])
        if vuln_candidates:
            lines.append(f"- Vulnerability candidates: {len(vuln_candidates)}")
        function_contexts = context.get("function_contexts", [])
        if function_contexts:
            lines.append(f"- Function contexts: {len(function_contexts)}")
            decompiled_contexts = [
                item
                for item in function_contexts
                if isinstance(item.get("decompiled"), str) and item.get("decompiled")
            ]
            if decompiled_contexts:
                lines.append(f"- Decompiled function contexts: {len(decompiled_contexts)}")
        ghidra = context.get("tool_observations", {}).get("ghidra", {})
        if isinstance(ghidra, dict) and ghidra.get("summary"):
            summary = ghidra["summary"]
            lines.append(
                "- Ghidra summary: "
                f"functions={summary.get('functions', 0)}, "
                f"strings={summary.get('strings', 0)}, "
                f"mmio_xrefs={summary.get('mmio_xrefs', 0)}"
            )
    if inference:
        lines.append(f"- Inferred peripherals: {len(inference.get('findings', []))}")
    if llm_audit:
        lines.append(f"- LLM provider requested: `{llm_audit.get('provider_requested')}`")
        lines.append(f"- LLM provider used: `{llm_audit.get('provider_used')}`")
        lines.append(f"- LLM validation status: `{llm_audit.get('validation_status')}`")
        if llm_audit.get("fallback_from"):
            lines.append(f"- LLM fallback from: `{llm_audit.get('fallback_from')}`")
        lines.append("- LLM audit artifact: `llm_audit.json`")
    if emulator_config:
        lines.append(f"- Emulator mappings: {len(emulator_config.get('mappings', []))}")
    if emulation_result:
        lines.append(f"- Emulation status: `{emulation_result.get('status')}`")
        lines.append(f"- Emulation stop reason: `{emulation_result.get('stop_reason')}`")
        lines.append(f"- Emulation success: `{emulation_result.get('success')}`")
    if loop_summary:
        lines.append(f"- Loop status: `{loop_summary.get('status')}`")
        lines.append(f"- Loop iterations: {len(loop_summary.get('iterations', []))}")

    lines.extend(["", "## Findings", ""])
    findings = inference.get("findings", []) if inference else []
    if findings:
        for finding in findings:
            name = finding.get("peripheral_name") or finding.get("type")
            lines.append(
                f"- `{finding.get('mmio_address')}` {name} type={finding.get('type')} "
                f"action={finding.get('action')} value={finding.get('value')} "
                f"confidence={finding.get('confidence')}"
            )
    else:
        lines.append("- No inference findings available.")

    if context:
        loaded_ranges = context.get("loaded_ranges", [])
        if loaded_ranges:
            lines.extend(["", "## Loaded Image Ranges", ""])
            for item in loaded_ranges[:20]:
                lines.append(
                    f"- `{item.get('start')}`-`{item.get('end')}` "
                    f"size={item.get('size_bytes')} source={item.get('source')}"
                )

        vector_table = context.get("vector_table")
        if isinstance(vector_table, dict):
            lines.extend(["", "## Cortex-M Vector Table", ""])
            lines.append(f"- Base: `{vector_table.get('base_address')}`")
            lines.append(f"- Initial SP: `{vector_table.get('initial_sp')}`")
            reset = vector_table.get("reset_handler", {})
            if isinstance(reset, dict):
                lines.append(f"- Reset Handler: `{reset.get('handler_address')}`")
            vectors = vector_table.get("vectors", [])
            if isinstance(vectors, list):
                for item in vectors[:16]:
                    if not isinstance(item, dict):
                        continue
                    if item.get("handler_address") or item.get("initial_sp"):
                        target = item.get("handler_address") or item.get("initial_sp")
                        lines.append(
                            f"- {item.get('index')}: {item.get('name')} "
                            f"`{target}` enabled={item.get('enabled')}"
                        )

        entropy_windows = context.get("entropy_windows", [])
        if entropy_windows:
            lines.extend(["", "## Entropy Windows", ""])
            for item in entropy_windows[:20]:
                marker = " high" if item.get("high_entropy") else ""
                lines.append(
                    f"- `{item.get('hex_offset')}` size={item.get('size_bytes')} "
                    f"entropy={item.get('entropy')}{marker}"
                )

        suspicious_ranges = context.get("compressed_or_encrypted_ranges", [])
        if suspicious_ranges:
            lines.extend(["", "## Compressed or Encrypted Suspect Ranges", ""])
            for item in suspicious_ranges[:30]:
                entropy = f" entropy={item.get('entropy')}" if item.get("entropy") is not None else ""
                lines.append(
                    f"- `{item.get('hex_offset')}`-`{item.get('hex_end_offset')}` "
                    f"kind={item.get('kind')} source={item.get('source')}{entropy}"
                )
                if item.get("reason"):
                    lines.append(f"  - reason: {item.get('reason')}")

        string_ranges = context.get("string_ranges", [])
        if string_ranges:
            lines.extend(["", "## String Ranges", ""])
            for item in string_ranges[:20]:
                lines.append(
                    f"- `{item.get('hex_offset')}`-`{item.get('hex_end_offset')}` "
                    f"size={item.get('size_bytes')} preview=`{item.get('preview')}`"
                )

        segments = context.get("firmware_segments", [])
        if segments:
            lines.extend(["", "## Firmware Segments", ""])
            for segment in segments[:20]:
                line = (
                    f"- `{segment.get('hex_offset')}` kind={segment.get('kind')} "
                    f"{segment.get('description')}"
                )
                if segment.get("size_bytes") is not None:
                    line += f" size={segment.get('size_bytes')}"
                lines.append(line)

        embedded = context.get("embedded_files", [])
        if embedded:
            lines.extend(["", "## Embedded Analysis Targets", ""])
            for item in embedded[:20]:
                lines.append(
                    f"- `{item.get('relative_path')}` kind={item.get('kind')} "
                    f"score={item.get('score')} size={item.get('size_bytes')} "
                    f"type={item.get('file_type')}"
                )
        selection = context.get("tool_observations", {}).get("ghidra_target_selection", {})
        if isinstance(selection, dict) and selection:
            lines.extend(["", "## Ghidra Target Selection", ""])
            lines.append(f"- Mode: `{selection.get('mode')}`")
            lines.append(f"- Target: `{selection.get('relative_path') or selection.get('path')}`")
            lines.append(f"- Score: {selection.get('score')}")
            if selection.get("matched_by"):
                lines.append(f"- Matched by: `{selection.get('matched_by')}`")
            if selection.get("reason"):
                lines.append(f"- Reason: {selection.get('reason')}")

        vuln_candidates = context.get("vulnerability_candidates", [])
        if vuln_candidates:
            lines.extend(["", "## Vulnerability Candidates", ""])
            for item in vuln_candidates[:30]:
                lines.append(
                    f"- risk={item.get('risk')} category={item.get('category')} "
                    f"function=`{item.get('function')}` symbol=`{item.get('symbol')}`"
                )
                evidence = item.get("evidence", [])
                if evidence:
                    lines.append(f"  - evidence: {evidence[0]}")

        function_contexts = context.get("function_contexts", [])
        if function_contexts:
            high_risk_contexts = [
                item
                for item in function_contexts
                if item.get("review_priority") in {"critical", "high"}
                or "web_input_to_file_write" in item.get("flow_signals", [])
            ]
            if high_risk_contexts:
                lines.extend(["", "## High-Risk Function Evidence", ""])
                for item in high_risk_contexts[:5]:
                    lines.append(
                        f"- `{item.get('name')}` entry=`{item.get('entry_point')}` "
                        f"priority={item.get('review_priority')} "
                        f"signals={','.join(item.get('flow_signals', []))}"
                    )
                    for snippet in item.get("evidence_snippets", [])[:6]:
                        lines.append(
                            f"  - {snippet.get('signal')} line {snippet.get('line')}: "
                            f"`{snippet.get('text')}`"
                        )

            lines.extend(["", "## Function Contexts", ""])
            for item in function_contexts[:10]:
                lines.append(
                    f"- `{item.get('name')}` entry=`{item.get('entry_point')}` "
                    f"priority={item.get('review_priority')} "
                    f"categories={','.join(item.get('candidate_categories', []))}"
                )
                flow_signals = item.get("flow_signals", [])
                if flow_signals:
                    lines.append(f"  - signals: {','.join(flow_signals)}")
                reasons = item.get("reasons", [])
                if reasons:
                    lines.append(f"  - reason: {reasons[0]}")
                snippets = item.get("evidence_snippets", [])
                if snippets:
                    first = snippets[0]
                    lines.append(
                        f"  - evidence snippet: {first.get('signal')} line "
                        f"{first.get('line')} `{first.get('text')}`"
                    )
                decompiled = item.get("decompiled")
                if isinstance(decompiled, str) and decompiled:
                    first_line = decompiled.strip().splitlines()[0] if decompiled.strip() else ""
                    if first_line:
                        lines.append(f"  - decompiled: `{first_line[:160]}`")

        warnings = context.get("analysis_warnings", [])
        if warnings:
            lines.extend(["", "## Analysis Warnings", ""])
            for warning in warnings:
                lines.append(f"- {warning}")

    if emulation_result:
        lines.extend(["", "## Emulation", ""])
        lines.append(f"- Backend: `{emulation_result.get('backend')}`")
        lines.append(f"- Status: `{emulation_result.get('status')}`")
        lines.append(f"- Stop reason: `{emulation_result.get('stop_reason')}`")
        lines.append(f"- Success: `{emulation_result.get('success')}`")
        exit_condition = emulation_result.get("exit_condition")
        if exit_condition:
            lines.append(f"- Exit condition: `{exit_condition.get('type')}`")
        criteria = emulation_result.get("success_criteria", [])
        if criteria:
            lines.append("- Success criteria:")
            for item in criteria:
                lines.append(
                    f"  - `{item.get('criterion')}` passed={item.get('passed')} "
                    f"evidence={item.get('evidence')}"
                )
        uart_output = emulation_result.get("uart_output", [])
        if uart_output:
            lines.append("- UART output:")
            for item in uart_output[:20]:
                lines.append(f"  - `{item}`")
        semihosting = emulation_result.get("semihosting", [])
        if semihosting:
            lines.append(f"- Semihosting events: {len(semihosting)}")
        crash = emulation_result.get("crash")
        if crash:
            lines.append(f"- Crash PC: `{crash.get('pc')}`")
            lines.append(f"- Crash access: `{crash.get('access')}`")
            lines.append(f"- Crash address: `{crash.get('address')}`")

    if loop_summary:
        lines.extend(["", "## Feedback Loop", ""])
        for item in loop_summary.get("iterations", []):
            lines.append(
                f"- Iteration {item.get('iteration')}: status={item.get('status')} "
                f"reason={item.get('stop_reason')} patch_applied={item.get('patch_applied')}"
            )
        lines.append(f"- Final config: `{loop_summary.get('final_config')}`")

    return "\n".join(lines) + "\n"


def _read_optional_json(path: Path, artifact: str | None = None) -> dict[str, Any] | None:
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if artifact:
        return normalize_artifact_payload(artifact, payload)
    return payload
