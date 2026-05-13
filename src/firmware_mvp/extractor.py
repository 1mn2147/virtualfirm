from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Literal
import hashlib
import math
import re
import shutil
import subprocess

from .ghidra import run_ghidra_headless
from .ida import run_ida_headless
from .models import FirmwareContext


ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
BINWALK_ROW_RE = re.compile(r"^\s*(\d+)\s+0x([0-9A-Fa-f]+)\s+(.+?)\s*$")
BINWALK_SIZE_RE = re.compile(
    r"\b(?:total|image|compressed|uncompressed)\s+size:\s*(\d+)\s*(?:bytes)?\b",
    re.IGNORECASE,
)
NON_CODE_SEGMENT_KINDS = {"compressed", "filesystem", "metadata"}
EMBEDDED_INTEREST_KEYWORDS = (
    "firmware",
    "upgrade",
    "upload",
    "httpd",
    "lighttpd",
    "cgi",
    "service",
    "auth",
    "login",
    "nvram",
    "wireless",
    "wlan",
    "config",
)
CALL_RISK_RULES = {
    "system": ("command_execution", "critical", "executes shell command"),
    "popen": ("command_execution", "critical", "executes shell command and captures output"),
    "execl": ("process_execution", "high", "executes a program"),
    "execv": ("process_execution", "high", "executes a program"),
    "sprintf": ("memory_unsafe_format", "high", "unbounded format write"),
    "strcpy": ("memory_unsafe_copy", "high", "unbounded string copy"),
    "strcat": ("memory_unsafe_concat", "high", "unbounded string concatenation"),
    "gets": ("memory_unsafe_input", "critical", "unbounded input read"),
    "memcpy": ("memory_copy", "medium", "raw memory copy"),
    "snprintf": ("bounded_format", "low", "bounded format construction; review length source"),
    "strncpy": ("bounded_copy", "low", "bounded string copy; review termination"),
    "sf_strncpy": ("bounded_copy", "low", "project string copy helper; review termination"),
    "fopen": ("file_access", "medium", "opens filesystem path"),
    "fwrite": ("file_write", "medium", "writes attacker-influenced data to file"),
    "fread": ("file_read", "low", "reads filesystem or stdin data"),
    "remove": ("file_delete", "medium", "deletes filesystem path"),
    "unlink": ("file_delete", "medium", "deletes filesystem path"),
    "rename": ("file_move", "medium", "moves filesystem path"),
    "getenv": ("web_input_source", "medium", "reads CGI/environment input"),
    "atoi": ("numeric_parse", "medium", "parses unvalidated numeric text"),
    "malloc": ("allocation", "low", "allocates memory from computed size"),
}
WEB_INPUT_STRINGS = {
    "CONTENT_LENGTH",
    "CONTENT_TYPE",
    "QUERY_STRING",
    "REQUEST_METHOD",
    "HTTP_COOKIE",
    "HTTP_AUTHORIZATION",
    "multipart/form-data;",
    "boundary",
}
SECURITY_CONTROL_FUNCTIONS = {"httpcon_auth", "check_csrf_attack"}
FLOW_SIGNAL_KEYWORDS = {
    "web_input": (
        "getenv",
        "CONTENT_LENGTH",
        "CONTENT_TYPE",
        "QUERY_STRING",
        "REQUEST_METHOD",
        "HTTP_",
        "multipart/form-data",
        "boundary",
    ),
    "file_write": ("fopen", "fwrite", "remove", "unlink", "rename", "/tmp/"),
    "firmware_update": ("firmware", "upgrade", "/tmp/firmware"),
    "security_control": ("httpcon_auth", "check_csrf_attack"),
    "command_execution": ("system", "popen", "execl", "execv"),
    "memory_unsafe": ("sprintf", "strcpy", "strcat", "gets", "memcpy"),
}
CATEGORY_FLOW_SIGNALS = {
    "auth_sensitive_string": "security_control",
    "command_execution": "command_execution",
    "file_access": "file_write",
    "file_delete": "file_write",
    "file_move": "file_write",
    "file_write": "file_write",
    "firmware_update_string": "firmware_update",
    "memory_copy": "memory_unsafe",
    "memory_unsafe_concat": "memory_unsafe",
    "memory_unsafe_copy": "memory_unsafe",
    "memory_unsafe_format": "memory_unsafe",
    "memory_unsafe_input": "memory_unsafe",
    "process_execution": "command_execution",
    "security_control": "security_control",
    "temporary_file_path": "file_write",
    "web_input_source": "web_input",
    "web_input_string": "web_input",
    "web_upload_file_write_flow": "web_input_to_file_write",
}
CORTEX_M_VECTOR_NAMES = (
    "initial_sp",
    "reset_handler",
    "nmi_handler",
    "hardfault_handler",
    "memmanage_handler",
    "busfault_handler",
    "usagefault_handler",
    "reserved_7",
    "reserved_8",
    "reserved_9",
    "reserved_10",
    "svc_handler",
    "debugmon_handler",
    "reserved_13",
    "pendsv_handler",
    "systick_handler",
)


AnalysisBackend = Literal["heuristic", "ghidra", "ida"]
MAX_LOADED_IMAGE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class FirmwareImage:
    original_data: bytes
    data: bytes
    input_format: str
    load_address: int | None = None
    loaded_ranges: tuple[dict[str, object], ...] = ()
    entry_point: int | None = None
    warnings: tuple[str, ...] = ()


def extract_context(
    path: Path,
    *,
    analysis_backend: AnalysisBackend = "heuristic",
    ghidra_headless: Path | None = None,
    ida_headless: Path | None = None,
    ghidra_project_dir: Path | None = None,
    ghidra_processor: str | None = None,
    extract_embedded: bool = False,
    embedded_extract_dir: Path | None = None,
    ghidra_target: str | None = None,
    ghidra_target_pattern: str | None = None,
) -> FirmwareContext:
    image = _load_firmware_image(path)
    data = image.data
    observations: dict[str, object] = {"analysis_backend": analysis_backend}
    observations["input_loader"] = {
        "format": image.input_format,
        "original_size_bytes": len(image.original_data),
        "loaded_size_bytes": len(image.data),
        "load_address": _hex_or_none(image.load_address),
        "loaded_ranges": list(image.loaded_ranges),
        "warnings": list(image.warnings),
    }
    observations.update(_collect_basic_tool_observations(path))

    firmware_segments = (
        _parse_binwalk_segments(observations.get("binwalk"), file_size=len(data))
        if image.input_format in {"raw-binary", "elf"}
        else []
    )
    excluded_ranges = _non_code_ranges(firmware_segments, file_size=len(data))
    embedded_files: list[dict[str, object]] = []
    if extract_embedded:
        extraction = _extract_embedded_files(
            path,
            firmware_segments,
            embedded_extract_dir or path.parent / f"{path.name}.extracted",
        )
        embedded_files = extraction["files"]
        observations["embedded_extraction"] = extraction["observations"]
    strings = _extract_strings(data)
    string_ranges = _extract_string_ranges(data)
    mmio_excluded_ranges = sorted([*excluded_ranges, *_ranges_as_tuples(string_ranges)])
    observations["mmio_scan"] = {
        "excluded_non_code_ranges": len(excluded_ranges),
        "excluded_string_ranges": len(string_ranges),
    }
    mmio_addresses = _extract_mmio_addresses(data, excluded_ranges=mmio_excluded_ranges)
    arch = _guess_architecture(data, strings, observations)
    entropy = _entropy(data)
    entropy_windows = _entropy_windows(data)
    compressed_or_encrypted_ranges = _compressed_or_encrypted_ranges(
        entropy_windows,
        firmware_segments,
    )
    entry_point = _hex_or_none(image.entry_point) or _guess_entry_point(data)
    vector_table = _parse_cortex_m_vector_table(data, image.load_address) if arch == "arm-cortex-m" else None
    if vector_table and vector_table.get("reset_handler"):
        reset_handler = vector_table["reset_handler"]
        if isinstance(reset_handler, dict) and reset_handler.get("handler_address"):
            entry_point = str(reset_handler["handler_address"])
    vulnerability_candidates: list[dict[str, object]] = []
    function_contexts: list[dict[str, object]] = []
    analysis_warnings = _build_analysis_warnings(
        entropy=entropy,
        firmware_segments=firmware_segments,
        ghidra_result=None,
    )

    if analysis_backend == "ghidra":
        ghidra_target_selection = _select_ghidra_target_details(
            path,
            embedded_files,
            target=ghidra_target,
            pattern=ghidra_target_pattern,
        )
        ghidra_input = Path(str(ghidra_target_selection["path"]))
        observations["ghidra_target"] = str(ghidra_input)
        observations["ghidra_target_selection"] = ghidra_target_selection
        ghidra_result = run_ghidra_headless(
            ghidra_input,
            ghidra_project_dir or path.parent / ".ghidra",
            analyze_headless=ghidra_headless,
            processor=ghidra_processor,
        )
        observations["ghidra"] = ghidra_result
        if ghidra_result.get("status") == "completed":
            analysis = ghidra_result.get("analysis", {})
            if isinstance(analysis, dict):
                strings = _merge_strings(strings, _strings_from_ghidra(analysis))
                mmio_addresses = _merge_hex_addresses(
                    mmio_addresses,
                    _mmio_addresses_from_ghidra(analysis),
                )
                arch = _architecture_from_ghidra(analysis) or arch
                entry_point = _entry_point_from_ghidra(analysis) or entry_point
                vulnerability_candidates = _vulnerability_candidates_from_ghidra(analysis)
                function_contexts = _function_contexts_from_ghidra(
                    analysis,
                    vulnerability_candidates,
                )
        analysis_warnings = _build_analysis_warnings(
            entropy=entropy,
            firmware_segments=firmware_segments,
            ghidra_result=ghidra_result,
        )
    if analysis_backend == "ida":
        ida_result = run_ida_headless(
            path,
            ghidra_project_dir or path.parent / ".ida",
            ida_headless=ida_headless,
        )
        observations["ida"] = ida_result
        if ida_result.get("status") == "completed":
            analysis = ida_result.get("analysis", {})
            if isinstance(analysis, dict):
                strings = _merge_strings(strings, _strings_from_ghidra(analysis))
                mmio_addresses = _merge_hex_addresses(
                    mmio_addresses,
                    _mmio_addresses_from_ghidra(analysis),
                )
                arch = _architecture_from_ghidra(analysis) or arch
                entry_point = _entry_point_from_ghidra(analysis) or entry_point
                vulnerability_candidates = _vulnerability_candidates_from_ghidra(analysis)
                function_contexts = _function_contexts_from_ghidra(
                    analysis,
                    vulnerability_candidates,
                )
    analysis_warnings.extend(image.warnings)

    return FirmwareContext(
        path=str(path),
        size_bytes=len(image.original_data),
        sha256=hashlib.sha256(image.original_data).hexdigest(),
        entropy=round(entropy, 4),
        architecture_hint=arch,
        encrypted_or_compressed_likely=entropy >= 7.4,
        entry_point=entry_point,
        strings=strings[:200],
        mmio_addresses=mmio_addresses[:200],
        input_format=image.input_format,
        loaded_base_address=_hex_or_none(image.load_address),
        loaded_size_bytes=len(image.data),
        loaded_ranges=list(image.loaded_ranges),
        vector_table=vector_table,
        entropy_windows=entropy_windows,
        compressed_or_encrypted_ranges=compressed_or_encrypted_ranges,
        string_ranges=string_ranges[:200],
        firmware_segments=firmware_segments,
        embedded_files=embedded_files[:200],
        vulnerability_candidates=vulnerability_candidates[:100],
        function_contexts=function_contexts[:30],
        analysis_warnings=analysis_warnings,
        tool_observations=observations,
    )


def _load_firmware_image(path: Path) -> FirmwareImage:
    original = path.read_bytes()
    if original.startswith(b"\x7fELF"):
        return FirmwareImage(
            original_data=original,
            data=original,
            input_format="elf",
            load_address=0,
            loaded_ranges=(
                {
                    "start": "0x00000000",
                    "end": f"0x{len(original):08X}",
                    "size_bytes": len(original),
                    "source": "elf-file",
                },
            ),
        )

    text = _decode_record_text(original)
    if text is not None:
        stripped_lines = [line.strip() for line in text.splitlines() if line.strip()]
        if stripped_lines and all(line.startswith(":") for line in stripped_lines):
            try:
                return _load_intel_hex(original, stripped_lines)
            except ValueError as exc:
                return FirmwareImage(
                    original_data=original,
                    data=original,
                    input_format="intel-hex",
                    warnings=(f"Intel HEX loader failed; using raw text bytes: {exc}",),
                )
        if stripped_lines and all(line.startswith("S") for line in stripped_lines):
            try:
                return _load_s_record(original, stripped_lines)
            except ValueError as exc:
                return FirmwareImage(
                    original_data=original,
                    data=original,
                    input_format="motorola-s-record",
                    warnings=(f"Motorola S-record loader failed; using raw text bytes: {exc}",),
                )

    return FirmwareImage(
        original_data=original,
        data=original,
        input_format="raw-binary",
        load_address=0,
        loaded_ranges=(
            {
                "start": "0x00000000",
                "end": f"0x{len(original):08X}",
                "size_bytes": len(original),
                "source": "raw-file",
            },
        ),
    )


def _decode_record_text(data: bytes) -> str | None:
    if b"\x00" in data[:1024]:
        return None
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return None
    return text if text.strip() else None


def _load_intel_hex(original: bytes, lines: list[str]) -> FirmwareImage:
    chunks: list[tuple[int, bytes]] = []
    base = 0
    entry_point: int | None = None
    for line_number, line in enumerate(lines, start=1):
        if not line.startswith(":"):
            raise ValueError(f"line {line_number}: missing ':' prefix")
        raw = bytes.fromhex(line[1:])
        if len(raw) < 5:
            raise ValueError(f"line {line_number}: record too short")
        count = raw[0]
        address = int.from_bytes(raw[1:3], "big")
        record_type = raw[3]
        payload = raw[4:-1]
        if len(payload) != count:
            raise ValueError(f"line {line_number}: byte count mismatch")
        if sum(raw) & 0xFF:
            raise ValueError(f"line {line_number}: checksum mismatch")
        if record_type == 0x00:
            chunks.append((base + address, payload))
        elif record_type == 0x01:
            break
        elif record_type == 0x02:
            if count != 2:
                raise ValueError(f"line {line_number}: invalid segment address record")
            base = int.from_bytes(payload, "big") << 4
        elif record_type == 0x04:
            if count != 2:
                raise ValueError(f"line {line_number}: invalid linear address record")
            base = int.from_bytes(payload, "big") << 16
        elif record_type == 0x05:
            if count != 4:
                raise ValueError(f"line {line_number}: invalid start address record")
            entry_point = int.from_bytes(payload, "big")
    return _image_from_addressed_chunks(
        original,
        chunks,
        "intel-hex",
        entry_point=entry_point,
    )


def _load_s_record(original: bytes, lines: list[str]) -> FirmwareImage:
    chunks: list[tuple[int, bytes]] = []
    entry_point: int | None = None
    address_lengths = {"1": 2, "2": 3, "3": 4, "7": 4, "8": 3, "9": 2}
    data_types = {"1", "2", "3"}
    entry_types = {"7", "8", "9"}
    for line_number, line in enumerate(lines, start=1):
        if len(line) < 4 or not line.startswith("S"):
            raise ValueError(f"line {line_number}: invalid S-record")
        record_type = line[1]
        if record_type not in address_lengths and record_type not in {"0", "5", "6"}:
            continue
        raw = bytes.fromhex(line[2:])
        if not raw:
            raise ValueError(f"line {line_number}: record too short")
        count = raw[0]
        body = raw[1:]
        if len(body) != count:
            raise ValueError(f"line {line_number}: byte count mismatch")
        if (sum(raw) & 0xFF) != 0xFF:
            raise ValueError(f"line {line_number}: checksum mismatch")
        if record_type in data_types | entry_types:
            address_length = address_lengths[record_type]
            address = int.from_bytes(body[:address_length], "big")
            payload = body[address_length:-1]
            if record_type in data_types:
                chunks.append((address, payload))
            else:
                entry_point = address
    return _image_from_addressed_chunks(
        original,
        chunks,
        "motorola-s-record",
        entry_point=entry_point,
    )


def _image_from_addressed_chunks(
    original: bytes,
    chunks: list[tuple[int, bytes]],
    input_format: str,
    *,
    entry_point: int | None = None,
) -> FirmwareImage:
    if not chunks:
        raise ValueError("no data records")
    start = min(address for address, _ in chunks)
    end = max(address + len(payload) for address, payload in chunks)
    span = end - start
    if span > MAX_LOADED_IMAGE_BYTES:
        raise ValueError(f"loaded image span {span} exceeds {MAX_LOADED_IMAGE_BYTES}")
    image = bytearray(b"\xFF" * span)
    ranges = []
    for address, payload in sorted(chunks):
        offset = address - start
        image[offset : offset + len(payload)] = payload
        ranges.append(
            {
                "start": f"0x{address:08X}",
                "end": f"0x{address + len(payload):08X}",
                "size_bytes": len(payload),
                "source": input_format,
            }
        )
    return FirmwareImage(
        original_data=original,
        data=bytes(image),
        input_format=input_format,
        load_address=start,
        loaded_ranges=tuple(ranges),
        entry_point=entry_point,
    )


def _hex_or_none(value: int | None) -> str | None:
    return None if value is None else f"0x{value:08X}"


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _entropy_windows(data: bytes, *, window_size: int = 4096, limit: int = 256) -> list[dict[str, object]]:
    if not data:
        return []
    windows = []
    for index, offset in enumerate(range(0, len(data), window_size)):
        if index >= limit:
            windows.append(
                {
                    "offset": offset,
                    "hex_offset": f"0x{offset:X}",
                    "size_bytes": 0,
                    "entropy": None,
                    "truncated": True,
                }
            )
            break
        chunk = data[offset : offset + window_size]
        entropy = round(_entropy(chunk), 4)
        windows.append(
            {
                "offset": offset,
                "hex_offset": f"0x{offset:X}",
                "size_bytes": len(chunk),
                "entropy": entropy,
                "high_entropy": entropy >= 7.4,
            }
        )
    return windows


def _compressed_or_encrypted_ranges(
    entropy_windows: list[dict[str, object]],
    firmware_segments: list[dict[str, object]],
) -> list[dict[str, object]]:
    ranges: list[dict[str, object]] = []
    for segment in firmware_segments:
        kind = str(segment.get("kind") or "")
        if kind not in {"compressed", "filesystem"}:
            continue
        offset = segment.get("offset")
        end = segment.get("end_offset")
        if not isinstance(offset, int) or not isinstance(end, int):
            continue
        ranges.append(
            {
                "offset": offset,
                "hex_offset": f"0x{offset:X}",
                "end_offset": end,
                "hex_end_offset": f"0x{end:X}",
                "kind": kind,
                "reason": f"binwalk identified {kind} segment",
                "source": "binwalk",
            }
        )

    for window in entropy_windows:
        if not window.get("high_entropy"):
            continue
        offset = window.get("offset")
        size = window.get("size_bytes")
        if not isinstance(offset, int) or not isinstance(size, int):
            continue
        end = offset + size
        ranges.append(
            {
                "offset": offset,
                "hex_offset": f"0x{offset:X}",
                "end_offset": end,
                "hex_end_offset": f"0x{end:X}",
                "kind": "high-entropy",
                "entropy": window.get("entropy"),
                "reason": "window entropy >= 7.4 suggests compressed or encrypted content",
                "source": "entropy-window",
            }
        )
    return _dedupe_ranges(ranges)[:200]


def _dedupe_ranges(ranges: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[tuple[object, object, object, object]] = set()
    deduped = []
    for item in ranges:
        key = (item.get("offset"), item.get("end_offset"), item.get("kind"), item.get("source"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _extract_strings(data: bytes) -> list[str]:
    values = []
    for match in ASCII_RE.finditer(data):
        text = match.group().decode("ascii", errors="ignore").strip()
        if text:
            values.append(text)
    return sorted(set(values), key=lambda item: (len(item), item))


def _extract_string_ranges(data: bytes, *, limit: int = 500) -> list[dict[str, object]]:
    ranges = []
    for match in ASCII_RE.finditer(data):
        text = match.group().decode("ascii", errors="ignore").strip()
        if not text:
            continue
        start, end = match.span()
        ranges.append(
            {
                "offset": start,
                "hex_offset": f"0x{start:X}",
                "end_offset": end,
                "hex_end_offset": f"0x{end:X}",
                "size_bytes": end - start,
                "preview": text[:120],
            }
        )
        if len(ranges) >= limit:
            break
    return ranges


def _ranges_as_tuples(ranges: list[dict[str, object]]) -> list[tuple[int, int]]:
    values = []
    for item in ranges:
        start = item.get("offset")
        end = item.get("end_offset")
        if isinstance(start, int) and isinstance(end, int):
            values.append((start, end))
    return values


def _extract_mmio_addresses(
    data: bytes,
    *,
    excluded_ranges: list[tuple[int, int]] | None = None,
) -> list[str]:
    found: set[int] = set()
    ranges = sorted(excluded_ranges or [])
    range_index = 0
    for offset in range(0, max(0, len(data) - 3), 4):
        while range_index < len(ranges) and offset >= ranges[range_index][1]:
            range_index += 1
        if range_index < len(ranges):
            start, end = ranges[range_index]
            if start <= offset < end:
                continue
        chunk = data[offset : offset + 4]
        if sum(0x20 <= byte <= 0x7E for byte in chunk) >= 3:
            continue
        value = int.from_bytes(chunk, "little")
        if 0x40000000 <= value <= 0x5FFFFFFF or 0xE0000000 <= value <= 0xE00FFFFF:
            found.add(value)
    return [f"0x{value:08X}" for value in sorted(found)]


def _guess_architecture(
    data: bytes,
    strings: list[str],
    observations: dict[str, object] | None = None,
) -> str:
    tool_arch = _architecture_from_tools(observations or {})
    if tool_arch:
        return tool_arch

    text = " ".join(strings).lower()
    if "cortex" in text or "stm32" in text:
        return "arm-cortex-m"
    if "esp32" in text or "xtensa" in text:
        return "xtensa"
    if "risc-v" in text or "riscv" in text:
        return "riscv"
    if "mips" in text:
        return "mips"
    if "aarch64" in text or "arm-linux" in text or "gnueabihf" in text:
        return "arm-linux"
    if len(data) >= 8:
        initial_sp = int.from_bytes(data[0:4], "little")
        reset = int.from_bytes(data[4:8], "little")
        if 0x20000000 <= initial_sp <= 0x200FFFFF and reset & 1:
            return "arm-cortex-m"
    return "unknown"


def _architecture_from_tools(observations: dict[str, object]) -> str | None:
    tool_results = observations.get("tool_results")
    if not isinstance(tool_results, dict):
        return None

    outputs: list[str] = []
    for result in tool_results.values():
        if not isinstance(result, dict):
            continue
        output = result.get("output")
        if isinstance(output, str):
            outputs.append(output)
    text = "\n".join(outputs).lower()
    if not text:
        return None

    if "cortex-m" in text or "cortex m" in text or "stm32" in text:
        return "arm-cortex-m"
    if "xtensa" in text or "esp32" in text:
        return "xtensa"
    if "risc-v" in text or "riscv" in text:
        return "riscv"
    if "mips" in text:
        return "mips"
    if "aarch64" in text or "arm64" in text:
        return "arm-linux"
    if ("elf" in text and " arm" in text) or "machine: arm" in text:
        return "arm-linux"
    return None


def _guess_entry_point(data: bytes) -> str | None:
    if len(data) < 8:
        return None
    reset = int.from_bytes(data[4:8], "little")
    if reset:
        return f"0x{reset & ~1:08X}"
    return None


def _parse_cortex_m_vector_table(
    data: bytes,
    load_address: int | None = None,
    *,
    max_vectors: int = 64,
) -> dict[str, object] | None:
    if len(data) < 8:
        return None
    initial_sp = int.from_bytes(data[0:4], "little")
    reset = int.from_bytes(data[4:8], "little")
    if not (0x20000000 <= initial_sp <= 0x3FFFFFFF and reset & 1):
        return None

    base = load_address or 0
    vectors = []
    count = min(max_vectors, len(data) // 4)
    for index in range(count):
        raw_value = int.from_bytes(data[index * 4 : index * 4 + 4], "little")
        name = CORTEX_M_VECTOR_NAMES[index] if index < len(CORTEX_M_VECTOR_NAMES) else f"irq_{index - 16}"
        entry: dict[str, object] = {
            "index": index,
            "name": name,
            "table_address": f"0x{base + index * 4:08X}",
            "raw_value": f"0x{raw_value:08X}",
            "enabled": raw_value not in {0, 0xFFFFFFFF},
        }
        if index == 0:
            entry["initial_sp"] = f"0x{raw_value:08X}"
        elif raw_value not in {0, 0xFFFFFFFF}:
            entry["handler_address"] = f"0x{raw_value & ~1:08X}"
            entry["thumb_bit"] = bool(raw_value & 1)
        vectors.append(entry)

    return {
        "architecture": "arm-cortex-m",
        "base_address": f"0x{base:08X}",
        "initial_sp": f"0x{initial_sp:08X}",
        "reset_handler": vectors[1],
        "vector_count": len(vectors),
        "vectors": vectors,
    }


def _collect_basic_tool_observations(path: Path) -> dict[str, object]:
    tools: dict[str, object] = {}
    commands = {
        "file": ["file", str(path)],
        "readelf": ["readelf", "-h", str(path)],
        "objdump": ["objdump", "-f", str(path)],
        "xxd": ["xxd", "-g", "1", "-l", "256", str(path)],
        "binwalk": ["binwalk", str(path)],
    }
    for name, command in commands.items():
        executable = shutil.which(command[0])
        if not executable:
            tools[name] = {"status": "skipped", "reason": f"{command[0]} not found"}
            continue
        tools[name] = _run_tool([executable, *command[1:]])
    return {"tool_results": tools, "binwalk": _legacy_binwalk_observation(tools)}


def _legacy_binwalk_observation(tools: dict[str, object]) -> str:
    binwalk = tools.get("binwalk")
    if isinstance(binwalk, dict):
        if binwalk.get("status") == "skipped":
            return "binwalk not found; skipped"
        output = binwalk.get("output")
        if isinstance(output, str):
            return output
    return str(binwalk or "binwalk not found; skipped")


def _parse_binwalk_segments(output: object, *, file_size: int | None = None) -> list[dict[str, object]]:
    if not isinstance(output, str) or "binwalk not found" in output:
        return []

    segments: list[dict[str, object]] = []
    for line in output.splitlines():
        match = BINWALK_ROW_RE.match(line)
        if not match:
            continue
        description = " ".join(match.group(3).split())
        if not description or set(description) == {"-"} or description.upper() == "DESCRIPTION":
            continue

        offset = int(match.group(1))
        segment: dict[str, object] = {
            "offset": offset,
            "hex_offset": f"0x{offset:X}",
            "description": description,
            "kind": _classify_binwalk_segment(description),
        }
        size = _parse_binwalk_segment_size(description)
        if size is not None:
            segment["size_bytes"] = size
            end_offset = offset + size
            if file_size is not None:
                end_offset = min(end_offset, file_size)
            segment["end_offset"] = end_offset
        segments.append(segment)

    return sorted(segments, key=lambda item: int(item["offset"]))


def _classify_binwalk_segment(description: str) -> str:
    lower = description.lower()
    if any(term in lower for term in ("squashfs", "cramfs", "jffs2", "ubifs", "file system")):
        return "filesystem"
    if any(term in lower for term in ("lzma", "xz", "gzip", "zlib", "zip archive", "compressed")):
        return "compressed"
    if any(term in lower for term in ("device tree blob", "dtb", "certificate", "signature")):
        return "metadata"
    if any(term in lower for term in ("elf", "u-boot", "kernel", "linux kernel")):
        return "code"
    return "unknown"


def _parse_binwalk_segment_size(description: str) -> int | None:
    match = BINWALK_SIZE_RE.search(description)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _non_code_ranges(
    firmware_segments: list[dict[str, object]],
    *,
    file_size: int,
) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for index, segment in enumerate(firmware_segments):
        if segment.get("kind") not in NON_CODE_SEGMENT_KINDS:
            continue
        offset = int(segment["offset"])
        end = segment.get("end_offset")
        if isinstance(end, int):
            end_offset = end
        else:
            next_offset = firmware_segments[index + 1]["offset"] if index + 1 < len(firmware_segments) else file_size
            end_offset = int(next_offset)
        start = max(0, min(offset, file_size))
        stop = max(start, min(end_offset, file_size))
        if start < stop:
            ranges.append((start, stop))
    return ranges


def _build_analysis_warnings(
    *,
    entropy: float,
    firmware_segments: list[dict[str, object]],
    ghidra_result: dict[str, object] | None,
) -> list[str]:
    warnings: list[str] = []
    if any(segment.get("kind") in NON_CODE_SEGMENT_KINDS for segment in firmware_segments):
        warnings.append(
            "binwalk identified non-code container segments; heuristic MMIO scan skipped those ranges"
        )
    if entropy >= 7.4 and firmware_segments:
        warnings.append(
            "high entropy with binwalk segments usually indicates compressed/encrypted regions; raw MMIO candidates may be incomplete"
        )
    if isinstance(ghidra_result, dict) and ghidra_result.get("status") == "completed":
        summary = ghidra_result.get("summary")
        if isinstance(summary, dict) and not summary.get("functions"):
            warnings.append(
                "Ghidra completed but found no functions; analyze an extracted executable/kernel instead of the whole container if code recovery is required"
            )
    return warnings


def _extract_embedded_files(
    firmware: Path,
    firmware_segments: list[dict[str, object]],
    extraction_dir: Path,
) -> dict[str, object]:
    observations: list[dict[str, object]] = []
    files: list[dict[str, object]] = []
    unsquashfs = shutil.which("unsquashfs")

    extraction_dir.mkdir(parents=True, exist_ok=True)
    for segment in firmware_segments:
        description = str(segment.get("description", "")).lower()
        if segment.get("kind") != "filesystem" or "squashfs" not in description:
            continue

        offset = int(segment["offset"])
        out_dir = extraction_dir / f"{offset:X}_squashfs"
        if not unsquashfs:
            observations.append(
                {
                    "status": "skipped",
                    "reason": "unsquashfs not found",
                    "offset": segment.get("hex_offset"),
                }
            )
            continue

        command = [
            unsquashfs,
            "-q",
            "-no-progress",
            "-d",
            str(out_dir),
            "-o",
            str(offset),
            str(firmware),
        ]
        result = _run_tool(command, timeout_seconds=120)
        result["offset"] = segment.get("hex_offset")
        result["output_dir"] = str(out_dir)
        observations.append(result)
        if result.get("status") not in {"completed", "completed_with_error"} or not out_dir.exists():
            continue
        files.extend(_collect_embedded_file_candidates(out_dir, source_segment=segment))

    return {
        "observations": observations,
        "files": sorted(files, key=_embedded_file_sort_key)[:200],
    }


def _collect_embedded_file_candidates(
    root: Path,
    *,
    source_segment: dict[str, object],
) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue
        try:
            size = file_path.stat().st_size
        except OSError:
            continue
        if size <= 0:
            continue
        file_type = _file_type(file_path)
        kind = _classify_embedded_file(file_path, file_type)
        if kind is None:
            continue
        try:
            relative_path = str(file_path.relative_to(root))
        except ValueError:
            relative_path = file_path.name
        candidates.append(
            _embedded_file_candidate(
                path=file_path,
                relative_path=relative_path,
                size=size,
                kind=kind,
                file_type=file_type,
                source_segment=source_segment,
            )
        )
    return candidates


def _file_type(path: Path) -> str:
    executable = shutil.which("file")
    if not executable:
        return "unknown"
    result = _run_tool([executable, str(path)], timeout_seconds=5)
    output = result.get("output")
    if not isinstance(output, str):
        return "unknown"
    prefix = f"{path}: "
    return output.removeprefix(prefix)


def _classify_embedded_file(path: Path, file_type: str) -> str | None:
    lower_type = file_type.lower()
    lower_name = path.name.lower()
    if "elf" in lower_type:
        if "relocatable" in lower_type or lower_name.endswith(".ko"):
            return "kernel-module"
        if "shared object" in lower_type or ".so" in lower_name:
            return "shared-library"
        if "executable" in lower_type:
            return "executable"
        return "elf"
    if lower_name.endswith((".sh", ".cgi")) or "script" in lower_type:
        return "script"
    return None


def _embedded_file_sort_key(item: dict[str, object]) -> tuple[int, int, str]:
    score = int(item.get("score") or 0)
    kind_rank = {
        "executable": 0,
        "elf": 1,
        "shared-library": 2,
        "kernel-module": 3,
        "script": 4,
    }.get(str(item.get("kind")), 9)
    size = int(item.get("size_bytes", 0))
    return (-score, kind_rank, -size, str(item.get("relative_path", "")))


def _embedded_file_candidate(
    *,
    path: Path,
    relative_path: str,
    size: int,
    kind: str,
    file_type: str,
    source_segment: dict[str, object],
) -> dict[str, object]:
    item: dict[str, object] = {
        "path": str(path),
        "relative_path": relative_path,
        "size_bytes": size,
        "kind": kind,
        "file_type": file_type,
        "source_segment": source_segment.get("hex_offset"),
    }
    score, reasons = _score_embedded_file(item)
    item["score"] = score
    item["score_reasons"] = reasons
    return item


def _score_embedded_file(item: dict[str, object]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    kind = str(item.get("kind", ""))
    relative_path = str(item.get("relative_path", item.get("path", ""))).lower()
    name = Path(relative_path).name
    size = int(item.get("size_bytes") or 0)

    kind_scores = {
        "executable": 1000,
        "elf": 850,
        "shared-library": 400,
        "kernel-module": 250,
        "script": 150,
    }
    if kind in kind_scores:
        score += kind_scores[kind]
        reasons.append(f"kind:{kind}+{kind_scores[kind]}")

    if relative_path.startswith("home/httpd/cgi/") or "/cgi/" in relative_path:
        score += 800
        reasons.append("path:cgi+800")
    if name.endswith(".cgi") or "cgi" in name:
        score += 700
        reasons.append("name:cgi+700")
    if relative_path.startswith(("sbin/", "bin/", "usr/sbin/", "usr/bin/")):
        score += 100
        reasons.append("path:system-bin+100")

    for keyword in EMBEDDED_INTEREST_KEYWORDS:
        if keyword in relative_path:
            score += 300
            reasons.append(f"keyword:{keyword}+300")

    if "debug_info" in str(item.get("file_type", "")).lower():
        score += 100
        reasons.append("debug-info+100")

    size_bonus = min(size // 4096, 200)
    if size_bonus:
        score += size_bonus
        reasons.append(f"size+{size_bonus}")

    return score, reasons


def _select_ghidra_target(
    firmware: Path,
    embedded_files: list[dict[str, object]],
    *,
    target: str | None = None,
    pattern: str | None = None,
) -> Path:
    return Path(str(_select_ghidra_target_details(firmware, embedded_files, target=target, pattern=pattern)["path"]))


def _select_ghidra_target_details(
    firmware: Path,
    embedded_files: list[dict[str, object]],
    *,
    target: str | None = None,
    pattern: str | None = None,
) -> dict[str, object]:
    normalized_target = (target or "auto").strip()
    if normalized_target and normalized_target != "auto":
        matched = _find_embedded_target(embedded_files, normalized_target)
        if matched:
            return _target_selection("target", matched, matched_by=normalized_target)

        explicit = Path(normalized_target)
        if explicit.exists():
            return {
                "mode": "target",
                "path": str(explicit),
                "matched_by": normalized_target,
                "status": "selected",
            }

        fallback = _auto_ghidra_target(firmware, embedded_files)
        fallback["status"] = "fallback"
        fallback["reason"] = f"requested target not found: {normalized_target}"
        return fallback

    if pattern:
        matched = _find_embedded_pattern(embedded_files, pattern)
        if matched:
            return _target_selection("pattern", matched, matched_by=pattern)
        fallback = _auto_ghidra_target(firmware, embedded_files)
        fallback["status"] = "fallback"
        fallback["reason"] = f"requested pattern matched no embedded file: {pattern}"
        return fallback

    return _auto_ghidra_target(firmware, embedded_files)


def _auto_ghidra_target(firmware: Path, embedded_files: list[dict[str, object]]) -> dict[str, object]:
    for item in sorted(embedded_files, key=_embedded_file_sort_key):
        if item.get("kind") in {"executable", "elf", "shared-library", "kernel-module"}:
            path = Path(str(item.get("path")))
            if path.exists():
                return _target_selection("auto", item)
    return {"mode": "auto", "path": str(firmware), "status": "selected", "reason": "no embedded ELF target"}


def _target_selection(
    mode: str,
    item: dict[str, object],
    *,
    matched_by: str | None = None,
) -> dict[str, object]:
    selection = {
        "mode": mode,
        "path": str(item.get("path")),
        "relative_path": str(item.get("relative_path", "")),
        "kind": str(item.get("kind", "")),
        "score": int(item.get("score") or 0),
        "score_reasons": item.get("score_reasons", []),
        "status": "selected",
    }
    if matched_by:
        selection["matched_by"] = matched_by
    return selection


def _find_embedded_target(
    embedded_files: list[dict[str, object]],
    target: str,
) -> dict[str, object] | None:
    target_path = Path(target)
    for item in sorted(embedded_files, key=_embedded_file_sort_key):
        path = Path(str(item.get("path", "")))
        relative_path = str(item.get("relative_path", ""))
        if target in {str(path), relative_path, path.name}:
            return item
        if target_path.parts and Path(relative_path) == target_path:
            return item
    return None


def _find_embedded_pattern(
    embedded_files: list[dict[str, object]],
    pattern: str,
) -> dict[str, object] | None:
    patterns = [item.strip() for item in pattern.split("|") if item.strip()]
    for item in sorted(embedded_files, key=_embedded_file_sort_key):
        relative_path = str(item.get("relative_path", ""))
        name = Path(relative_path).name
        path = str(item.get("path", ""))
        if any(
            fnmatch(relative_path, candidate) or fnmatch(name, candidate) or fnmatch(path, candidate)
            for candidate in patterns
        ):
            return item
    return None


def _vulnerability_candidates_from_ghidra(analysis: dict[str, object]) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    call_graph = [item for item in analysis.get("call_graph", []) if isinstance(item, dict)]
    string_refs = [item for item in analysis.get("string_references", []) if isinstance(item, dict)]
    strings = [item for item in analysis.get("strings", []) if isinstance(item, dict)]

    function_calls: dict[str, set[str]] = {}
    for edge in call_graph:
        caller = str(edge.get("caller") or "")
        callee = str(edge.get("callee") or "")
        if caller and callee:
            function_calls.setdefault(caller, set()).add(callee)
        rule = _call_rule(callee)
        if rule:
            category, risk, reason = rule
            candidates.append(
                {
                    "category": category,
                    "risk": risk,
                    "function": caller,
                    "address": edge.get("caller_entry"),
                    "symbol": callee,
                    "evidence": [
                        f"{caller} calls {callee}",
                        reason,
                    ],
                }
            )
        if callee in SECURITY_CONTROL_FUNCTIONS:
            candidates.append(
                {
                    "category": "security_control",
                    "risk": "info",
                    "function": caller,
                    "address": edge.get("caller_entry"),
                    "symbol": callee,
                    "evidence": [f"{caller} calls {callee}"],
                }
            )

    function_strings: dict[str, list[str]] = {}
    for ref in string_refs:
        function = str(ref.get("from_function") or "")
        value = str(ref.get("string_value") or "")
        if function and value:
            function_strings.setdefault(function, []).append(value)
        string_candidate = _string_candidate(value, ref.get("from_address"), function or None)
        if string_candidate:
            candidates.append(string_candidate)

    referenced_values = {str(ref.get("string_value") or "") for ref in string_refs}
    for item in strings:
        value = str(item.get("value") or "")
        if value in referenced_values:
            continue
        string_candidate = _string_candidate(value, item.get("address"), None)
        if string_candidate:
            candidates.append(string_candidate)

    for function in sorted(set(function_calls) | set(function_strings)):
        calls = function_calls.get(function, set())
        values = function_strings.get(function, [])
        if _has_web_input_signal(calls, values) and _has_file_write_signal(calls, values):
            candidates.append(
                {
                    "category": "web_upload_file_write_flow",
                    "risk": "high",
                    "function": function,
                    "address": _function_entry(call_graph, function),
                    "symbol": None,
                    "evidence": [
                        "same function handles CGI/web input and filesystem write signals",
                        f"input={', '.join(sorted(_web_input_evidence(calls, values))[:6])}",
                        f"file_write={', '.join(sorted(_file_write_evidence(calls, values))[:6])}",
                    ],
                }
            )

    return _dedupe_candidates(candidates)[:100]


def _function_contexts_from_ghidra(
    analysis: dict[str, object],
    vulnerability_candidates: list[dict[str, object]],
) -> list[dict[str, object]]:
    interesting = [
        item for item in analysis.get("interesting_functions", []) if isinstance(item, dict)
    ]
    categories_by_function: dict[str, set[str]] = {}
    risks_by_function: dict[str, set[str]] = {}
    candidate_count_by_function: dict[str, int] = {}
    for candidate in vulnerability_candidates:
        function = candidate.get("function")
        if not isinstance(function, str) or not function:
            continue
        categories_by_function.setdefault(function, set()).add(str(candidate.get("category")))
        risks_by_function.setdefault(function, set()).add(str(candidate.get("risk")))
        candidate_count_by_function[function] = candidate_count_by_function.get(function, 0) + 1

    contexts: list[dict[str, object]] = []
    for item in interesting:
        name = str(item.get("name") or "")
        categories = sorted(categories_by_function.get(name, set()))
        risks = sorted(risks_by_function.get(name, set()), key=_risk_sort_key)
        evidence_snippets = _function_evidence_snippets(item)
        flow_signals = _function_flow_signals(categories, evidence_snippets)
        context = {
            "name": name,
            "entry_point": item.get("entry_point"),
            "candidate_categories": categories,
            "candidate_risks": risks,
            "candidate_count": candidate_count_by_function.get(name, 0),
            "review_priority": risks[0] if risks else "info",
            "flow_signals": flow_signals,
            "evidence_snippets": evidence_snippets,
            "reasons": item.get("reasons", []),
            "disassembly": item.get("disassembly", []),
            "decompiled": item.get("decompiled"),
        }
        contexts.append(context)
    return contexts


def _risk_sort_key(risk: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(risk, 9)


def _function_flow_signals(
    categories: list[str],
    evidence_snippets: list[dict[str, object]],
) -> list[str]:
    signals = {
        signal
        for category in categories
        if (signal := CATEGORY_FLOW_SIGNALS.get(category)) is not None
    }
    signals.update(
        str(snippet["signal"])
        for snippet in evidence_snippets
        if isinstance(snippet.get("signal"), str)
    )
    if {"web_input", "file_write"}.issubset(signals):
        signals.add("web_input_to_file_write")
    return sorted(signals)


def _function_evidence_snippets(item: dict[str, object]) -> list[dict[str, object]]:
    decompiled = item.get("decompiled")
    if not isinstance(decompiled, str) or not decompiled.strip():
        return []

    snippets: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for line_number, line in enumerate(decompiled.splitlines(), start=1):
        normalized = " ".join(line.strip().split())
        if not normalized:
            continue
        for signal, keywords in FLOW_SIGNAL_KEYWORDS.items():
            if not _line_matches_any(normalized, keywords):
                continue
            key = (signal, normalized)
            if key in seen:
                continue
            seen.add(key)
            snippets.append(
                {
                    "signal": signal,
                    "line": line_number,
                    "text": normalized[:240],
                }
            )
            break
        if len(snippets) >= 12:
            break
    return snippets


def _line_matches_any(line: str, keywords: tuple[str, ...]) -> bool:
    lower = line.lower()
    for keyword in keywords:
        if keyword.endswith("_"):
            if keyword in line:
                return True
            continue
        if keyword.lower() in lower:
            return True
    return False


def _call_rule(symbol: str) -> tuple[str, str, str] | None:
    name = symbol.lower()
    return CALL_RISK_RULES.get(name)


def _string_candidate(
    value: str,
    address: object,
    function: str | None,
) -> dict[str, object] | None:
    lower = value.lower()
    if value in WEB_INPUT_STRINGS or value.startswith("HTTP_"):
        return {
            "category": "web_input_string",
            "risk": "medium",
            "function": function,
            "address": address,
            "symbol": value,
            "evidence": [f"web/CGI input string: {value}"],
        }
    if lower.startswith("/tmp/") or "/tmp/" in lower:
        return {
            "category": "temporary_file_path",
            "risk": "medium",
            "function": function,
            "address": address,
            "symbol": value,
            "evidence": [f"temporary filesystem path: {value}"],
        }
    if "firmware" in lower or "upgrade" in lower:
        return {
            "category": "firmware_update_string",
            "risk": "medium",
            "function": function,
            "address": address,
            "symbol": value,
            "evidence": [f"firmware update related string: {value}"],
        }
    if any(keyword in lower for keyword in ("password", "passwd", "token", "secret", "auth", "login")):
        return {
            "category": "auth_sensitive_string",
            "risk": "medium",
            "function": function,
            "address": address,
            "symbol": value,
            "evidence": [f"authentication-sensitive string: {value}"],
        }
    return None


def _has_web_input_signal(calls: set[str], values: list[str]) -> bool:
    return bool(_web_input_evidence(calls, values))


def _web_input_evidence(calls: set[str], values: list[str]) -> set[str]:
    evidence = {call for call in calls if call.lower() == "getenv"}
    evidence.update(value for value in values if value in WEB_INPUT_STRINGS or value.startswith("HTTP_"))
    evidence.update(value for value in values if "multipart/form-data" in value.lower())
    return evidence


def _has_file_write_signal(calls: set[str], values: list[str]) -> bool:
    return bool(_file_write_evidence(calls, values))


def _file_write_evidence(calls: set[str], values: list[str]) -> set[str]:
    evidence = {call for call in calls if call.lower() in {"fopen", "fwrite", "remove", "unlink", "rename"}}
    evidence.update(value for value in values if value.startswith("/tmp/") or "/tmp/" in value)
    return evidence


def _function_entry(call_graph: list[dict[str, object]], function: str) -> object:
    for edge in call_graph:
        if edge.get("caller") == function:
            return edge.get("caller_entry")
    return None


def _dedupe_candidates(candidates: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[tuple[object, object, object, object]] = set()
    deduped: list[dict[str, object]] = []
    risk_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for candidate in sorted(
        candidates,
        key=lambda item: (
            risk_rank.get(str(item.get("risk")), 9),
            str(item.get("category")),
            str(item.get("function")),
            str(item.get("symbol")),
        ),
    ):
        if str(candidate.get("category", "")).endswith("_string"):
            key = (candidate.get("category"), candidate.get("function"), None, candidate.get("symbol"))
        else:
            key = (
                candidate.get("category"),
                candidate.get("function"),
                candidate.get("address"),
                candidate.get("symbol"),
            )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped


def _run_tool(command: list[str], *, timeout_seconds: int = 20) -> dict[str, object]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "command": command, "timeout_seconds": timeout_seconds}
    except Exception as exc:  # pragma: no cover - depends on host tools
        return {"status": "failed", "command": command, "error": str(exc)}
    output = (completed.stdout.strip() or completed.stderr.strip())[:8000]
    status = "completed" if completed.returncode == 0 else "completed_with_error"
    return {
        "status": status,
        "command": command,
        "returncode": completed.returncode,
        "output": output,
    }


def _strings_from_ghidra(analysis: dict[str, object]) -> list[str]:
    values = []
    for item in analysis.get("strings", []):
        if isinstance(item, dict) and isinstance(item.get("value"), str):
            values.append(item["value"])
        elif isinstance(item, str):
            values.append(item)
    return values


def _mmio_addresses_from_ghidra(analysis: dict[str, object]) -> list[str]:
    values = []
    for key in ("mmio_references", "mmio_xrefs"):
        for item in analysis.get(key, []):
            if isinstance(item, dict) and isinstance(item.get("address"), str):
                values.append(item["address"])
            elif isinstance(item, str):
                values.append(item)
    return values


def _architecture_from_ghidra(analysis: dict[str, object]) -> str | None:
    language = str(analysis.get("language_id") or "").lower()
    if "cortex" in language:
        return "arm-cortex-m"
    if language.startswith("arm:") or language.startswith("aarch64:"):
        return "arm-linux"
    if language.startswith("mips:"):
        return "mips"
    if language.startswith("riscv:"):
        return "riscv"
    if language.startswith("xtensa:"):
        return "xtensa"
    return None


def _entry_point_from_ghidra(analysis: dict[str, object]) -> str | None:
    reset_candidates = analysis.get("reset_handler_candidates")
    if isinstance(reset_candidates, list) and reset_candidates:
        first_candidate = reset_candidates[0]
        if isinstance(first_candidate, dict) and isinstance(first_candidate.get("entry_point"), str):
            return first_candidate["entry_point"]
    entry_points = analysis.get("entry_points")
    if isinstance(entry_points, list) and entry_points:
        first = entry_points[0]
        return first if isinstance(first, str) else None
    functions = analysis.get("functions")
    if isinstance(functions, list) and functions:
        first_function = functions[0]
        if isinstance(first_function, dict) and isinstance(first_function.get("entry_point"), str):
            return first_function["entry_point"]
    return None


def _merge_strings(primary: list[str], secondary: list[str]) -> list[str]:
    return sorted(set(primary + secondary), key=lambda item: (len(item), item))


def _merge_hex_addresses(primary: list[str], secondary: list[str]) -> list[str]:
    values: set[int] = set()
    for item in primary + secondary:
        try:
            values.add(int(item, 16))
        except ValueError:
            continue
    return [f"0x{value:08X}" for value in sorted(values)]
