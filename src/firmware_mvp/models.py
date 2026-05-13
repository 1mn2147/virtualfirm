from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
import json


SCHEMA_VERSION = "0.2.0"


@dataclass(frozen=True)
class FirmwareContext:
    path: str
    size_bytes: int
    sha256: str
    entropy: float
    architecture_hint: str
    encrypted_or_compressed_likely: bool
    entry_point: str | None
    strings: list[str]
    mmio_addresses: list[str]
    input_format: str = "raw-binary"
    loaded_base_address: str | None = None
    loaded_size_bytes: int | None = None
    loaded_ranges: list[dict[str, Any]] = field(default_factory=list)
    vector_table: dict[str, Any] | None = None
    entropy_windows: list[dict[str, Any]] = field(default_factory=list)
    compressed_or_encrypted_ranges: list[dict[str, Any]] = field(default_factory=list)
    string_ranges: list[dict[str, Any]] = field(default_factory=list)
    firmware_segments: list[dict[str, Any]] = field(default_factory=list)
    embedded_files: list[dict[str, Any]] = field(default_factory=list)
    vulnerability_candidates: list[dict[str, Any]] = field(default_factory=list)
    function_contexts: list[dict[str, Any]] = field(default_factory=list)
    analysis_warnings: list[str] = field(default_factory=list)
    tool_observations: dict[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION


@dataclass(frozen=True)
class RagHit:
    source: str
    score: int
    excerpt: str
    kind: str = "text"
    source_location: str | None = None


@dataclass(frozen=True)
class PeripheralFinding:
    mmio_address: str
    type: str
    action: str
    value: str
    confidence: float
    evidence: list[str]
    peripheral_name: str | None = None
    reference_range: str | None = None
    reference_source: str | None = None


@dataclass(frozen=True)
class InferenceResult:
    device: str
    findings: list[PeripheralFinding]
    rag_hits: list[RagHit]
    assumptions: list[str]
    schema_version: str = SCHEMA_VERSION


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = asdict(payload) if hasattr(payload, "__dataclass_fields__") else payload
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
