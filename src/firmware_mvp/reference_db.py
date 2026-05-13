from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json


@dataclass(frozen=True)
class PeripheralRange:
    device: str
    name: str
    type: str
    start: int
    end: int
    default_read: str
    description: str
    source: str

    @property
    def range_text(self) -> str:
        return f"0x{self.start:08X}-0x{self.end:08X}"

    def contains(self, address: int) -> bool:
        return self.start <= address <= self.end


def load_memory_maps(references_dir: Path, device: str) -> list[PeripheralRange]:
    if not references_dir.exists():
        return []

    device_key = device.lower()
    ranges: list[PeripheralRange] = []
    for path in sorted((references_dir / "memory_maps").glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        aliases = {payload.get("device", "").lower()}
        aliases.update(alias.lower() for alias in payload.get("aliases", []))
        if device_key not in aliases:
            continue
        source = payload.get("source") or str(path)
        for item in payload.get("ranges", []):
            ranges.append(
                PeripheralRange(
                    device=payload.get("device", device),
                    name=item["name"],
                    type=item["type"],
                    start=int(item["start"], 16),
                    end=int(item["end"], 16),
                    default_read=item.get("default_read", "0x00000000"),
                    description=item.get("description", ""),
                    source=source,
                )
            )
    return sorted(ranges, key=lambda item: (item.start, item.end, item.name))


def lookup_address(address: int, ranges: list[PeripheralRange]) -> PeripheralRange | None:
    for peripheral_range in ranges:
        if peripheral_range.contains(address):
            return peripheral_range
    return None
