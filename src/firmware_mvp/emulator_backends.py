from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
import json
import importlib.util
import signal
import tempfile

from .models import SCHEMA_VERSION
from .emulator import run_emulation_stub


class EmulationBackend(Protocol):
    name: str

    def run(
        self,
        emulator_config_path: Path,
        probe_address: str | None,
        access: str,
        pc: str,
        instruction_limit: int,
        timeout_seconds: int,
    ) -> dict:
        ...


@dataclass(frozen=True)
class StubEmulationBackend:
    name: str = "stub"

    def run(
        self,
        emulator_config_path: Path,
        probe_address: str | None,
        access: str,
        pc: str,
        instruction_limit: int,
        timeout_seconds: int,
    ) -> dict:
        return run_emulation_stub(
            emulator_config_path,
            probe_address,
            access,
            pc,
            instruction_limit,
            timeout_seconds,
        )


@dataclass(frozen=True)
class QilingEmulationBackend:
    rootfs: str | None = None
    name: str = "qiling"

    def run(
        self,
        emulator_config_path: Path,
        probe_address: str | None,
        access: str,
        pc: str,
        instruction_limit: int,
        timeout_seconds: int,
    ) -> dict:
        if importlib.util.find_spec("qiling") is None:
            raise RuntimeError(
                "qiling backend requested but qiling is not installed; "
                "install with `pip install -e .[qiling]`"
            )
        return self._run_qiling(
            emulator_config_path,
            probe_address,
            access,
            pc,
            instruction_limit,
            timeout_seconds,
        )

    def _run_qiling(
        self,
        emulator_config_path: Path,
        probe_address: str | None,
        access: str,
        pc: str,
        instruction_limit: int,
        timeout_seconds: int,
    ) -> dict[str, Any]:
        config = json.loads(emulator_config_path.read_text(encoding="utf-8"))
        firmware_path = config.get("firmware", {}).get("path")
        if not firmware_path:
            return _backend_error_result(
                config,
                instruction_limit,
                timeout_seconds,
                "missing_firmware_path",
            )

        try:
            from qiling import Qiling
            from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
        except Exception as exc:  # pragma: no cover - depends on optional package
            raise RuntimeError(f"qiling import failed: {exc}") from exc

        rootfs = self.rootfs or config.get("qiling", {}).get("rootfs") or "."
        hook_events: list[dict[str, Any]] = []
        profile_path = _write_mcu_profile(config)
        try:
            ql = Qiling(
                _qiling_argv(config, firmware_path),
                rootfs,
                ostype=_qiling_os(config, QL_OS),
                archtype=_qiling_arch(config, QL_ARCH),
                verbose=QL_VERBOSE.OFF,
                profile=profile_path,
            )
            mapped_regions = _install_mappings(ql, config.get("mappings", []), hook_events)
            _run_with_limit(ql, instruction_limit, timeout_seconds)
        except Exception as exc:  # pragma: no cover - depends on optional package
            return _backend_error_result(
                config,
                instruction_limit,
                timeout_seconds,
                "qiling_execution_error",
                str(exc),
                hook_events,
            )
        finally:
            if profile_path:
                Path(profile_path).unlink(missing_ok=True)

        return {
            "schema_version": SCHEMA_VERSION,
            "backend": "qiling",
            "device": config.get("device", "unknown"),
            "status": "completed",
            "stop_reason": "instruction_limit_reached",
            "instruction_count": _instruction_count(ql, instruction_limit),
            "instruction_limit": instruction_limit,
            "timeout_seconds": timeout_seconds,
            "mapped_regions": mapped_regions,
            "crash": None,
            "events": hook_events,
            "probe": _probe_payload(probe_address, access, pc),
        }


def get_emulation_backend(name: str, rootfs: str | None = None) -> EmulationBackend:
    if name == "stub":
        return StubEmulationBackend()
    if name == "qiling":
        return QilingEmulationBackend(rootfs=rootfs)
    raise ValueError(f"unknown emulator backend: {name}")


def _qiling_argv(config: dict[str, Any], firmware_path: str) -> list[Any]:
    if _is_cortex_m(config):
        load_address = config.get("qiling", {}).get("load_address") or "0x08000000"
        return [firmware_path, int(load_address, 16)]
    return [firmware_path]


def _qiling_arch(config: dict[str, Any], ql_arch):
    if _is_cortex_m(config):
        return ql_arch.CORTEX_M
    return None


def _qiling_os(config: dict[str, Any], ql_os):
    if _is_cortex_m(config):
        return ql_os.MCU
    return None


def _is_cortex_m(config: dict[str, Any]) -> bool:
    firmware = config.get("firmware", {})
    hint = (firmware.get("architecture_hint") or "").lower()
    return "cortex-m" in hint


def _write_mcu_profile(config: dict[str, Any]) -> str | None:
    if not _is_cortex_m(config):
        return None
    profile = _mcu_profile(config)
    if not profile:
        return None
    import yaml

    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as handle:
        yaml.safe_dump(profile, handle)
        return handle.name


def _mcu_profile(config: dict[str, Any]) -> dict[str, Any] | None:
    device = (config.get("device") or "").lower()
    if device.startswith("stm32f1"):
        from qiling.extensions.mcu.stm32f1.stm32f103 import stm32f103

        return stm32f103
    return None


def _install_mappings(ql, mappings: list[dict[str, Any]], events: list[dict[str, Any]]) -> int:
    installed = 0
    for mapping in mappings:
        base = int(mapping["base"], 16)
        size = int(mapping["size"], 16)
        try:
            ql.mem.map(base, size, info=mapping.get("type", "MMIO"))
        except Exception as exc:
            reason = str(exc)
            events.append(
                {
                    "event": "mapping_existing" if "unavailable" in reason.lower() else "mapping_skipped",
                    "base": mapping["base"],
                    "size": mapping["size"],
                    "reason": reason,
                }
            )
            if "unavailable" in reason.lower():
                installed += 1
        else:
            installed += 1
        _install_mmio_hooks(ql, base, size, mapping, events)
    return installed


def _install_mmio_hooks(
    ql,
    base: int,
    size: int,
    mapping: dict[str, Any],
    events: list[dict[str, Any]],
) -> None:
    end = base + size - 1

    def _read_hook(_ql, _access, address, read_size, _value):
        events.append(
            {
                "event": "mmio_read",
                "address": f"0x{address:08X}",
                "size": read_size,
                "type": mapping.get("type"),
                "default_read": mapping.get("default_read"),
            }
        )

    def _write_hook(_ql, _access, address, write_size, value):
        events.append(
            {
                "event": "mmio_write",
                "address": f"0x{address:08X}",
                "size": write_size,
                "value": f"0x{value:X}",
                "type": mapping.get("type"),
            }
        )

    if hasattr(ql, "hook_mem_read"):
        ql.hook_mem_read(_read_hook, begin=base, end=end)
    if hasattr(ql, "hook_mem_write"):
        ql.hook_mem_write(_write_hook, begin=base, end=end)


def _run_with_limit(ql, instruction_limit: int, timeout_seconds: int) -> None:
    def _raise_timeout(_signum, _frame):
        raise TimeoutError(f"wall-clock timeout after {timeout_seconds}s")

    old_handler = None
    try:
        if timeout_seconds > 0:
            old_handler = signal.signal(signal.SIGALRM, _raise_timeout)
            signal.setitimer(signal.ITIMER_REAL, timeout_seconds)
        ql.run(count=instruction_limit)
    except TypeError:
        ql.run()
    finally:
        if timeout_seconds > 0:
            signal.setitimer(signal.ITIMER_REAL, 0)
            if old_handler is not None:
                signal.signal(signal.SIGALRM, old_handler)


def _instruction_count(ql, fallback: int) -> int:
    counter = getattr(getattr(ql, "os", None), "counter", None)
    if isinstance(counter, int):
        return counter
    return fallback


def _backend_error_result(
    config: dict[str, Any],
    instruction_limit: int,
    timeout_seconds: int,
    stop_reason: str,
    message: str | None = None,
    events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "backend": "qiling",
        "device": config.get("device", "unknown"),
        "status": "crashed",
        "stop_reason": stop_reason,
        "instruction_count": 0,
        "instruction_limit": instruction_limit,
        "timeout_seconds": timeout_seconds,
        "mapped_regions": 0,
        "crash": {
            "pc": config.get("firmware", {}).get("entry_point") or "0x00000000",
            "access": "execute",
            "address": config.get("firmware", {}).get("entry_point") or "0x00000000",
            "registers": {},
            "message": message or stop_reason,
            "proposed_patch": None,
        },
        "events": events or [],
    }


def _probe_payload(probe_address: str | None, access: str, pc: str) -> dict[str, str] | None:
    if not probe_address:
        return None
    return {
        "pc": pc,
        "access": access,
        "address": probe_address,
    }
