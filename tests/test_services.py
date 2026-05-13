from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from firmware_mvp.services import (
    EmulationOptions,
    analyze_firmware,
    create_sample_firmware,
    emulate_config,
    extract_firmware_context,
    infer_from_context,
    run_pipeline,
)


class ServicesTest(unittest.TestCase):
    def test_service_pipeline_returns_artifacts_without_stdout_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "demo.bin"
            out = tmp_path / "run"

            sample = create_sample_firmware(firmware)
            self.assertEqual(sample.exit_code, 0)
            self.assertEqual(sample.artifacts["sample"], firmware)

            result = run_pipeline(
                firmware,
                "stm32f1",
                out,
                Path("references"),
                emulation_options=EmulationOptions(probe_address="0x40011000"),
            )

            self.assertEqual(result.exit_code, 0)
            self.assertFalse(result.errors)
            self.assertTrue(result.artifacts["context"].exists())
            self.assertTrue(result.artifacts["inference"].exists())
            self.assertTrue(result.artifacts["emulator_config"].exists())
            self.assertTrue(result.artifacts["emulation_result"].exists())
            emulation = result.payloads["emulation"]
            self.assertEqual(emulation["status"], "completed")
            self.assertEqual(emulation["stop_reason"], "mapped_mmio_access")

    def test_stage_services_can_be_called_individually(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "demo.bin"
            out = tmp_path / "staged"

            self.assertEqual(create_sample_firmware(firmware).exit_code, 0)
            extracted = extract_firmware_context(firmware, out)
            self.assertEqual(extracted.exit_code, 0)

            inferred = infer_from_context(out / "context.json", "stm32f1", out, Path("references"))
            self.assertEqual(inferred.exit_code, 0)

            emulated = emulate_config(
                out / "emulator_config.json",
                out,
                EmulationOptions(probe_address="0x50000000", access="write", pc="0x08000120"),
            )
            self.assertEqual(emulated.exit_code, 1)
            result = json.loads((out / "emulation_result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "crashed")
            self.assertEqual(result["crash"]["address"], "0x50000000")

    def test_services_return_errors_for_missing_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            result = analyze_firmware(
                tmp_path / "missing.bin",
                "stm32f1",
                tmp_path / "run",
                Path("references"),
            )

            self.assertEqual(result.exit_code, 2)
            self.assertIn("firmware not found", result.errors[0])
            self.assertFalse(result.artifacts)

    def test_emulation_timeout_is_configurable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "demo.bin"
            out = tmp_path / "timeout"

            self.assertEqual(create_sample_firmware(firmware).exit_code, 0)
            analysis = analyze_firmware(firmware, "stm32f1", out, Path("references"))
            self.assertEqual(analysis.exit_code, 0)

            result = emulate_config(
                out / "emulator_config.json",
                out,
                EmulationOptions(timeout_seconds=0),
            )

            self.assertEqual(result.exit_code, 1)
            emulation = result.payloads["emulation"]
            self.assertEqual(emulation["stop_reason"], "wall_clock_timeout")
            self.assertEqual(emulation["timeout_seconds"], 0)


if __name__ == "__main__":
    unittest.main()
