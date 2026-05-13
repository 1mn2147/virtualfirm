from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from firmware_mvp.reporting import write_report
from firmware_mvp.validation import validate_run_dir


class CompatibilityTest(unittest.TestCase):
    def test_legacy_emulation_result_is_normalized_for_validation_and_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "emulation_result.json").write_text(
                json.dumps(
                    {
                        "schema_version": "0.2.0",
                        "backend": "stub",
                        "device": "stm32f1",
                        "status": "completed",
                        "stop_reason": "mapped_mmio_access",
                        "instruction_count": 1,
                        "instruction_limit": 1,
                        "mapped_regions": 3,
                        "crash": None,
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            self.assertEqual(validate_run_dir(run_dir), [])
            report = write_report(run_dir).read_text(encoding="utf-8")
            self.assertIn("Emulation success: `True`", report)
            self.assertIn("Exit condition: `mapped_mmio_access`", report)
