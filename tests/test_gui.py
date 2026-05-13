from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from firmware_mvp.gui import JobManager, read_artifact, render_index


class GuiTest(unittest.TestCase):
    def test_gui_index_exposes_core_workflows_and_forms(self) -> None:
        html = render_index()
        for text in (
            "analyze",
            "extract",
            "infer",
            "emulate",
            "loop",
            "feedback",
            "validate",
            "init-sample",
            "Firmware / JSON / PDF path",
            "Probe address",
            "Success criterion",
        ):
            self.assertIn(text, html)

    def test_gui_job_manager_runs_command_and_rewrites_report_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "demo.bin"
            out = tmp_path / "run"
            manager = JobManager(Path.cwd())

            sample = manager.start(["init-sample", "--out", str(firmware)])
            self._wait(sample)
            self.assertEqual(sample.status, "completed")

            analyze = manager.start(
                ["analyze", str(firmware), "--device", "stm32f1", "--out", str(out)]
            )
            self._wait(analyze)
            self.assertEqual(analyze.status, "completed")
            report = (out / "report.md").read_text(encoding="utf-8")
            self.assertIn("Command: `firmware-mvp analyze", report)

            artifact = read_artifact({"run_dir": [str(out)], "name": ["context"]})
            self.assertIn("context.json", artifact["path"])
            self.assertIn("schema_version", artifact["content"])

            retry = manager.retry(analyze.id)
            self.assertIsNotNone(retry)
            self._wait(retry)
            self.assertEqual(retry.status, "completed")

    def test_gui_rejects_unsupported_command(self) -> None:
        with self.assertRaises(ValueError):
            JobManager(Path.cwd()).start(["rm", "-rf", "/"])

    def _wait(self, job, timeout: float = 5.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline and job.status in {"queued", "running"}:
            time.sleep(0.05)
        self.assertNotIn(job.status, {"queued", "running"})
