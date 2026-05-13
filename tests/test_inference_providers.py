from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from firmware_mvp.inference import InferenceOptions, build_inference_prompt
from firmware_mvp.models import FirmwareContext
from firmware_mvp.services import create_sample_firmware, extract_firmware_context, infer_from_context
from firmware_mvp.validation import validate_inference_payload


class InferenceProviderTest(unittest.TestCase):
    def test_validate_inference_payload_accepts_minimal_valid_payload(self) -> None:
        payload = {
            "schema_version": "0.2.0",
            "device": "stm32f1",
            "findings": [
                {
                    "mmio_address": "0x40011000",
                    "type": "UART",
                    "action": "map_dummy_mmio",
                    "value": "0x00000020",
                    "confidence": 0.8,
                    "evidence": ["fixture"],
                }
            ],
            "rag_hits": [],
            "assumptions": ["fixture"],
        }

        self.assertEqual(validate_inference_payload(payload), [])

    def test_validate_inference_payload_rejects_bad_findings(self) -> None:
        payload = {
            "schema_version": "0.2.0",
            "device": "stm32f1",
            "findings": [
                {
                    "mmio_address": "40011000",
                    "type": "UART",
                    "action": "map_dummy_mmio",
                    "value": "not-hex",
                    "confidence": 2,
                    "evidence": "fixture",
                }
            ],
            "rag_hits": [],
            "assumptions": [],
        }

        errors = validate_inference_payload(payload)

        self.assertTrue(any("mmio_address" in error for error in errors))
        self.assertTrue(any("value" in error for error in errors))
        self.assertTrue(any("confidence" in error for error in errors))
        self.assertTrue(any("evidence" in error for error in errors))

    def test_prompt_is_bounded_and_redacts_secret_like_strings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "demo.bin"
            context_dir = tmp_path / "context"
            self.assertEqual(create_sample_firmware(firmware).exit_code, 0)
            result = extract_firmware_context(firmware, context_dir)
            context = result.payloads["context"]
            context = type(context)(
                **{**context.__dict__, "strings": ["api_key=SECRET123", "USART"] * 20}
            )

            prompt = build_inference_prompt(context, "stm32f1", [], [], max_chars=200)

            self.assertLessEqual(len(prompt), 200)
            self.assertNotIn("SECRET123", prompt)

    def test_prompt_includes_emulation_feedback_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            context_json = self._write_context(tmp_path)
            context = json.loads(context_json.read_text(encoding="utf-8"))
            context["vulnerability_candidates"] = [
                {
                    "category": "web_upload_file_write_flow",
                    "risk": "high",
                    "function": "handle_upload",
                    "symbol": None,
                    "evidence": ["same function handles CGI/web input and filesystem write signals"],
                }
            ]
            context["function_contexts"] = [
                {
                    "name": "handle_upload",
                    "entry_point": "0x08001000",
                    "review_priority": "high",
                    "flow_signals": ["web_input", "file_write", "web_input_to_file_write"],
                    "evidence_snippets": [
                        {
                            "signal": "file_write",
                            "line": 42,
                            "text": "fwrite(buf, 1, len, out);",
                        }
                    ],
                    "reasons": ["calls fwrite"],
                    "disassembly": [],
                    "decompiled": "int handle_upload(void) { fwrite(buf, 1, len, out); }",
                }
            ]

            prompt = build_inference_prompt(
                FirmwareContext(**context),
                "stm32f1",
                [],
                [],
                feedback_artifacts={
                    "emulation_result": {
                        "status": "crashed",
                        "stop_reason": "unmapped_mmio",
                        "crash": {
                            "pc": "0x08000120",
                            "access": "write",
                            "address": "0x50000000",
                            "proposed_patch": {
                                "address": "0x50000000",
                                "type": "MMIO",
                                "action": "map_dummy_mmio",
                            },
                        },
                    },
                    "loop_summary": {
                        "status": "failed",
                        "final_config": "loop/emulator_config.json",
                        "iterations": [
                            {
                                "status": "crashed",
                                "stop_reason": "repeated_crash",
                                "patch_applied": False,
                            }
                        ],
                    },
                },
            )

            self.assertIn("Emulation feedback artifacts:", prompt)
            self.assertIn("web_upload_file_write_flow", prompt)
            self.assertIn("handle_upload", prompt)
            self.assertIn("fwrite(buf", prompt)
            self.assertIn("pc=0x08000120", prompt)
            self.assertIn("address=0x50000000", prompt)
            self.assertIn("last_loop_iteration", prompt)

    def test_mock_provider_success_writes_audit_and_emulator_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            context_json = self._write_context(tmp_path)
            out = tmp_path / "mock"

            result = infer_from_context(
                context_json,
                "stm32f1",
                out,
                Path("references"),
                InferenceOptions(provider="mock", mock_response="valid"),
            )

            self.assertEqual(result.exit_code, 0, result.errors)
            self.assertTrue((out / "inference.json").exists())
            self.assertTrue((out / "emulator_config.json").exists())
            audit = json.loads((out / "llm_audit.json").read_text(encoding="utf-8"))
            self.assertEqual(audit["provider_requested"], "mock")
            self.assertEqual(audit["provider_used"], "mock")
            self.assertEqual(audit["validation_status"], "valid")

    def test_mock_provider_invalid_fails_closed_without_emulator_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            context_json = self._write_context(tmp_path)
            out = tmp_path / "bad-mock"

            result = infer_from_context(
                context_json,
                "stm32f1",
                out,
                Path("references"),
                InferenceOptions(provider="mock", mock_response="invalid-json", max_retries=1),
            )

            self.assertEqual(result.exit_code, 1)
            self.assertTrue((out / "llm_audit.json").exists())
            self.assertFalse((out / "emulator_config.json").exists())
            audit = json.loads((out / "llm_audit.json").read_text(encoding="utf-8"))
            self.assertEqual(audit["validation_status"], "invalid")
            self.assertEqual(len(audit["attempts"]), 2)

    def test_mock_provider_invalid_can_explicitly_fallback_to_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            context_json = self._write_context(tmp_path)
            out = tmp_path / "fallback"

            result = infer_from_context(
                context_json,
                "stm32f1",
                out,
                Path("references"),
                InferenceOptions(
                    provider="mock",
                    mock_response="invalid-json",
                    fallback="deterministic",
                    max_retries=0,
                ),
            )

            self.assertEqual(result.exit_code, 0, result.errors)
            self.assertTrue((out / "emulator_config.json").exists())
            audit = json.loads((out / "llm_audit.json").read_text(encoding="utf-8"))
            self.assertEqual(audit["provider_requested"], "mock")
            self.assertEqual(audit["provider_used"], "deterministic")
            self.assertEqual(audit["validation_status"], "fallback")
            self.assertEqual(audit["fallback_from"], "mock")

    def test_mock_missing_field_is_repaired_with_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            context_json = self._write_context(tmp_path)
            out = tmp_path / "repaired-missing"

            result = infer_from_context(
                context_json,
                "stm32f1",
                out,
                Path("references"),
                InferenceOptions(provider="mock", mock_response="missing-field", max_retries=0),
            )

            self.assertEqual(result.exit_code, 0, result.errors)
            inference = json.loads((out / "inference.json").read_text(encoding="utf-8"))
            self.assertEqual(inference["findings"][0]["confidence"], 0.5)
            audit = json.loads((out / "llm_audit.json").read_text(encoding="utf-8"))
            self.assertEqual(audit["validation_status"], "valid")
            self.assertTrue(audit["attempts"][0]["repair_applied"])
            self.assertTrue(any("confidence" in note for note in audit["attempts"][0]["repair_notes"]))

    def test_mock_low_confidence_is_clamped_with_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            context_json = self._write_context(tmp_path)
            out = tmp_path / "repaired-low-confidence"

            result = infer_from_context(
                context_json,
                "stm32f1",
                out,
                Path("references"),
                InferenceOptions(provider="mock", mock_response="low-confidence", max_retries=0),
            )

            self.assertEqual(result.exit_code, 0, result.errors)
            inference = json.loads((out / "inference.json").read_text(encoding="utf-8"))
            self.assertEqual(inference["findings"][0]["confidence"], 0.0)
            audit = json.loads((out / "llm_audit.json").read_text(encoding="utf-8"))
            self.assertTrue(audit["attempts"][0]["repair_applied"])
            self.assertTrue(any("clamped confidence" in note for note in audit["attempts"][0]["repair_notes"]))

    def test_json_valid_findings_string_fails_closed_with_audit(self) -> None:
        payload = {
            "schema_version": "0.2.0",
            "device": "stm32f1",
            "findings": "bad",
            "rag_hits": [],
            "assumptions": [],
        }

        self._assert_payload_fails_closed(payload)

    def test_json_valid_non_dict_finding_fails_closed_with_audit(self) -> None:
        payload = {
            "schema_version": "0.2.0",
            "device": "stm32f1",
            "findings": ["bad"],
            "rag_hits": [],
            "assumptions": [],
        }

        self._assert_payload_fails_closed(payload)

    def test_json_valid_malformed_rag_hit_fails_closed_with_audit(self) -> None:
        payload = {
            "schema_version": "0.2.0",
            "device": "stm32f1",
            "findings": [
                {
                    "mmio_address": "0x40011000",
                    "type": "UART",
                    "action": "map_dummy_mmio",
                    "value": "0x00000020",
                    "confidence": 0.8,
                    "evidence": ["fixture"],
                }
            ],
            "rag_hits": [{"source": "missing score/excerpt"}],
            "assumptions": [],
        }

        self._assert_payload_fails_closed(payload)

    def test_openai_provider_missing_key_is_structured_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            old_key = os.environ.pop("OPENAI_API_KEY", None)
            try:
                tmp_path = Path(tmp)
                context_json = self._write_context(tmp_path)
                result = infer_from_context(
                    context_json,
                    "stm32f1",
                    tmp_path / "openai",
                    Path("references"),
                    InferenceOptions(provider="openai", max_retries=0),
                )
            finally:
                if old_key is not None:
                    os.environ["OPENAI_API_KEY"] = old_key

            self.assertEqual(result.exit_code, 1)
            self.assertTrue(any("OPENAI_API_KEY" in error for error in result.errors))

    def _write_context(self, tmp_path: Path) -> Path:
        firmware = tmp_path / "demo.bin"
        out = tmp_path / "context"
        self.assertEqual(create_sample_firmware(firmware).exit_code, 0)
        result = extract_firmware_context(firmware, out)
        self.assertEqual(result.exit_code, 0)
        return out / "context.json"

    def _assert_payload_fails_closed(self, payload: dict[str, object]) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            context_json = self._write_context(tmp_path)
            response_path = tmp_path / "response.json"
            response_path.write_text(json.dumps(payload), encoding="utf-8")
            out = tmp_path / "bad-payload"

            result = infer_from_context(
                context_json,
                "stm32f1",
                out,
                Path("references"),
                InferenceOptions(
                    provider="mock",
                    mock_response_path=response_path,
                    max_retries=0,
                ),
            )

            self.assertEqual(result.exit_code, 1)
            self.assertTrue((out / "llm_audit.json").exists())
            self.assertTrue((out / "llm_attempts" / "attempt-1.raw.txt").exists())
            self.assertTrue((out / "llm_attempts" / "attempt-1.parsed.json").exists())
            self.assertFalse((out / "emulator_config.json").exists())
            audit = json.loads((out / "llm_audit.json").read_text(encoding="utf-8"))
            self.assertEqual(audit["validation_status"], "invalid")


if __name__ == "__main__":
    unittest.main()
