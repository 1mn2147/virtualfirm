from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from firmware_mvp.cli import main
from firmware_mvp.extractor import (
    _architecture_from_ghidra,
    _architecture_from_tools,
    _compressed_or_encrypted_ranges,
    _extract_mmio_addresses,
    _extract_string_ranges,
    _entropy_windows,
    _function_contexts_from_ghidra,
    _load_firmware_image,
    _non_code_ranges,
    _parse_cortex_m_vector_table,
    _parse_binwalk_segments,
    _run_tool,
    _score_embedded_file,
    _select_ghidra_target,
    _select_ghidra_target_details,
    _vulnerability_candidates_from_ghidra,
)
from firmware_mvp.rag import search_references
from firmware_mvp.services import create_sample_firmware, extract_firmware_context


def _ihex_record(address: int, record_type: int, payload: bytes) -> str:
    body = bytes([len(payload), (address >> 8) & 0xFF, address & 0xFF, record_type]) + payload
    checksum = (-sum(body)) & 0xFF
    return ":" + (body + bytes([checksum])).hex().upper()


def _srec_record(record_type: str, address: int, payload: bytes) -> str:
    address_lengths = {"1": 2, "2": 3, "3": 4, "7": 4, "8": 3, "9": 2}
    address_length = address_lengths[record_type]
    address_bytes = address.to_bytes(address_length, "big")
    count = len(address_bytes) + len(payload) + 1
    body = bytes([count]) + address_bytes + payload
    checksum = (~sum(body)) & 0xFF
    return "S" + record_type + (body + bytes([checksum])).hex().upper()


class PipelineTest(unittest.TestCase):
    def test_pipeline_creates_json_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "demo.bin"
            out = tmp_path / "run"

            self.assertEqual(main(["init-sample", "--out", str(firmware)]), 0)
            self.assertEqual(
                main(["analyze", str(firmware), "--device", "stm32f1", "--out", str(out)]),
                0,
            )

            self.assertTrue((out / "context.json").exists())
            self.assertTrue((out / "inference.json").exists())
            self.assertTrue((out / "emulator_config.json").exists())
            self.assertTrue((out / "report.md").exists())

            context = json.loads((out / "context.json").read_text(encoding="utf-8"))
            inference = json.loads((out / "inference.json").read_text(encoding="utf-8"))
            emulator_config = json.loads(
                (out / "emulator_config.json").read_text(encoding="utf-8")
            )
            self.assertEqual(context["schema_version"], "0.2.0")
            self.assertIn("tool_results", context["tool_observations"])
            self.assertIn("file", context["tool_observations"]["tool_results"])
            self.assertIn("readelf", context["tool_observations"]["tool_results"])
            self.assertIn("objdump", context["tool_observations"]["tool_results"])
            self.assertIn("xxd", context["tool_observations"]["tool_results"])
            self.assertEqual(inference["schema_version"], "0.2.0")
            self.assertEqual(emulator_config["schema_version"], "0.2.0")
            self.assertEqual(emulator_config["firmware"]["path"], str(firmware))
            self.assertEqual(emulator_config["firmware"]["entry_point"], "0x08000100")

            findings = {item["mmio_address"]: item for item in inference["findings"]}
            self.assertEqual(findings["0x40021018"]["peripheral_name"], "RCC")
            self.assertEqual(findings["0x40011000"]["reference_range"], "0x40011000-0x400113FF")
            self.assertEqual(main(["validate", str(out)]), 0)

    def test_project_config_supplies_cli_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "demo.bin"
            out = tmp_path / "configured"
            config = tmp_path / "firmware-mvp.yml"
            config.write_text(
                "\n".join(
                    [
                        "defaults:",
                        "  device: stm32f1",
                        "  references: references",
                        "analyze:",
                        f"  out: {out}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            self.assertEqual(main(["init-sample", "--out", str(firmware)]), 0)
            self.assertEqual(main(["--config", str(config), "analyze", str(firmware)]), 0)

            inference = json.loads((out / "inference.json").read_text(encoding="utf-8"))
            self.assertEqual(inference["device"], "stm32f1")

    def test_project_config_defaults_apply_from_real_cli_argv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "demo.bin"
            out = tmp_path / "configured-real-argv"
            config = tmp_path / "firmware-mvp.json"
            config.write_text(
                json.dumps(
                    {
                        "defaults": {"device": "stm32f1", "references": "references"},
                        "analyze": {"out": str(out)},
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(main(["init-sample", "--out", str(firmware)]), 0)
            with patch(
                "sys.argv",
                ["firmware-mvp", "--config", str(config), "analyze", str(firmware)],
            ):
                self.assertEqual(main(), 0)

            inference = json.loads((out / "inference.json").read_text(encoding="utf-8"))
            self.assertEqual(inference["device"], "stm32f1")

    def test_json_output_reports_exit_code_artifacts_and_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "missing.bin"
            out = tmp_path / "json-error"
            output = StringIO()

            with redirect_stdout(output):
                exit_code = main(["analyze", str(firmware), "--out", str(out), "--json"])

            payload = json.loads(output.getvalue())
            self.assertEqual(exit_code, 2)
            self.assertEqual(payload["exit_code"], 2)
            self.assertEqual(payload["artifacts"], {})
            self.assertIn("firmware not found", payload["errors"][0])

    def test_output_root_prefixes_relative_output_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "demo.bin"
            output_root = tmp_path / "outside-repo"

            self.assertEqual(main(["init-sample", "--out", str(firmware)]), 0)
            self.assertEqual(
                main(
                    [
                        "--output-root",
                        str(output_root),
                        "analyze",
                        str(firmware),
                        "--device",
                        "stm32f1",
                        "--out",
                        "relative-run",
                    ]
                ),
                0,
            )

            self.assertTrue((output_root / "relative-run" / "context.json").exists())

    def test_json_output_covers_utility_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "demo.bin"
            out = tmp_path / "run"

            sample_output = StringIO()
            with redirect_stdout(sample_output):
                self.assertEqual(main(["init-sample", "--out", str(firmware), "--json"]), 0)
            sample_payload = json.loads(sample_output.getvalue())
            self.assertEqual(sample_payload["exit_code"], 0)
            self.assertEqual(sample_payload["artifacts"]["sample"], str(firmware))

            self.assertEqual(main(["analyze", str(firmware), "--device", "stm32f1", "--out", str(out)]), 0)

            report_output = StringIO()
            with redirect_stdout(report_output):
                self.assertEqual(main(["report", str(out), "--json"]), 0)
            report_payload = json.loads(report_output.getvalue())
            self.assertEqual(report_payload["artifacts"]["report"], str(out / "report.md"))

            feedback_output = StringIO()
            with redirect_stdout(feedback_output):
                self.assertEqual(main(["feedback", "0x40021018", "--access", "write", "--json"]), 0)
            feedback_payload = json.loads(feedback_output.getvalue())
            self.assertEqual(feedback_payload["exit_code"], 0)
            self.assertEqual(feedback_payload["payload"]["mmio_address"], "0x40021018")

            validate_output = StringIO()
            with redirect_stdout(validate_output):
                self.assertEqual(main(["validate", str(out), "--json"]), 0)
            validate_payload = json.loads(validate_output.getvalue())
            self.assertEqual(validate_payload["exit_code"], 0)
            self.assertEqual(validate_payload["errors"], [])

    def test_rag_hits_include_file_location(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "demo.bin"
            context_dir = tmp_path / "context"
            refs = tmp_path / "references"
            refs.mkdir()
            (refs / "stm32f1.md").write_text(
                "intro\n\nUSART1 is mapped at 0x40011000.\n",
                encoding="utf-8",
            )

            self.assertEqual(create_sample_firmware(firmware).exit_code, 0)
            result = extract_firmware_context(firmware, context_dir)
            self.assertEqual(result.exit_code, 0)

            hits = search_references(result.payloads["context"], "stm32f1", refs)

            self.assertTrue(hits)
            self.assertEqual(hits[0].source, str(refs / "stm32f1.md"))
            self.assertEqual(hits[0].kind, "sqlite-text")
            self.assertEqual(hits[0].source_location, f"{refs / 'stm32f1.md'}:3")
            self.assertIn("USART1", hits[0].excerpt)

    def test_ingest_pdf_converts_datasheet_to_rag_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "demo.bin"
            pdf = tmp_path / "datasheet.pdf"
            fake_pdftotext = tmp_path / "pdftotext"
            refs = tmp_path / "references"
            context_dir = tmp_path / "context"

            pdf.write_bytes(b"%PDF-1.4 fake")
            fake_pdftotext.write_text(
                "\n".join(
                    [
                        "#!/usr/bin/env python3",
                        "import pathlib",
                        "import sys",
                        "out = pathlib.Path(sys.argv[-1])",
                        "out.write_text('USART1 register 0x40011000\\nRCC 0x40021000\\n')",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            fake_pdftotext.chmod(0o755)

            self.assertEqual(
                main(
                    [
                        "ingest-pdf",
                        str(pdf),
                        "--device",
                        "stm32f1",
                        "--out",
                        str(refs),
                        "--pdftotext",
                        str(fake_pdftotext),
                    ]
                ),
                0,
            )
            self.assertTrue((refs / "datasheet.md").exists())

            self.assertEqual(create_sample_firmware(firmware).exit_code, 0)
            result = extract_firmware_context(firmware, context_dir)
            hits = search_references(result.payloads["context"], "stm32f1", refs)
            self.assertTrue(hits)
            self.assertEqual(hits[0].kind, "sqlite-text")
            self.assertTrue(any("0x40011000" in hit.excerpt for hit in hits))

    def test_init_sample_kinds_cover_fixture_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            expectations = {
                "raw": "raw-binary",
                "elf": "elf",
                "high-entropy": "raw-binary",
                "mmio-heavy": "raw-binary",
            }
            for kind, expected_format in expectations.items():
                firmware = tmp_path / f"{kind}.bin"
                out = tmp_path / f"{kind}-run"
                self.assertEqual(main(["init-sample", "--kind", kind, "--out", str(firmware)]), 0)
                self.assertEqual(main(["extract", str(firmware), "--out", str(out)]), 0)
                context = json.loads((out / "context.json").read_text(encoding="utf-8"))
                self.assertEqual(context["input_format"], expected_format)
                if kind == "high-entropy":
                    self.assertTrue(context["encrypted_or_compressed_likely"])
                    self.assertTrue(context["compressed_or_encrypted_ranges"])
                if kind == "mmio-heavy":
                    self.assertGreaterEqual(len(context["mmio_addresses"]), 100)

    def test_external_tool_runner_bounds_timeout_and_output(self) -> None:
        timeout = _run_tool(
            ["python", "-c", "import time; time.sleep(1)"],
            timeout_seconds=0,
        )
        self.assertEqual(timeout["status"], "timeout")

        output = _run_tool(
            ["python", "-c", "print('A' * 9000)"],
            timeout_seconds=5,
        )
        self.assertEqual(output["status"], "completed")
        self.assertLessEqual(len(str(output["output"])), 8000)

    def test_feedback_patch_is_printable(self) -> None:
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["feedback", "0x40021018", "--access", "write"]), 0)
        self.assertIn("0x40021018", output.getvalue())
        self.assertIn("store_and_continue", output.getvalue())

    def test_staged_commands_and_stub_emulation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "demo.bin"
            out = tmp_path / "staged"

            self.assertEqual(main(["init-sample", "--out", str(firmware)]), 0)
            self.assertEqual(main(["extract", str(firmware), "--out", str(out)]), 0)
            self.assertEqual(
                main(["infer", str(out / "context.json"), "--device", "stm32f1", "--out", str(out)]),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "emulate",
                        str(out / "emulator_config.json"),
                        "--out",
                        str(out),
                        "--probe-address",
                        "0x40011000",
                    ]
                ),
                0,
            )

            result = json.loads((out / "emulation_result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["stop_reason"], "mapped_mmio_access")
            self.assertEqual(result["success"], True)
            self.assertEqual(result["exit_condition"]["type"], "mapped_mmio_access")
            self.assertEqual(main(["validate", str(out)]), 0)

    def test_emulation_success_criteria_and_io_capture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "demo.bin"
            out = tmp_path / "criteria"

            self.assertEqual(main(["init-sample", "--out", str(firmware)]), 0)
            self.assertEqual(
                main(["analyze", str(firmware), "--device", "stm32f1", "--out", str(out)]),
                0,
            )
            config_path = out / "emulator_config.json"
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config["capture"] = {
                "uart_output": ["Boot OK", "USART ready"],
                "semihosting": [{"operation": "SYS_EXIT", "code": 0}],
            }
            config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

            self.assertEqual(
                main(
                    [
                        "emulate",
                        str(config_path),
                        "--out",
                        str(out),
                        "--success-criterion",
                        "uart-output",
                        "--success-uart-contains",
                        "Boot",
                    ]
                ),
                0,
            )

            result = json.loads((out / "emulation_result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["success"], True)
            self.assertEqual(result["uart_output"], ["Boot OK", "USART ready"])
            self.assertEqual(result["semihosting"][0]["operation"], "SYS_EXIT")
            self.assertEqual(result["success_criteria"][0]["criterion"], "uart-output")
            report = (out / "report.md").read_text(encoding="utf-8")
            self.assertIn("UART output", report)
            self.assertIn("Semihosting events: 1", report)
            self.assertEqual(main(["validate", str(out)]), 0)

    def test_emulation_success_criteria_can_fail_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "demo.bin"
            out = tmp_path / "criteria-fail"

            self.assertEqual(main(["init-sample", "--out", str(firmware)]), 0)
            self.assertEqual(
                main(["analyze", str(firmware), "--device", "stm32f1", "--out", str(out)]),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "emulate",
                        str(out / "emulator_config.json"),
                        "--out",
                        str(out),
                        "--success-criterion",
                        "no-crash-for-instructions",
                        "--instruction-limit",
                        "1",
                    ]
                ),
                1,
            )
            result = json.loads((out / "emulation_result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["success"], False)
            self.assertEqual(result["success_criteria"][0]["criterion"], "no-crash-for-instructions")

    def test_extract_ghidra_backend_merges_headless_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "demo.bin"
            out = tmp_path / "ghidra-run"
            fake_headless = tmp_path / "analyzeHeadless"

            self.assertEqual(main(["init-sample", "--out", str(firmware)]), 0)
            fake_headless.write_text(
                "\n".join(
                    [
                        "#!/usr/bin/env python3",
                        "import json",
                        "import pathlib",
                        "import sys",
                        "output = pathlib.Path(sys.argv[-1])",
                        "output.parent.mkdir(parents=True, exist_ok=True)",
                        "output.write_text(json.dumps({",
                        "  'language_id': 'ARM:LE:32:Cortex',",
                        "  'entry_points': ['0x08000200'],",
                        "  'functions': [{'name': 'Reset_Handler', 'entry_point': '0x08000200'}],",
                        "  'call_graph': [{'caller': 'Reset_Handler', 'callee': 'uart_init'}],",
                        "  'strings': [{'address': '0x08000300', 'value': 'Ghidra UART'}],",
                        "  'string_references': [{'string_address': '0x08000300', 'from_address': '0x08000210'}],",
                        "  'mmio_references': [{'address': '0x40011400'}],",
                        "  'mmio_xrefs': [{'address': '0x40011800', 'instruction_address': '0x08000220'}],",
                        "  'reset_handler_candidates': [{'name': 'Reset_Handler', 'entry_point': '0x08000204', 'disassembly': [{'address': '0x08000204', 'text': 'push {lr}'}]}],",
                        "  'interesting_functions': [{'name': 'Reset_Handler', 'entry_point': '0x08000204', 'reasons': ['calls getenv'], 'disassembly': [{'address': '0x08000204', 'text': 'push {lr}'}], 'decompiled': 'int Reset_Handler(void) { return 0; }'}],",
                        "}), encoding='utf-8')",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            fake_headless.chmod(0o755)

            self.assertEqual(
                main(
                    [
                        "extract",
                        str(firmware),
                        "--out",
                        str(out),
                        "--analysis-backend",
                        "ghidra",
                        "--ghidra-headless",
                        str(fake_headless),
                    ]
                ),
                0,
            )

            context = json.loads((out / "context.json").read_text(encoding="utf-8"))
            self.assertEqual(context["architecture_hint"], "arm-cortex-m")
            self.assertEqual(context["entry_point"], "0x08000204")
            self.assertIn("Ghidra UART", context["strings"])
            self.assertIn("0x40011400", context["mmio_addresses"])
            self.assertIn("0x40011800", context["mmio_addresses"])
            self.assertEqual(context["tool_observations"]["ghidra"]["status"], "completed")
            self.assertEqual(
                context["tool_observations"]["ghidra"]["summary"]["call_graph_edges"],
                1,
            )
            self.assertEqual(
                context["tool_observations"]["ghidra"]["summary"]["reset_handler_candidates"],
                1,
            )
            self.assertEqual(context["function_contexts"][0]["name"], "Reset_Handler")
            self.assertIn("calls getenv", context["function_contexts"][0]["reasons"])
            self.assertEqual(context["function_contexts"][0]["review_priority"], "info")

    def test_extract_ida_backend_merges_headless_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "demo.bin"
            out = tmp_path / "ida-run"
            fake_ida = tmp_path / "idat64"

            self.assertEqual(main(["init-sample", "--out", str(firmware)]), 0)
            fake_ida.write_text(
                "\n".join(
                    [
                        "#!/usr/bin/env python3",
                        "import json",
                        "import pathlib",
                        "import sys",
                        "output = None",
                        "for arg in sys.argv:",
                        "    if arg.startswith('-S'):",
                        "        output = pathlib.Path(arg[2:].split(' ', 1)[1])",
                        "if output is None:",
                        "    raise SystemExit(2)",
                        "output.parent.mkdir(parents=True, exist_ok=True)",
                        "output.write_text(json.dumps({",
                        "  'language_id': 'ARM:LE:32:Cortex',",
                        "  'entry_points': ['0x08000400'],",
                        "  'functions': [{'name': 'ida_reset', 'entry_point': '0x08000400'}],",
                        "  'strings': [{'address': '0x08000500', 'value': 'IDA UART'}],",
                        "  'mmio_references': [{'address': '0x40011800'}],",
                        "  'mmio_xrefs': [],",
                        "}), encoding='utf-8')",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            fake_ida.chmod(0o755)

            self.assertEqual(
                main(
                    [
                        "extract",
                        str(firmware),
                        "--out",
                        str(out),
                        "--analysis-backend",
                        "ida",
                        "--ida-headless",
                        str(fake_ida),
                    ]
                ),
                0,
            )
            context = json.loads((out / "context.json").read_text(encoding="utf-8"))
            self.assertEqual(context["tool_observations"]["analysis_backend"], "ida")
            self.assertEqual(context["tool_observations"]["ida"]["status"], "completed")
            self.assertEqual(context["architecture_hint"], "arm-cortex-m")
            self.assertIn("IDA UART", context["strings"])
            self.assertIn("0x40011800", context["mmio_addresses"])

    def test_extract_ghidra_backend_falls_back_when_headless_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "demo.bin"
            out = tmp_path / "ghidra-missing"

            self.assertEqual(main(["init-sample", "--out", str(firmware)]), 0)
            self.assertEqual(
                main(
                    [
                        "extract",
                        str(firmware),
                        "--out",
                        str(out),
                        "--analysis-backend",
                        "ghidra",
                        "--ghidra-headless",
                        str(tmp_path / "missing-analyzeHeadless"),
                    ]
                ),
                0,
            )

            context = json.loads((out / "context.json").read_text(encoding="utf-8"))
            self.assertEqual(context["entry_point"], "0x08000100")
            self.assertIn("0x40011000", context["mmio_addresses"])
            self.assertEqual(context["tool_observations"]["ghidra"]["status"], "skipped")

    def test_architecture_detection_from_tools_and_ghidra(self) -> None:
        self.assertEqual(
            _architecture_from_tools(
                {
                    "tool_results": {
                        "file": {"output": "ELF 32-bit LSB executable, MIPS, MIPS32 rel2"}
                    }
                }
            ),
            "mips",
        )
        self.assertEqual(
            _architecture_from_tools(
                {"tool_results": {"readelf": {"output": "Machine: RISC-V"}}}
            ),
            "riscv",
        )
        self.assertEqual(
            _architecture_from_tools(
                {
                    "tool_results": {
                        "file": {"output": "ELF 32-bit LSB executable, ARM, EABI5 version 1"}
                    }
                }
            ),
            "arm-linux",
        )
        self.assertEqual(
            _architecture_from_ghidra({"language_id": "ARM:LE:32:Cortex"}),
            "arm-cortex-m",
        )
        self.assertEqual(
            _architecture_from_ghidra({"language_id": "ARM:LE:32:v7"}),
            "arm-linux",
        )
        self.assertEqual(
            _architecture_from_ghidra({"language_id": "Xtensa:LE:32:default"}),
            "xtensa",
        )

    def test_binwalk_segments_are_structured_and_excluded_from_mmio_scan(self) -> None:
        output = """
DECIMAL                            HEXADECIMAL                        DESCRIPTION
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
56                                 0x38                               Device tree blob (DTB), version: 17, CPU ID: 0, total size: 16 bytes
128                                0x80                               SquashFS file system, little endian, version: 4.0, compression: xz, inode count: 1, block size: 262144, image size: 32 bytes
"""
        segments = _parse_binwalk_segments(output, file_size=256)

        self.assertEqual(len(segments), 2)
        self.assertEqual(segments[0]["kind"], "metadata")
        self.assertEqual(segments[0]["end_offset"], 72)
        self.assertEqual(segments[1]["kind"], "filesystem")
        self.assertEqual(segments[1]["size_bytes"], 32)

        data = bytearray(192)
        data[0:4] = (0x40021018).to_bytes(4, "little")
        data[128:132] = (0x40011000).to_bytes(4, "little")

        excluded = _non_code_ranges(segments, file_size=len(data))
        self.assertEqual(_extract_mmio_addresses(bytes(data), excluded_ranges=excluded), ["0x40021018"])

    def test_input_loader_distinguishes_raw_elf_ihex_and_srec(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            raw = tmp_path / "firmware.bin"
            elf = tmp_path / "firmware.elf"
            ihex = tmp_path / "firmware.hex"
            srec = tmp_path / "firmware.srec"
            vector = bytes.fromhex("0020002001010008")

            raw.write_bytes(vector)
            elf.write_bytes(b"\x7fELF" + b"\x00" * 12)
            ihex.write_text(
                "\n".join(
                    [
                        _ihex_record(0x0000, 0x04, bytes.fromhex("0800")),
                        _ihex_record(0x0000, 0x00, vector),
                        _ihex_record(0x0000, 0x05, bytes.fromhex("08000100")),
                        _ihex_record(0x0000, 0x01, b""),
                    ]
                )
                + "\n",
                encoding="ascii",
            )
            srec.write_text(
                "\n".join(
                    [
                        _srec_record("3", 0x08000000, vector),
                        _srec_record("7", 0x08000100, b""),
                    ]
                )
                + "\n",
                encoding="ascii",
            )

            self.assertEqual(_load_firmware_image(raw).input_format, "raw-binary")
            self.assertEqual(_load_firmware_image(elf).input_format, "elf")
            ihex_image = _load_firmware_image(ihex)
            srec_image = _load_firmware_image(srec)
            self.assertEqual(ihex_image.input_format, "intel-hex")
            self.assertEqual(ihex_image.load_address, 0x08000000)
            self.assertEqual(ihex_image.entry_point, 0x08000100)
            self.assertEqual(ihex_image.data[:8], vector)
            self.assertEqual(srec_image.input_format, "motorola-s-record")
            self.assertEqual(srec_image.load_address, 0x08000000)
            self.assertEqual(srec_image.entry_point, 0x08000100)
            self.assertEqual(srec_image.data[:8], vector)

    def test_extract_intel_hex_records_loaded_image_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "firmware.hex"
            out = tmp_path / "hex-run"
            vector = bytes.fromhex("0020002001010008")
            firmware.write_text(
                "\n".join(
                    [
                        _ihex_record(0x0000, 0x04, bytes.fromhex("0800")),
                        _ihex_record(0x0000, 0x00, vector + b"USART1"),
                        _ihex_record(0x0000, 0x01, b""),
                    ]
                )
                + "\n",
                encoding="ascii",
            )

            self.assertEqual(main(["extract", str(firmware), "--out", str(out)]), 0)

            context = json.loads((out / "context.json").read_text(encoding="utf-8"))
            self.assertEqual(context["input_format"], "intel-hex")
            self.assertEqual(context["loaded_base_address"], "0x08000000")
            self.assertEqual(context["entry_point"], "0x08000100")
            self.assertEqual(context["architecture_hint"], "arm-cortex-m")
            self.assertIn("USART1", context["strings"])

    def test_cortex_m_vector_table_is_structured(self) -> None:
        vector = bytearray()
        vector += (0x20002000).to_bytes(4, "little")
        vector += (0x08000101).to_bytes(4, "little")
        vector += (0x08000201).to_bytes(4, "little")
        vector += (0).to_bytes(4, "little")

        table = _parse_cortex_m_vector_table(bytes(vector), 0x08000000, max_vectors=4)

        self.assertIsNotNone(table)
        assert table is not None
        self.assertEqual(table["initial_sp"], "0x20002000")
        self.assertEqual(table["base_address"], "0x08000000")
        self.assertEqual(table["reset_handler"]["handler_address"], "0x08000100")
        self.assertEqual(table["vectors"][2]["name"], "nmi_handler")
        self.assertEqual(table["vectors"][2]["handler_address"], "0x08000200")
        self.assertFalse(table["vectors"][3]["enabled"])

    def test_extract_records_cortex_m_vector_table(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "firmware.bin"
            out = tmp_path / "vector-run"

            firmware.write_bytes(
                b"".join(
                    [
                        (0x20001000).to_bytes(4, "little"),
                        (0x08000101).to_bytes(4, "little"),
                        (0x08000201).to_bytes(4, "little"),
                        (0).to_bytes(4, "little"),
                    ]
                )
                + b"STM32F1"
            )

            self.assertEqual(main(["extract", str(firmware), "--out", str(out)]), 0)

            context = json.loads((out / "context.json").read_text(encoding="utf-8"))
            self.assertEqual(context["entry_point"], "0x08000100")
            self.assertEqual(context["vector_table"]["initial_sp"], "0x20001000")
            self.assertEqual(
                context["vector_table"]["reset_handler"]["handler_address"],
                "0x08000100",
            )
            self.assertEqual(context["vector_table"]["vectors"][2]["name"], "nmi_handler")

    def test_entropy_windows_are_recorded(self) -> None:
        data = bytes([0] * 16 + list(range(16)))

        windows = _entropy_windows(data, window_size=16)

        self.assertEqual(len(windows), 2)
        self.assertEqual(windows[0]["hex_offset"], "0x0")
        self.assertEqual(windows[0]["entropy"], 0.0)
        self.assertGreater(windows[1]["entropy"], 3.0)

    def test_extract_records_entropy_windows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "firmware.bin"
            out = tmp_path / "entropy-run"
            firmware.write_bytes(bytes(range(256)) * 20)

            self.assertEqual(main(["extract", str(firmware), "--out", str(out)]), 0)

            context = json.loads((out / "context.json").read_text(encoding="utf-8"))
            self.assertGreaterEqual(len(context["entropy_windows"]), 1)
            self.assertIn("entropy", context["entropy_windows"][0])

    def test_compressed_or_encrypted_ranges_use_binwalk_and_entropy(self) -> None:
        ranges = _compressed_or_encrypted_ranges(
            [
                {
                    "offset": 0,
                    "hex_offset": "0x0",
                    "size_bytes": 4096,
                    "entropy": 7.9,
                    "high_entropy": True,
                }
            ],
            [
                {
                    "offset": 8192,
                    "end_offset": 12288,
                    "kind": "filesystem",
                    "description": "SquashFS file system",
                }
            ],
        )

        self.assertEqual({item["source"] for item in ranges}, {"binwalk", "entropy-window"})
        self.assertTrue(any(item["kind"] == "filesystem" for item in ranges))
        self.assertTrue(any(item["kind"] == "high-entropy" for item in ranges))

    def test_string_ranges_are_excluded_from_mmio_scan(self) -> None:
        data = b"AAAA" + (0x40011000).to_bytes(4, "little") + b"USART_STRING"
        string_ranges = _extract_string_ranges(data)

        self.assertEqual(string_ranges[0]["hex_offset"], "0x0")
        self.assertIn("USART_STRING", string_ranges[-1]["preview"])
        self.assertEqual(
            _extract_mmio_addresses(data, excluded_ranges=[(8, len(data))]),
            ["0x40011000"],
        )
        self.assertEqual(
            _extract_mmio_addresses(data, excluded_ranges=[(4, 8), (8, len(data))]),
            [],
        )

    def test_extract_records_string_ranges_and_mmio_scan_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "firmware.bin"
            out = tmp_path / "string-ranges"
            firmware.write_bytes(
                (0x20001000).to_bytes(4, "little")
                + (0x08000101).to_bytes(4, "little")
                + b"STRING_LITERAL"
                + (0x40011000).to_bytes(4, "little")
            )

            self.assertEqual(main(["extract", str(firmware), "--out", str(out)]), 0)

            context = json.loads((out / "context.json").read_text(encoding="utf-8"))
            self.assertTrue(context["string_ranges"])
            self.assertGreaterEqual(
                context["tool_observations"]["mmio_scan"]["excluded_string_ranges"],
                1,
            )

    def test_ghidra_target_prefers_embedded_executable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "firmware.bin"
            library = tmp_path / "libexample.so"
            executable = tmp_path / "service.cgi"
            firmware.write_bytes(b"container")
            library.write_bytes(b"lib")
            executable.write_bytes(b"elf")

            target = _select_ghidra_target(
                firmware,
                [
                    {"path": str(library), "kind": "shared-library", "size_bytes": 1000},
                    {"path": str(executable), "kind": "executable", "size_bytes": 10},
                ],
            )

            self.assertEqual(target, executable)

    def test_embedded_target_score_prioritizes_router_web_paths(self) -> None:
        openvpn = {
            "relative_path": "sbin/openvpn",
            "kind": "executable",
            "size_bytes": 729660,
            "file_type": "ELF 32-bit LSB executable, MIPS, stripped",
        }
        firmware_cgi = {
            "relative_path": "home/httpd/cgi/firmware.cgi",
            "kind": "executable",
            "size_bytes": 42000,
            "file_type": "ELF 32-bit LSB executable, MIPS, stripped",
        }

        openvpn_score, _ = _score_embedded_file(openvpn)
        firmware_score, reasons = _score_embedded_file(firmware_cgi)

        self.assertGreater(firmware_score, openvpn_score)
        self.assertIn("path:cgi+800", reasons)
        self.assertIn("keyword:firmware+300", reasons)

    def test_ghidra_target_can_be_selected_by_path_or_pattern(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "firmware.bin"
            openvpn = tmp_path / "openvpn"
            firmware_cgi = tmp_path / "firmware.cgi"
            firmware.write_bytes(b"container")
            openvpn.write_bytes(b"elf")
            firmware_cgi.write_bytes(b"elf")
            embedded = [
                {
                    "path": str(openvpn),
                    "relative_path": "sbin/openvpn",
                    "kind": "executable",
                    "size_bytes": 729660,
                    "score": 1200,
                },
                {
                    "path": str(firmware_cgi),
                    "relative_path": "home/httpd/cgi/firmware.cgi",
                    "kind": "executable",
                    "size_bytes": 42000,
                    "score": 2800,
                },
            ]

            by_target = _select_ghidra_target_details(
                firmware,
                embedded,
                target="sbin/openvpn",
            )
            by_pattern = _select_ghidra_target_details(
                firmware,
                embedded,
                pattern="*firmware*|*.cgi",
            )

            self.assertEqual(Path(str(by_target["path"])), openvpn)
            self.assertEqual(by_target["mode"], "target")
            self.assertEqual(Path(str(by_pattern["path"])), firmware_cgi)
            self.assertEqual(by_pattern["mode"], "pattern")

    def test_vulnerability_candidates_correlate_web_upload_file_write_flow(self) -> None:
        candidates = _vulnerability_candidates_from_ghidra(
            {
                "call_graph": [
                    {"caller": "handle_upload", "caller_entry": "0x1000", "callee": "getenv"},
                    {"caller": "handle_upload", "caller_entry": "0x1000", "callee": "atoi"},
                    {"caller": "handle_upload", "caller_entry": "0x1000", "callee": "fopen"},
                    {"caller": "handle_upload", "caller_entry": "0x1000", "callee": "fwrite"},
                    {"caller": "main", "caller_entry": "0x0800", "callee": "check_csrf_attack"},
                ],
                "string_references": [
                    {
                        "from_function": "handle_upload",
                        "from_address": "0x1010",
                        "string_value": "CONTENT_LENGTH",
                    },
                    {
                        "from_function": "handle_upload",
                        "from_address": "0x1020",
                        "string_value": "/tmp/firmware",
                    },
                    {
                        "from_function": "handle_upload",
                        "from_address": "0x1030",
                        "string_value": "firmware/upgrade",
                    },
                ],
                "strings": [],
            }
        )

        categories = {item["category"] for item in candidates}
        self.assertIn("web_upload_file_write_flow", categories)
        self.assertIn("web_input_string", categories)
        self.assertIn("temporary_file_path", categories)
        self.assertIn("security_control", categories)

    def test_function_contexts_include_decompiled_flow_evidence(self) -> None:
        analysis = {
            "interesting_functions": [
                {
                    "name": "handle_upload",
                    "entry_point": "0x1000",
                    "reasons": ["calls getenv", "calls fwrite"],
                    "disassembly": [{"address": "0x1000", "text": "jal getenv"}],
                    "decompiled": "\n".join(
                        [
                            "int handle_upload(void) {",
                            '  len = getenv("CONTENT_LENGTH");',
                            '  out = fopen("/tmp/firmware", "wb");',
                            "  fwrite(buf, 1, len, out);",
                            "}",
                        ]
                    ),
                }
            ],
        }
        candidates = [
            {
                "category": "web_upload_file_write_flow",
                "risk": "high",
                "function": "handle_upload",
                "evidence": ["same function handles CGI/web input and filesystem write signals"],
            },
            {
                "category": "file_write",
                "risk": "medium",
                "function": "handle_upload",
                "symbol": "fwrite",
                "evidence": ["handle_upload calls fwrite"],
            },
        ]

        contexts = _function_contexts_from_ghidra(analysis, candidates)

        self.assertEqual(contexts[0]["review_priority"], "high")
        self.assertIn("web_input_to_file_write", contexts[0]["flow_signals"])
        self.assertGreaterEqual(contexts[0]["candidate_count"], 2)
        snippet_text = " ".join(item["text"] for item in contexts[0]["evidence_snippets"])
        self.assertIn("CONTENT_LENGTH", snippet_text)
        self.assertIn("fwrite", snippet_text)

    def test_stub_emulation_captures_unmapped_mmio(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "demo.bin"
            out = tmp_path / "run"

            self.assertEqual(main(["init-sample", "--out", str(firmware)]), 0)
            self.assertEqual(
                main(["analyze", str(firmware), "--device", "stm32f1", "--out", str(out)]),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "emulate",
                        str(out / "emulator_config.json"),
                        "--out",
                        str(out),
                        "--probe-address",
                        "0x50000000",
                        "--access",
                        "write",
                        "--pc",
                        "0x08000120",
                    ]
                ),
                1,
            )

            result = json.loads((out / "emulation_result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "crashed")
            self.assertEqual(result["crash"]["pc"], "0x08000120")
            self.assertEqual(result["crash"]["address"], "0x50000000")
            self.assertEqual(result["crash"]["proposed_patch"]["type"], "MMIO")

    def test_feedback_loop_patches_unmapped_mmio(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "demo.bin"
            run_dir = tmp_path / "run"
            loop_dir = tmp_path / "loop"

            self.assertEqual(main(["init-sample", "--out", str(firmware)]), 0)
            self.assertEqual(
                main(["analyze", str(firmware), "--device", "stm32f1", "--out", str(run_dir)]),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "loop",
                        str(run_dir / "emulator_config.json"),
                        "--out",
                        str(loop_dir),
                        "--probe-address",
                        "0x50000000",
                        "--access",
                        "write",
                        "--pc",
                        "0x08000120",
                        "--max-iterations",
                        "3",
                    ]
                ),
                0,
            )

            summary = json.loads((loop_dir / "loop_summary.json").read_text(encoding="utf-8"))
            config = json.loads((loop_dir / "emulator_config.loop.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["status"], "completed")
            self.assertEqual(summary["backend"], "stub")
            self.assertEqual(len(summary["iterations"]), 2)
            self.assertTrue(summary["iterations"][0]["patch_applied"])
            self.assertTrue(
                any(mapping["base"] == "0x50000000" for mapping in config["mappings"])
            )
            report = (loop_dir / "report.md").read_text(encoding="utf-8")
            self.assertIn("## Feedback Loop", report)
            self.assertIn("Iteration 1", report)
            self.assertIn("Final config", report)
            self.assertEqual(main(["validate", str(loop_dir)]), 0)

    def test_report_command_regenerates_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "demo.bin"
            out = tmp_path / "run"

            self.assertEqual(main(["init-sample", "--out", str(firmware)]), 0)
            self.assertEqual(
                main(
                    [
                        "run",
                        str(firmware),
                        "--device",
                        "stm32f1",
                        "--out",
                        str(out),
                        "--probe-address",
                        "0x40011000",
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(["report", str(out), "--source-command", "pytest report test"]),
                0,
            )

            report = (out / "report.md").read_text(encoding="utf-8")
            self.assertIn("Tool version", report)
            self.assertIn("Command: `pytest report test`", report)
            self.assertIn("## Emulation", report)
            self.assertIn("USART1", report)

    def test_qiling_backend_returns_actionable_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            firmware = tmp_path / "demo.bin"
            out = tmp_path / "run"

            self.assertEqual(main(["init-sample", "--out", str(firmware)]), 0)
            self.assertEqual(
                main(["analyze", str(firmware), "--device", "stm32f1", "--out", str(out)]),
                0,
            )

            output = StringIO()
            with redirect_stdout(output):
                code = main(
                    [
                        "emulate",
                        str(out / "emulator_config.json"),
                        "--out",
                        str(out),
                        "--backend",
                        "qiling",
                        "--instruction-limit",
                        "1",
                    ]
                )
            if importlib.util.find_spec("qiling") is None:
                self.assertEqual(code, 2)
                self.assertIn("qiling backend requested", output.getvalue())
            else:
                self.assertIn(code, {0, 1, 2})


if __name__ == "__main__":
    unittest.main()
