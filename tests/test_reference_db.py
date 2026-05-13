from __future__ import annotations

from pathlib import Path
import unittest

from firmware_mvp.inference import infer_peripherals
from firmware_mvp.models import FirmwareContext
from firmware_mvp.reference_db import load_memory_maps, lookup_address


class ReferenceDbTest(unittest.TestCase):
    def test_stm32f1_range_lookup(self) -> None:
        ranges = load_memory_maps(Path("references"), "stm32f103")

        self.assertTrue(ranges)
        usart = lookup_address(0x4001100C, ranges)
        rcc = lookup_address(0x40021018, ranges)

        self.assertIsNotNone(usart)
        self.assertEqual(usart.name, "USART1")
        self.assertEqual(usart.type, "UART")
        self.assertIsNotNone(rcc)
        self.assertEqual(rcc.name, "RCC")

    def test_unknown_device_has_no_structured_ranges(self) -> None:
        self.assertEqual(load_memory_maps(Path("references"), "unknown-mcu"), [])

    def test_additional_reference_maps_cover_common_targets(self) -> None:
        cases = [
            ("stm32f407", 0x40023800, "RCC"),
            ("esp32", 0x3FF40000, "UART0"),
            ("nrf52840", 0x50000000, "GPIO"),
        ]
        for device, address, expected_name in cases:
            with self.subTest(device=device):
                ranges = load_memory_maps(Path("references"), device)
                self.assertTrue(ranges)
                match = lookup_address(address, ranges)
                self.assertIsNotNone(match)
                assert match is not None
                self.assertEqual(match.name, expected_name)

    def test_stm32f1_inference_classifies_addresses_from_memory_map(self) -> None:
        context = FirmwareContext(
            path="fixture.bin",
            size_bytes=16,
            sha256="0" * 64,
            entropy=0.0,
            architecture_hint="arm-cortex-m",
            encrypted_or_compressed_likely=False,
            entry_point="0x08000100",
            strings=[],
            mmio_addresses=["0x40021018", "0x4001100C", "0xE000E010"],
        )
        ranges = load_memory_maps(Path("references"), "stm32f103")

        result = infer_peripherals(context, "stm32f103", [], ranges)
        findings = {item.mmio_address: item for item in result.findings}

        self.assertEqual(findings["0x40021018"].peripheral_name, "RCC")
        self.assertEqual(findings["0x40021018"].type, "RCC")
        self.assertEqual(findings["0x4001100C"].peripheral_name, "USART1")
        self.assertEqual(findings["0x4001100C"].type, "UART")
        self.assertEqual(findings["0xE000E010"].type, "CORE_SYSTEM")


if __name__ == "__main__":
    unittest.main()
