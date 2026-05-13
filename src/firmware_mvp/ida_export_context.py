# ruff: noqa: F821
# IDAPython script used by firmware_mvp. It is executed with:
# idat64 -A -S"ida_export_context.py <output.json>" <firmware>

import json

import idaapi
import idautils
import idc


MMIO_RANGES = ((0x40000000, 0x5FFFFFFF), (0xE0000000, 0xE00FFFFF))


def is_mmio(value):
    return any(start <= value <= end for start, end in MMIO_RANGES)


def hex_addr(value):
    return "0x%08X" % int(value)


def collect_functions():
    values = []
    for ea in idautils.Functions():
        values.append({"name": idc.get_func_name(ea), "entry_point": hex_addr(ea)})
    return values[:2000]


def collect_strings():
    values = []
    for item in idautils.Strings():
        text = str(item)
        if text:
            values.append({"address": hex_addr(item.ea), "value": text})
    return values[:2000]


def collect_mmio_references():
    values = []
    seen = set()
    for _seg_ea in idautils.Segments():
        for head in idautils.Heads():
            for operand_index in range(2):
                value = idc.get_operand_value(head, operand_index)
                if value and is_mmio(value) and value not in seen:
                    seen.add(value)
                    values.append(
                        {
                            "address": hex_addr(value),
                            "instruction_address": hex_addr(head),
                            "mnemonic": idc.print_insn_mnem(head),
                        }
                    )
    return values[:2000]


def main():
    output = idc.ARGV[1]
    info = idaapi.get_inf_structure()
    payload = {
        "tool": "ida",
        "processor": info.procname,
        "entry_points": [hex_addr(ea) for _ordinal, ea, _name in idautils.Entries()],
        "functions": collect_functions(),
        "call_graph": [],
        "strings": collect_strings(),
        "string_references": [],
        "mmio_references": collect_mmio_references(),
        "mmio_xrefs": [],
        "reset_handler_candidates": [],
        "interesting_functions": [],
    }
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    idc.qexit(0)


main()
