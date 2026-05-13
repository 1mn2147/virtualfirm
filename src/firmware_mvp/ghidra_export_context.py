# ruff: noqa: F821
# Ghidra Jython script used by firmware_mvp. It is executed with:
# analyzeHeadless <project_dir> <project_name> -import <firmware> -postScript ghidra_export_context.py <output.json>

from java.io import File, PrintWriter

try:
    from ghidra.app.decompiler import DecompInterface
except Exception:
    DecompInterface = None

try:
    long
except NameError:
    long = int


MMIO_RANGES = ((0x40000000, 0x5FFFFFFF), (0xE0000000, 0xE00FFFFF))
INTERESTING_CALLEES = (
    "system",
    "popen",
    "execl",
    "execv",
    "sprintf",
    "strcpy",
    "strcat",
    "gets",
    "memcpy",
    "snprintf",
    "strncpy",
    "sf_strncpy",
    "fopen",
    "fwrite",
    "fread",
    "remove",
    "unlink",
    "rename",
    "getenv",
    "atoi",
    "malloc",
    "httpcon_auth",
    "check_csrf_attack",
)
INTERESTING_STRING_MARKERS = (
    "CONTENT_LENGTH",
    "CONTENT_TYPE",
    "QUERY_STRING",
    "REQUEST_METHOD",
    "HTTP_",
    "multipart/form-data",
    "boundary",
    "firmware",
    "upgrade",
    "/tmp/",
    "password",
    "passwd",
    "token",
    "secret",
    "auth",
    "login",
)


def is_mmio(value):
    for start, end in MMIO_RANGES:
        if start <= value <= end:
            return True
    return False


def quote(value):
    if value is None:
        return "null"
    text = str(value)
    text = text.replace("\\", "\\\\").replace('"', '\\"')
    text = text.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return '"' + text + '"'


def dump_json(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, long, float)):
        return str(value)
    if isinstance(value, dict):
        parts = []
        for key in sorted(value.keys()):
            parts.append(quote(key) + ":" + dump_json(value[key]))
        return "{" + ",".join(parts) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(dump_json(item) for item in value) + "]"
    return quote(value)


def hex_addr(address):
    return "0x%08X" % int(address.getOffset())


def collect_functions():
    functions = []
    manager = currentProgram.getFunctionManager()
    for function in manager.getFunctions(True):
        body = function.getBody()
        functions.append(
            {
                "name": function.getName(),
                "entry_point": hex_addr(function.getEntryPoint()),
                "body_min": hex_addr(body.getMinAddress()) if body else None,
                "body_max": hex_addr(body.getMaxAddress()) if body else None,
            }
        )
    return functions[:2000]


def function_name_at(address):
    try:
        function = currentProgram.getFunctionManager().getFunctionContaining(address)
        if function:
            return function.getName()
    except Exception:
        pass
    return None


def collect_call_graph():
    edges = []
    manager = currentProgram.getFunctionManager()
    for function in manager.getFunctions(True):
        try:
            called = function.getCalledFunctions(monitor)
        except Exception:
            called = []
        for target in called:
            edges.append(
                {
                    "caller": function.getName(),
                    "caller_entry": hex_addr(function.getEntryPoint()),
                    "callee": target.getName(),
                    "callee_entry": hex_addr(target.getEntryPoint()),
                }
            )
    return edges[:5000]


def collect_strings():
    strings = []
    listing = currentProgram.getListing()
    for data in listing.getDefinedData(True):
        try:
            if data.hasStringValue():
                text = str(data.getValue()).strip()
                if text:
                    strings.append(
                        {
                            "address": hex_addr(data.getAddress()),
                            "value": text,
                        }
                    )
        except Exception:
            pass
    return strings[:2000]


def collect_string_references():
    references = []
    listing = currentProgram.getListing()
    reference_manager = currentProgram.getReferenceManager()
    for data in listing.getDefinedData(True):
        try:
            if not data.hasStringValue():
                continue
            text = str(data.getValue()).strip()
            if not text:
                continue
            iterator = reference_manager.getReferencesTo(data.getAddress())
            for ref in iterator:
                from_address = ref.getFromAddress()
                references.append(
                    {
                        "string_address": hex_addr(data.getAddress()),
                        "string_value": text,
                        "from_address": hex_addr(from_address),
                        "from_function": function_name_at(from_address),
                        "reference_type": str(ref.getReferenceType()),
                    }
                )
        except Exception:
            pass
    return references[:5000]


def collect_mmio_references(xrefs):
    refs = {}
    for item in xrefs:
        key = item["address"]
        if key not in refs:
            refs[key] = {
                "address": key,
                "instruction_address": item["instruction_address"],
                "mnemonic": item["mnemonic"],
            }
    return [refs[key] for key in sorted(refs.keys())][:2000]


def collect_mmio_xrefs():
    refs = []
    listing = currentProgram.getListing()
    for instruction in listing.getInstructions(True):
        for index in range(instruction.getNumOperands()):
            try:
                objects = instruction.getOpObjects(index)
            except Exception:
                objects = []
            for obj in objects:
                try:
                    value = int(obj.getValue())
                except Exception:
                    continue
                if is_mmio(value):
                    refs.append(
                        {
                            "address": "0x%08X" % value,
                            "instruction_address": hex_addr(instruction.getAddress()),
                            "function": function_name_at(instruction.getAddress()),
                            "mnemonic": instruction.getMnemonicString(),
                            "operand_index": index,
                        }
                    )
    return refs[:5000]


def collect_disassembly(function, limit):
    lines = []
    listing = currentProgram.getListing()
    try:
        instructions = listing.getInstructions(function.getBody(), True)
    except Exception:
        return lines
    count = 0
    for instruction in instructions:
        lines.append(
            {
                "address": hex_addr(instruction.getAddress()),
                "text": str(instruction),
            }
        )
        count += 1
        if count >= limit:
            break
    return lines


def collect_reset_handler_candidates():
    candidates = []
    manager = currentProgram.getFunctionManager()
    seen = {}
    for function in manager.getFunctions(True):
        name = function.getName().lower()
        if "reset" in name or name in ("entry", "_entry", "start", "_start"):
            seen[hex_addr(function.getEntryPoint())] = function
    for entry in collect_entry_points():
        try:
            address = toAddr(entry)
            function = manager.getFunctionContaining(address)
            if function:
                seen[hex_addr(function.getEntryPoint())] = function
        except Exception:
            pass
    for entry in sorted(seen.keys()):
        function = seen[entry]
        candidates.append(
            {
                "name": function.getName(),
                "entry_point": entry,
                "disassembly": collect_disassembly(function, 80),
            }
        )
    return candidates[:20]


def decompile_function(function):
    if DecompInterface is None:
        return None
    interface = None
    try:
        interface = DecompInterface()
        interface.openProgram(currentProgram)
        result = interface.decompileFunction(function, 10, monitor)
        if result and result.decompileCompleted():
            decompiled = result.getDecompiledFunction()
            if decompiled:
                text = str(decompiled.getC())
                return text[:8000]
    except Exception as exc:
        return "decompile failed: " + str(exc)
    finally:
        try:
            if interface:
                interface.dispose()
        except Exception:
            pass
    return None


def collect_interesting_functions(call_graph, string_references):
    manager = currentProgram.getFunctionManager()
    seen = {}
    for edge in call_graph:
        callee = str(edge.get("callee", ""))
        caller = str(edge.get("caller", ""))
        if not caller:
            continue
        if callee in INTERESTING_CALLEES:
            seen.setdefault(caller, set()).add("calls " + callee)
    for ref in string_references:
        function = ref.get("from_function")
        if not function:
            continue
        value = str(ref.get("string_value", ""))
        lower = value.lower()
        for marker in INTERESTING_STRING_MARKERS:
            if marker in value or marker.lower() in lower:
                seen.setdefault(function, set()).add("references " + value)
                break

    contexts = []
    for function in manager.getFunctions(True):
        name = function.getName()
        if name not in seen:
            continue
        contexts.append(
            {
                "name": name,
                "entry_point": hex_addr(function.getEntryPoint()),
                "reasons": sorted(seen.get(name, [])),
                "disassembly": collect_disassembly(function, 120),
                "decompiled": decompile_function(function),
            }
        )
        if len(contexts) >= 15:
            break
    return contexts


def collect_entry_points():
    values = []
    try:
        iterator = currentProgram.getSymbolTable().getExternalEntryPointIterator()
        while iterator.hasNext():
            values.append(hex_addr(iterator.next()))
    except Exception:
        pass
    return values[:200]


args = getScriptArgs()
if len(args) < 1:
    raise Exception("output JSON path argument is required")

mmio_xrefs = collect_mmio_xrefs()
call_graph = collect_call_graph()
string_references = collect_string_references()
payload = {
    "program_name": currentProgram.getName(),
    "image_base": hex_addr(currentProgram.getImageBase()),
    "language_id": str(currentProgram.getLanguageID()),
    "compiler_spec_id": str(currentProgram.getCompilerSpec().getCompilerSpecID()),
    "entry_points": collect_entry_points(),
    "functions": collect_functions(),
    "call_graph": call_graph,
    "strings": collect_strings(),
    "string_references": string_references,
    "mmio_references": collect_mmio_references(mmio_xrefs),
    "mmio_xrefs": mmio_xrefs,
    "reset_handler_candidates": collect_reset_handler_candidates(),
    "interesting_functions": collect_interesting_functions(call_graph, string_references),
}

writer = PrintWriter(File(args[0]), "UTF-8")
try:
    # Ghidra 12 PyGhidra runs this script under CPython/JPype, where Java
    # methods named like Python keywords are exposed with a trailing underscore.
    if hasattr(writer, "print_"):
        writer.print_(dump_json(payload))
    else:
        writer.print(dump_json(payload))
finally:
    writer.close()
