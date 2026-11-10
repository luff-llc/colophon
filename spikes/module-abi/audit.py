#!/usr/bin/env python3
"""Static audit of a compiled WASM module's imports, memory, float opcodes.
Requires WABT wasm2wat/wasm-objdump (Apache-2.0); no conclusions about
runtime execution can be drawn from static presence alone.
"""
import collections
import json
import pathlib
import re
import subprocess
import sys

def main():
    wasm, output = map(pathlib.Path, sys.argv[1:3])
    wat = subprocess.check_output(["wasm2wat", str(wasm)], text=True)
    # Opcode positions, not type declarations. Both integer conversion
    # instructions mentioning f64 and f32/f64 arithmetic are included.
    float_ops = re.findall(r"(?m)^\s*((?:f32|f64|i32|i64)\.[a-z0-9_]*f(?:32|64)[a-z0-9_]*|f(?:32|64)\.[a-z0-9_]+)\b", wat)
    imports = re.findall(r"(?m)^\s*\(import\s", wat)
    memories = re.findall(r"(?m)^\s*\(memory\s.*", wat)
    result = {
        "file": wasm.name,
        "module_bytes": wasm.stat().st_size,
        "imports": len(imports),
        "memory_declarations": memories,
        "float_opcodes": dict(collections.Counter(float_ops)),
        "float_opcode_count": len(float_ops),
        "audited_by": "WABT wasm2wat text scan"
    }
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    if imports:
        raise SystemExit("WASM must import nothing")

if __name__ == "__main__":
    main()
