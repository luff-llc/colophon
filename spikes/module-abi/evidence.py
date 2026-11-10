#!/usr/bin/env python3
"""Verify archived, PUBLIC spike evidence without reinterpreting the module ABI.

All provenance refers to the exact built .wasm bytes, not source revision alone.
Not a security audit, deterministic gas proof, or release approval.
Uses only Python 3 standard library. Run from either CI OS.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys

OUT = Path(__file__).resolve().parent / "out"
COUNTS = (1, 1_000, 10_000)
BLOBS = (
    "notes.wasm", "notes-metered.wasm", "initial.json", "operations.jsonl",
    *(f"expected-{n}.json" for n in COUNTS),
    *(f"expected-query-{n}.json" for n in COUNTS),
)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(name: str) -> dict:
    return json.loads((OUT / name).read_text())


def write(name: str, value: dict) -> None:
    (OUT / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def required(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


def record() -> None:
    for name in BLOBS:
        required((OUT / name).is_file(), f"missing {name}")
    provenance = {
        "ci_source_commit": os.environ.get("GITHUB_SHA", "manual"),
        "bytes": {
            name: {"sha256": sha(OUT / name), "size": (OUT / name).stat().st_size}
            for name in BLOBS
        },
        "purpose": "same-byte inputs for native/Bun/Chromium/WasmKit; not a release",
        "tool_versions_file": "tool-versions-linux.txt",
    }
    write("binary-provenance.json", provenance)
    verify()


def verify() -> dict:
    manifest = read("binary-provenance.json")
    for name, meta in manifest["bytes"].items():
        path = OUT / name
        required(path.exists(), f"binary-provenance missing {name}")
        required(path.stat().st_size == meta["size"], f"{name} length mismatch")
        required(sha(path) == meta["sha256"], f"{name} SHA-256 mismatch")
    original = read("wasm-audit.json")
    metered = read("wasm-metered-audit.json")
    for name, audit in (("notes.wasm", original), ("notes-metered.wasm", metered)):
        required(audit["imports"] == 0, f"{name} imports present")
        required(audit["module_bytes"] == manifest["bytes"][name]["size"], f"{name} audit size mismatch")
        required(any(" 1024)" in decl for decl in audit["memory_declarations"]), f"{name} missing 64MiB declared limit")
    required(original["float_opcode_count"] == metered["float_opcode_count"], "instrumenter unexpectedly changes float count")
    print("Verified binary input digests:",
          manifest["bytes"]["notes.wasm"]["sha256"],
          manifest["bytes"]["notes-metered.wasm"]["sha256"])
    return manifest


def result(name: str, expected_module: str | None, expected_count: int | None = None) -> dict:
    r = read(name)
    required(r.get("byte_equal") is True, f"{name}: bytes not equal")
    if expected_count is not None:
        required(r.get("operations") == expected_count, f"{name}: count mismatch")
    if expected_module is not None:
        required(r.get("wasm_sha256") == expected_module, f"{name}: binary digest mismatch")
    return r


def fuel(name: str, expected_module: str | None) -> dict:
    r = read(name)
    required(r.get("passed") is True, f"{name}: failed probe")
    p, f = r.get("min_success_budget"), r.get("failed_budget")
    required(isinstance(p, int) and isinstance(f, int) and p == f + 1, f"{name}: nonadjacent fuel boundary")
    if expected_module is not None:
        required(r.get("wasm_sha256") == expected_module, f"{name}: metered binary digest mismatch")
    return r


def compare(apple: bool) -> None:
    manifest = verify()
    original = manifest["bytes"]["notes.wasm"]["sha256"]
    metered = manifest["bytes"]["notes-metered.wasm"]["sha256"]
    for n in COUNTS:
        for host in ("bun", "browser"):
            result(f"{host}-{n}.json", None, n)
    fuels = {host: fuel(f"{host}-meter.json", None)
             for host in ("bun", "browser")}
    if apple:
        for n in COUNTS:
            for host in ("swift", "ios-release"):
                r = result(f"{host}-{n}.json", original, n)
                required(r.get("build_configuration") == "release",
                         f"{host}-{n}: not built in Swift release mode")
        fuels["wasmkit-macos"] = fuel("swift-meter.json", metered)
        fuels["wasmkit-ios-simulator-release"] = fuel("ios-release-meter.json", metered)
        builtin = fuel("swift-builtin-fuel.json", original)
    else:
        builtin = None
    bounds = {host: (r["failed_budget"], r["min_success_budget"])
              for host, r in fuels.items()}
    required(len(set(bounds.values())) == 1, f"host internal-meter disagreement: {bounds}")
    summary = {
        "ci_source_commit": manifest["ci_source_commit"],
        "original_module_sha256": original,
        "metered_module_sha256": metered,
        "fuel_adjacent_boundaries": bounds,
        "wasmkit_native_fuel_distinct_budget": (
            {"failed": builtin["failed_budget"], "passed": builtin["min_success_budget"]}
            if builtin is not None else None
        ),
        "verified_hosts": (
            ["native-reference", "bun", "chromium-browser", "wasmkit-macos-release",
             "wasmkit-ios-simulator-release"] if apple else
            ["native-reference", "bun", "chromium-browser"]
        ),
        "physical_iphone": "NOT RUN",
        "claim": "byte equality in fixture, adjacent cutoffs for this binary; NOT secure metering",
    }
    write("cross-host-evidence.json" if apple else "linux-evidence.json", summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    try:
        cmd = sys.argv[1] if len(sys.argv) == 2 else None
        if cmd == "record":
            record()
        elif cmd == "verify":
            verify()
        elif cmd == "linux":
            compare(apple=False)
        elif cmd == "all":
            compare(apple=True)
        else:
            raise ValueError("usage: evidence.py {record|verify|linux|all}")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"ABI evidence error: {error}", file=sys.stderr)
        sys.exit(1)
