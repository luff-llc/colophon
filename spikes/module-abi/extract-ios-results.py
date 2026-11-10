#!/usr/bin/env python3
"""Export release-mode iOS Simulator XCTest JSON from the exact xcodebuild log.

The Simulator's app sandbox temp files cannot be uploaded directly by Actions;
the XCTest log emits one JSON marker per test measurement and fuel probe.
Reject missing, malformed, Debug-config, or unsuccessful test results.
"""
import json
from pathlib import Path
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: extract-ios-results.py ios-simulator-release.log OUT_DIRECTORY")
log = Path(sys.argv[1]).read_text(errors="replace")
out = Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)

if "** TEST SUCCEEDED **" not in log:
    raise SystemExit("xcodebuild never reported TEST SUCCEEDED")
if "Release-iphonesimulator" not in log:
    raise SystemExit("expected Release-iphonesimulator build output; may be Debug")

results = {}
meter = []
for line in log.splitlines():
    if "SIMULATOR MEASUREMENT " in line:
        obj = json.loads(line.split("SIMULATOR MEASUREMENT ", 1)[1].strip())
        count = obj.get("operations")
        if count in results:
            raise SystemExit(f"duplicate simulator measurement {count}")
        results[count] = obj
    elif "SIMULATOR METER " in line:
        meter.append(json.loads(line.split("SIMULATOR METER ", 1)[1].strip()))

if set(results) != {1, 1_000, 10_000} or len(meter) != 1:
    raise SystemExit(f"incomplete simulator outputs: {list(results)}, meter={len(meter)}")

for count, measurement in sorted(results.items()):
    if measurement.get("byte_equal") is not True:
        raise SystemExit(f"byte mismatch at {count}")
    if measurement.get("build_configuration") != "release":
        raise SystemExit(f"not release mode at {count}: {measurement.get('build_configuration')}")
    (out / f"ios-release-{count}.json").write_text(
        json.dumps(measurement, indent=2, sort_keys=True) + "\n"
    )
fuel = meter[0]
if fuel.get("passed") is not True or fuel.get("failed_budget") + 1 != fuel.get("min_success_budget"):
    raise SystemExit(f"nonadjacent simulator fuel boundary: {fuel}")
(out / "ios-release-meter.json").write_text(json.dumps(fuel, indent=2, sort_keys=True) + "\n")
print("Exported VERIFIED release-mode iOS Simulator measurements and metering.")
