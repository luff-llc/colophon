#!/usr/bin/env python3
"""Checks the public surface of the Swift 0.6 hosts as the compiler sees it.

Reads the symbol graphs `swift package dump-symbol-graph --minimum-access-level public --include-spi-symbols
--emit-extension-block-symbols` wrote, and fails unless:

- no symbol of ColophonHosts (its own graph and any extension graph `ColophonHosts@*`) is SPI, names, takes, returns or
  conforms through the engine (`AccountEngine`, `ColophonEngine`), an endpoint (`SessionEndpoint`), the stream client
  (`HomeStream`), an account view (`SessionAccountView`), or the session's host access, and none is the raw signer,
  the engine or the endpoint by name;
- no symbol ColophonSession itself declares is SPI or is its host access (that is `package`, reachable only from this
  package's targets), and none of its own symbols returns the engine, an endpoint, the stream client or a view;
- no public symbol of ColophonListeningKit (its `now-playing` session included) names the engine, an endpoint, the stream
  client, a view, the host access or the cell host it runs (`SessionCellHost`);
- the public surface of ColophonHosts is exactly the pinned one (swift/Tests/ColophonHostsTests/ColophonHosts.public-api;
  `--update` rewrites it from the graph).
"""
import json
import pathlib
import sys

FORBIDDEN_TYPES = {"AccountEngine", "ColophonEngine", "SessionEndpoint", "HomeStream", "SessionAccountView",
                   "SessionHostAccess", "SessionHostAccount", "HostAccount"}
FORBIDDEN_NAMES = {"signRaw(_:)", "engine()", "streamCall(home:)", "current", "source", "hostAccess", "SessionHostAccess"}


def load(path):
    return json.loads(path.read_text())


def declaration(symbol):
    return " ".join("".join(f["spelling"] for f in symbol.get("declarationFragments", [])).split())


def types_named(symbol):
    names = set()
    for key in ("declarationFragments",):
        for f in symbol.get(key, []):
            if f.get("kind") == "typeIdentifier":
                names.add(f["spelling"])
    for fn in (symbol.get("functionSignature") or {},):
        for part in fn.get("parameters", []) + [{"declarationFragments": fn.get("returns", [])}]:
            for f in part.get("declarationFragments", []):
                if f.get("kind") == "typeIdentifier":
                    names.add(f["spelling"])
    return names


def returns(symbol):
    return {f["spelling"] for f in (symbol.get("functionSignature") or {}).get("returns", []) if f.get("kind") == "typeIdentifier"}


def main():
    graphs = pathlib.Path(sys.argv[1])
    update = "--update" in sys.argv
    root = pathlib.Path(__file__).resolve().parent.parent
    pinned_path = root / "swift/Tests/ColophonHostsTests/ColophonHosts.public-api"
    problems = []

    host_files = [graphs / "ColophonHosts.symbols.json"] + sorted(graphs.glob("ColophonHosts@*.symbols.json"))
    if not host_files[0].exists():
        sys.exit(f"no symbol graph for ColophonHosts in {graphs}")
    surface = []
    by_id = {}
    for path in host_files:
        graph = load(path)
        for s in graph["symbols"]:
            by_id[s["identifier"]["precise"]] = ".".join(s["pathComponents"])
            where = ".".join(s["pathComponents"])
            if s.get("spi"):
                problems.append(f"SPI symbol in ColophonHosts: {where}")
            if s.get("accessLevel") not in ("public", "open"):
                problems.append(f"{s.get('accessLevel')} symbol in the public graph: {where}")
            hit = types_named(s) & FORBIDDEN_TYPES
            if hit:
                problems.append(f"ColophonHosts.{where} exposes {sorted(hit)}: {declaration(s)}")
            if s["pathComponents"][-1] in FORBIDDEN_NAMES:
                problems.append(f"ColophonHosts.{where} is named like a capability: {declaration(s)}")
            surface.append(f"{s['kind']['identifier']} {where}: {declaration(s)}")
        for r in graph.get("relationships", []):
            # The target by name: a symbol of this graph, or another module's (`targetFallback`, `Module.Type`).
            target = by_id.get(r["target"]) or r.get("targetFallback") or r["target"]
            if target.split(".")[-1] in FORBIDDEN_TYPES:
                problems.append(f"ColophonHosts relationship {r['kind']} {by_id.get(r['source'], r['source'])} -> {target}")

    session = load(graphs / "ColophonSession.symbols.json")
    for s in session["symbols"]:
        own = s["identifier"]["precise"].startswith("s:15ColophonSession")
        where = ".".join(s["pathComponents"])
        if s.get("spi"):
            problems.append(f"SPI symbol in ColophonSession: {where}")
        if not own:
            continue
        if s["pathComponents"][-1] in FORBIDDEN_NAMES or "SessionHostAccess" in types_named(s):
            problems.append(f"ColophonSession.{where} exposes the hosts' access: {declaration(s)}")
        hit = returns(s) & FORBIDDEN_TYPES
        if hit:
            problems.append(f"ColophonSession.{where} returns {sorted(hit)}: {declaration(s)}")

    listening = sorted(graphs.glob("ColophonListeningKit*.symbols.json"))
    if not listening:
        problems.append(f"no symbol graph for ColophonListeningKit in {graphs}")
    for path in listening:
        for s in load(path)["symbols"]:
            # Its own symbols only: the graph also carries what it re-exports (ColophonSession, ColophonKit).
            if not s["identifier"]["precise"].startswith("s:20ColophonListeningKit"):
                continue
            where = ".".join(s["pathComponents"])
            hit = types_named(s) & (FORBIDDEN_TYPES | {"SessionCellHost"})
            if hit:
                problems.append(f"ColophonListeningKit.{where} exposes {sorted(hit)}: {declaration(s)}")

    surface = sorted(set(surface))
    if update:
        pinned_path.write_text("\n".join(surface) + "\n")
    pinned = [line for line in pinned_path.read_text().splitlines() if line]
    added = [line for line in surface if line not in pinned]
    removed = [line for line in pinned if line not in surface]
    for line in added:
        problems.append(f"not pinned: {line}")
    for line in removed:
        problems.append(f"pinned but gone: {line}")
    if problems:
        print("\n".join(problems))
        sys.exit(1)
    print(f"public API: ColophonHosts {len(surface)} symbols, as pinned; no SPI; nothing exposes the engine, a signer, an endpoint, the stream client or a view; ColophonListeningKit exposes none of them nor its cell host")


main()
