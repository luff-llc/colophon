#!/usr/bin/env python3
"""Writes (or, with --check, verifies) conformance/0.6-sessions/now-playing-anchor.json: the anchor and presence
coding and the anchor translation of the `listening.podcasts/now-playing` cell (spec/colophon-0.6-sessions.md §S12,
docs/now-playing.md §2 and §3).

This is an implementation of the rules independent of the Swift kit: every expected verdict, canonical text and
translated position in the file is computed here, with Python's exact integers, and the Swift, Kotlin and JavaScript
kits replay the file. Run: python3 scripts/generate-now-playing-vectors.py [--check]
"""
import base64
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "conformance/0.6-sessions/now-playing-anchor.json"
MAX = (1 << 53) - 1
MAX_BYTES = 8192
ANCHOR_FIELDS = ["at", "episode", "playing", "positionMs", "ratePermille", "show"]
PRESENCE_FIELDS = ["label", "playing"]
WHITE_SPACE = {0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680, *range(0x2000, 0x200B), 0x2028, 0x2029, 0x202F, 0x205F, 0x3000}
ORDER = ["tooLarge", "syntax", "duplicateField", "notObject", "unknownField", "missingField", "wrongType", "outOfRange",
         "badText", "notCanonical"]


class Num(str):
    """A number token as written."""


class Fail(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def quoted(s):
    out = ['"']
    for ch in s:
        c = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif c < 0x20:
            out.append("\\u%04x" % c)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def canonical_anchor(a):
    return ("{" + f'"at":{a["at"]},"episode":{quoted(a["episode"])},"playing":{"true" if a["playing"] else "false"},'
            f'"positionMs":{a["positionMs"]},"ratePermille":{a["ratePermille"]},"show":{quoted(a["show"])}' + "}")


def canonical_presence(p):
    return "{" + f'"label":{quoted(p["label"])},"playing":{"true" if p["playing"] else "false"}' + "}"


def valid_text(s):
    n = len(s.encode("utf-8"))
    if n < 1 or n > 1024:
        return False
    for ch in s:
        c = ord(ch)
        if c < 0x20 or 0x7F <= c <= 0x9F:
            return False
    return not all(ord(ch) in WHITE_SPACE for ch in s)


def parse(data):
    """One strict JSON value: syntax first (whole input), then duplicates."""
    if len(data) > MAX_BYTES:
        raise Fail("tooLarge")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Fail("syntax")
    duplicate = [False]

    def pairs(items):
        names = [k for k, _ in items]
        if len(set(names)) != len(names):
            duplicate[0] = True
        return dict(items)

    def bad_constant(_):
        raise ValueError("not JSON")

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_int=Num, parse_float=Num, parse_constant=bad_constant)
    except (ValueError, RecursionError):
        raise Fail("syntax")

    def walk(v, depth):
        if isinstance(v, str) and not isinstance(v, Num):
            try:
                v.encode("utf-8")
            except UnicodeEncodeError:
                raise Fail("syntax")  # a lone surrogate escape
        if isinstance(v, dict):
            if depth >= 64:
                raise Fail("syntax")
            for k, x in v.items():
                walk(k, depth + 1)
                walk(x, depth + 1)
        if isinstance(v, list):
            if depth >= 64:
                raise Fail("syntax")
            for x in v:
                walk(x, depth + 1)

    walk(value, 0)
    if duplicate[0]:
        raise Fail("duplicateField")
    return value


def is_int_token(v):
    return isinstance(v, Num) and not any(c in v for c in ".eE")


def fields(data, names):
    value = parse(data)
    if not isinstance(value, dict):
        raise Fail("notObject")
    if any(k not in names for k in value):
        raise Fail("unknownField")
    if any(k not in value for k in names):
        raise Fail("missingField")
    return value


def decode_anchor(data):
    v = fields(data, ANCHOR_FIELDS)
    kinds = {"at": "int", "episode": "str", "playing": "bool", "positionMs": "int", "ratePermille": "int", "show": "str"}
    for k in ANCHOR_FIELDS:
        x, kind = v[k], kinds[k]
        ok = (kind == "int" and is_int_token(x)) or (kind == "str" and isinstance(x, str) and not isinstance(x, Num)) \
            or (kind == "bool" and isinstance(x, bool))
        if not ok:
            raise Fail("wrongType")
    for k in ["at", "positionMs", "ratePermille"]:
        if not 0 <= int(v[k]) <= MAX:
            raise Fail("outOfRange")
    for k in ["episode", "show"]:
        if not valid_text(v[k]):
            raise Fail("badText")
    a = {k: (int(v[k]) if kinds[k] == "int" else v[k]) for k in ANCHOR_FIELDS}
    if canonical_anchor(a).encode("utf-8") != data:
        raise Fail("notCanonical")
    return a


def decode_presence(data):
    v = fields(data, PRESENCE_FIELDS)
    if not isinstance(v["label"], str) or isinstance(v["label"], Num) or not isinstance(v["playing"], bool):
        raise Fail("wrongType")
    if not valid_text(v["label"]):
        raise Fail("badText")
    p = {"label": v["label"], "playing": v["playing"]}
    if canonical_presence(p).encode("utf-8") != data:
        raise Fail("notCanonical")
    return p


def clamp(v, lo, hi):
    return min(max(v, lo), hi)


def ceil_div(a, b):
    return -((-a) // b)


def translate(anchor, now, offset, error, sample_age, limit):
    now, offset = clamp(now, 0, MAX), clamp(offset, -MAX, MAX)
    age = clamp(now - anchor["at"] + offset, -MAX, MAX)
    if not anchor["playing"]:
        return {"ageMs": age, "capped": False, "elapsedMs": 0, "errorBoundMs": 0, "positionMs": anchor["positionMs"]}
    limit = clamp(limit, 0, MAX)
    elapsed = clamp(age, 0, limit)
    position = min(MAX, anchor["positionMs"] + anchor["ratePermille"] * elapsed // 1000)
    drift = ceil_div(clamp(sample_age, 0, MAX), 1000)
    bound = min(MAX, ceil_div(anchor["ratePermille"] * (clamp(error, 0, MAX) + drift), 1000))
    return {"ageMs": age, "capped": age > limit, "elapsedMs": elapsed, "errorBoundMs": bound, "positionMs": position}


def anchor(episode="ep-1", show="show-1", positionMs=1234567, ratePermille=1250, playing=True, at=98765432):
    return {"at": at, "episode": episode, "playing": playing, "positionMs": positionMs, "ratePermille": ratePermille, "show": show}


def text_case(name, text, kind="anchor"):
    return {"name": name, "kind": kind, "text": text}


def bytes_case(name, data, kind="anchor"):
    return {"name": name, "kind": kind, "base64": base64.b64encode(data).decode()}


def build():
    S = canonical_anchor(anchor())
    encode = [
        ("the §S12 example", anchor()),
        ("paused at zero", anchor(positionMs=0, ratePermille=1000, playing=False, at=0)),
        ("every integer at 2^53 - 1", anchor(positionMs=MAX, ratePermille=MAX, at=MAX)),
        ("rate 0 while playing", anchor(ratePermille=0)),
        ("non-ASCII IDs are UTF-8, not escaped", anchor(episode="épisode-ü-中", show="🎧 show")),
        ("a quote and a backslash are escaped, a slash is not", anchor(episode='a"b\\c/d', show="x")),
        ("an ID of exactly 1,024 bytes", anchor(episode="e" * 1024)),
        ("an ID with inner white space", anchor(episode=" ep 1 ")),
    ]
    encode_cases = [{"name": n, "anchor": a, "text": canonical_anchor(a)} for n, a in encode]
    presence = [("the §S12 example", {"label": "Kitchen iPad", "playing": False}),
                ("playing, non-ASCII label", {"label": "Küche – iPad", "playing": True})]
    presence_cases = [{"name": n, "presence": p, "text": canonical_presence(p)} for n, p in presence]

    reorder = '{"episode":"ep-1","show":"show-1","positionMs":1234567,"ratePermille":1250,"playing":true,"at":98765432}'
    decode = [
        text_case("8,193 bytes", "{" + " " * 8191 + "}"),
        text_case("empty", ""),
        text_case("not JSON", "now playing"),
        text_case("unterminated", S[:-1]),
        text_case("trailing data", S + "x"),
        text_case("two values", S + S),
        bytes_case("invalid UTF-8 in a string", S.replace("ep-1", "ep-\x01").encode().replace(b"\x01", b"\xff")),
        bytes_case("an encoded surrogate (CESU-8) in a string", S.replace("ep-1", "ep-\x01").encode().replace(b"\x01", b"\xed\xa0\x80")),
        text_case("a lone surrogate escape", S.replace('"ep-1"', '"ep-\\ud800"')),
        text_case("a lone low surrogate escape", S.replace('"ep-1"', '"\\udc00"')),
        text_case("a raw tab inside a string", S.replace('"ep-1"', '"ep\t1"')),
        text_case("NaN", S.replace("1234567", "NaN")),
        text_case("a leading zero", S.replace("1234567", "01234567")),
        text_case("a single-quoted string", S.replace('"show-1"', "'show-1'")),
        text_case("an unknown field nested 65 deep", S[:-1] + ',"x":' + "[" * 65 + "]" * 65 + "}"),
        text_case("an unknown field nested to 64 containers in all", S[:-1] + ',"x":' + "[" * 63 + "]" * 63 + "}"),
        text_case("a duplicate field", S[:-1] + ',"at":98765432}'),
        text_case("a duplicate inside an unknown field", S[:-1] + ',"x":{"a":1,"a":1}}'),
        text_case("an array", "[" + S + "]"),
        text_case("a string", '"ep-1"'),
        text_case("a number", "1"),
        text_case("null", "null"),
        text_case("an unknown field", S[:-1] + ',"zz":1}'),
        text_case("an unknown field that sorts first", '{"a":1,' + S[1:]),
        text_case("no show", S.replace(',"show":"show-1"', "")),
        text_case("no at", S.replace('"at":98765432,', "")),
        text_case("an empty object", "{}"),
        text_case("at as a string", S.replace("98765432", '"98765432"')),
        text_case("positionMs with a fraction", S.replace("1234567", "1234567.0")),
        text_case("positionMs with an exponent", S.replace("1234567", "1234567e0")),
        text_case("playing as 1", S.replace("true", "1")),
        text_case("ratePermille null", S.replace("1250", "null")),
        text_case("episode as a number", S.replace('"ep-1"', "1")),
        text_case("show as an object", S.replace('"show-1"', "{}")),
        text_case("at -1", S.replace("98765432", "-1")),
        text_case("positionMs 2^53", S.replace("1234567", str(MAX + 1))),
        text_case("ratePermille 10^20", S.replace("1250", "100000000000000000000")),
        text_case("an empty episode", S.replace('"ep-1"', '""')),
        text_case("an episode of spaces", S.replace('"ep-1"', '"   "')),
        text_case("an episode of ideographic spaces", S.replace('"ep-1"', '"　　"')),
        text_case("a NUL in the episode (escaped)", S.replace('"ep-1"', '"ep\\u00001"')),
        text_case("U+0085 in the show", S.replace('"show-1"', '"show\u00851"')),
        text_case("DEL in the show", S.replace('"show-1"', '"show\u007f"')),
        text_case("an episode of 1,025 bytes", S.replace('"ep-1"', quoted("e" * 1025))),
        text_case("the spec's field order", reorder),
        text_case("white space after a colon", S.replace('"at":', '"at": ')),
        text_case("a newline at the end", S + "\n"),
        text_case("an escaped slash", S.replace('"show-1"', '"show\\/1"')),
        text_case("an unneeded unicode escape", S.replace('"ep-1"', '"\\u0065p-1"')),
        text_case("an escape of a printable character in upper-case hex", S.replace('"ep-1"', '"\\u0045P-1"')),
        text_case("negative zero", canonical_anchor(anchor(at=0)).replace('"at":0', '"at":-0')),
        text_case("presence: the spec's example", '{"label":"Kitchen iPad","playing":false}', "presence"),
        text_case("presence: no playing", '{"label":"Kitchen iPad"}', "presence"),
        text_case("presence: an extra field", '{"label":"Kitchen iPad","playing":false,"x":1}', "presence"),
        text_case("presence: a blank label", '{"label":" ","playing":false}', "presence"),
        text_case("presence: playing as a string", '{"label":"Kitchen iPad","playing":"no"}', "presence"),
        text_case("presence: keys out of order", '{"playing":false,"label":"Kitchen iPad"}', "presence"),
    ]
    for c in encode_cases:
        decode.append(text_case("valid: " + c["name"], c["text"]))
    for d in decode:
        data = base64.b64decode(d["base64"]) if "base64" in d else d["text"].encode("utf-8")
        try:
            value = (decode_anchor if d["kind"] == "anchor" else decode_presence)(data)
            d["valid"] = True
            d["anchor" if d["kind"] == "anchor" else "presence"] = value
        except Fail as e:
            d["valid"] = False
            d["error"] = e.code

    T = 1_000_000
    translate_in = [
        ("paused: the position, whatever the time", anchor(positionMs=60_000, ratePermille=1500, playing=False, at=T), T + 3_600_000, 25, 4, 0, 75_000),
        ("playing at 1x, 5 s later on the same clock", anchor(positionMs=60_000, ratePermille=1000, at=T), T + 5_000, 0, 0, 0, 75_000),
        ("playing at 1.25x: floor(1250 x 1001 / 1000) = 1251", anchor(positionMs=0, ratePermille=1250, at=T), T + 1_001, 0, 0, 0, 75_000),
        ("playing at 1.5x for 1 ms: floor(1.5) = 1", anchor(positionMs=0, ratePermille=1500, at=T), T + 1, 0, 0, 0, 75_000),
        ("playing at 0.75x for 3 ms: floor(2.25) = 2", anchor(positionMs=10, ratePermille=750, at=T), T + 3, 0, 0, 0, 75_000),
        ("the publisher's clock is ahead (positive offset)", anchor(positionMs=0, ratePermille=1000, at=5_000_000), T, 4_002_000, 3, 0, 75_000),
        ("the publisher's clock is behind (negative offset)", anchor(positionMs=0, ratePermille=1000, at=200), T, -998_000, 3, 0, 75_000),
        ("offset error makes the age negative: no projection backwards", anchor(positionMs=42_000, ratePermille=1000, at=T + 4), T, 0, 4, 0, 75_000),
        ("a rebooted clock: now before at", anchor(positionMs=42_000, ratePermille=1000, at=T), 5, 0, 0, 0, 75_000),
        ("older than the limit: capped at 75 s", anchor(positionMs=0, ratePermille=1000, at=T), T + 200_000, 0, 0, 0, 75_000),
        ("exactly at the limit: not capped", anchor(positionMs=0, ratePermille=1000, at=T), T + 75_000, 0, 0, 0, 75_000),
        ("a limit of 0 never projects", anchor(positionMs=7, ratePermille=1000, at=T), T + 9_000, 0, 0, 0, 0),
        ("rate 0 while playing does not move", anchor(positionMs=7, ratePermille=0, at=T), T + 9_000, 0, 5, 0, 75_000),
        ("the error bound: ceil(1250 x (3 + ceil(2500 / 1000)) / 1000) = 8", anchor(positionMs=0, ratePermille=1250, at=T), T + 10, 0, 3, 2_500, 75_000),
        ("the error bound with a fresh sample: ceil(1000 x 20 / 1000) = 20", anchor(positionMs=0, ratePermille=1000, at=T), T + 10, 0, 20, 0, 75_000),
        ("the error bound rounds 1 ms of drift up", anchor(positionMs=0, ratePermille=1000, at=T), T + 10, 0, 0, 1, 75_000),
        ("saturates at 2^53 - 1", anchor(positionMs=MAX - 10, ratePermille=1000, at=T), T + 11, 0, 0, 0, 75_000),
        ("a product beyond 64 bits saturates", anchor(positionMs=0, ratePermille=MAX, at=0), MAX, 0, MAX, MAX, MAX),
        ("the largest rate for 4,000 s saturates", anchor(positionMs=0, ratePermille=MAX, at=0), 4_000_000, 0, 0, 0, MAX),
        ("a product above 2^53 whose result fits: exact integers needed", anchor(positionMs=3, ratePermille=1250, at=0), 7_000_000_000_000_001, 0, 0, 0, MAX),
        ("the most negative offset clamps the age", anchor(positionMs=1, ratePermille=1000, at=MAX), 0, -MAX, 0, 0, 75_000),
        ("the most positive offset clamps the age", anchor(positionMs=1, ratePermille=1000, at=0), MAX, MAX, 0, 0, MAX),
        ("a long-running anchor within the limit", anchor(positionMs=3_600_000, ratePermille=1100, at=T), T + 59_999, -17, 2, 30_000, 75_000),
    ]
    translate_cases = []
    for name, a, now, offset, error, age, limit in translate_in:
        translate_cases.append({"name": name, "anchor": a, "nowMs": now, "offsetMs": offset, "offsetErrorMs": error,
                                "sampleAgeMs": age, "maximumProjectionMs": limit,
                                "expect": translate(a, now, offset, error, age, limit)})
    return {
        "format": "colophon/now-playing-anchor-vectors/6",
        "description": "Coding and translation of the listening.podcasts/now-playing anchor and presence (sessions §S12; "
                       "docs/now-playing.md §2 and §3). Generated by scripts/generate-now-playing-vectors.py.",
        "rules": {
            "anchor": 'canonical JSON of {"at","episode","playing","positionMs","ratePermille","show"}, all required, nothing else',
            "presence": 'canonical JSON of {"label","playing"}, both required, nothing else',
            "integers": "integer tokens (no fraction, no exponent), 0 to 2^53 - 1",
            "text": "1 to 1,024 UTF-8 bytes, not only Unicode White_Space, no Cc control character",
            "maximumBytes": MAX_BYTES,
            "errorOrder": ORDER,
            "translate": "ageMs = clamp(now + clamp(offset, ±(2^53-1)) - at, ±(2^53-1)); paused: positionMs, elapsed 0, bound 0; "
                         "playing: elapsedMs = clamp(ageMs, 0, maximumProjectionMs), capped = ageMs > maximumProjectionMs, "
                         "positionMs + floor(ratePermille × elapsedMs / 1000) saturating at 2^53-1; errorBoundMs = "
                         "ceil(ratePermille × (offsetErrorMs + ceil(sampleAgeMs / 1000)) / 1000) saturating at 2^53-1",
        },
        "encode": encode_cases,
        "presence": presence_cases,
        "decode": decode,
        "translate": translate_cases,
    }


def main():
    text = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if OUT.read_text(encoding="utf-8") != text:
            sys.exit(f"{OUT.relative_to(ROOT)} is out of date: run scripts/generate-now-playing-vectors.py")
        print("now-playing vectors are up to date")
        return
    OUT.write_text(text, encoding="utf-8")
    v = build()
    valid = sum(1 for d in v["decode"] if d["valid"])
    print(f"wrote {OUT.relative_to(ROOT)}: {len(v['encode'])} encode, {len(v['presence'])} presence, "
          f"{len(v['decode'])} decode ({valid} valid, {len(v['decode']) - valid} invalid), {len(v['translate'])} translate")


if __name__ == "__main__":
    main()
