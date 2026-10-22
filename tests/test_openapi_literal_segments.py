#!/usr/bin/env python3
"""Static gate: every raw-string segment of the OpenAPI document literal stays under the MSVC
string-token limit.

The OpenAPI template in server/core/src/rest_api_v1.cpp is one chain of adjacent raw-string
literals (R"json(...)json") passed to expand_ecosystem_tokens(). MSVC refuses a single string
token longer than 16,380 bytes (C2026), and the compiler concatenates the chain only after each
token has been checked, so the limit applies to every segment on its own, not to the total.
Linux and macOS compilers have no such limit, so only the Windows leg of CI would notice a
segment that grew past it, and only when that leg runs. This gate makes every platform see it.

The ceiling here is 15,000 bytes: the same figure tests/unit/server/test_swagger_page.cpp uses
for its own pieces, leaving about 1,380 bytes of margin under the compiler's limit for a
multi-byte character or a few edits made between a green run and a merge.

When a segment is too large, split it at a JSON-value boundary (after a comma or a closing
brace at the end of a line) by closing the raw string and opening another one on the next
line: )json"  newline  R"json(. The compiler joins them back into the same text.

Reads the file as bytes: the limit is in bytes, not characters.
Run: python3 tests/test_openapi_literal_segments.py
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = ROOT / "server" / "core" / "src" / "rest_api_v1.cpp"

CEILING = 15_000  # bytes per raw-string segment; MSVC C2026 is 16,380
MIN_SEGMENTS = 20  # a chain this short means the lexer lost the chain, not that it got smaller

CHAIN_START = re.compile(rb"static\s+const\s+std::string\s+spec\s*=\s*expand_ecosystem_tokens\s*\(")
OPEN = b'R"json('
CLOSE = b')json"'


class ChainError(Exception):
    pass


def segments(src: bytes):
    """Returns [(1-based start line, byte length)] for each raw-string segment of the chain."""
    m = CHAIN_START.search(src)
    if not m:
        raise ChainError(
            "cannot find `static const std::string spec = expand_ecosystem_tokens(` in "
            "rest_api_v1.cpp: if the chain moved or was renamed, update this gate and "
            "scripts/ci/check-api-parity.py, which lexes the same call"
        )
    pos = m.end()
    out = []
    while True:
        # Whitespace and comments between segments (a `// Split literal` note is customary).
        while pos < len(src):
            if src[pos : pos + 1].isspace():
                pos += 1
            elif src.startswith(b"//", pos):
                nl = src.find(b"\n", pos)
                pos = len(src) if nl < 0 else nl + 1
            elif src.startswith(b"/*", pos):
                end = src.find(b"*/", pos + 2)
                if end < 0:
                    raise ChainError("unterminated block comment in the OpenAPI literal chain")
                pos = end + 2
            else:
                break
        if src.startswith(OPEN, pos):
            body_start = pos + len(OPEN)
            end = src.find(CLOSE, body_start)
            if end < 0:
                raise ChainError("unterminated raw string in the OpenAPI literal chain")
            line = src.count(b"\n", 0, pos) + 1
            out.append((line, end - body_start))
            pos = end + len(CLOSE)
        elif src[pos : pos + 1] == b")":
            return out
        else:
            line = src.count(b"\n", 0, pos) + 1
            raise ChainError(
                f"line {line}: the OpenAPI literal chain holds something other than "
                'R"json(...)json" segments; this gate (and check-api-parity.py) expect only those'
            )


def problems(src: bytes, ceiling: int = CEILING, minimum: int = MIN_SEGMENTS):
    segs = segments(src)
    found = []
    if len(segs) < minimum:
        found.append(
            f"only {len(segs)} segments found in the OpenAPI literal chain (expected at least "
            f"{minimum}); the chain was probably restructured, update this gate"
        )
    for line, size in segs:
        if size >= ceiling:
            found.append(
                f"rest_api_v1.cpp:{line}: OpenAPI literal segment is {size:,} bytes, at or over "
                f"the {ceiling:,}-byte ceiling (MSVC C2026 rejects a string token over 16,380 "
                f"bytes, and only the Windows CI leg would notice). Split it: close the raw "
                f'string with )json" and open another with R"json( at a JSON-value boundary'
            )
    return found


def selftest():
    def chain(*sizes):
        parts = "\n".join(f'    R"json({"x" * n})json"' for n in sizes)
        return f"static const std::string spec = expand_ecosystem_tokens(\n{parts});\n".encode()

    assert problems(chain(10, 14_999, 10), minimum=3) == []
    assert len(problems(chain(10, 15_000, 10), minimum=3)) == 1, "a segment at the ceiling passes"
    assert len(problems(chain(20_000, 30_000), minimum=2)) == 2, "each oversized segment reported"
    assert len(problems(chain(10, 10), minimum=3)) == 1, "a chain shorter than expected passes"
    with_comments = chain(10, 10).replace(b'"\n    R"json(', b'"\n    // Split literal\n    /* x */ R"json(')
    assert problems(with_comments, minimum=2) == [], "comments between segments are skipped"
    for bad in (b"int main() {}", chain(5)[:-6] + b' "stray" );'):
        try:
            segments(bad)
        except ChainError:
            continue
        raise AssertionError("an unreadable chain must raise, never pass")


def main():
    selftest()
    try:
        found = problems(SOURCE.read_bytes())
    except ChainError as e:
        print(f"FAIL: {e}")
        return 1
    for f in found:
        print(f"FAIL: {f}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
