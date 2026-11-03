
#!/usr/bin/env python3

import re
import base64
import sys
import math
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(errors="replace")
blobs = re.findall(r"['\"]([A-Za-z0-9+/]{100,}={0,2})['\"]", text)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0

    freq = [0] * 256

    for b in data:
        freq[b] += 1

    n = len(data)

    return -sum(
        (f / n) * math.log2(f / n)
        for f in freq if f
    )


def readable(data: bytes) -> float:
    if not data:
        return 0.0

    return sum(
        1 for c in data
        if 32 <= c < 127 or c in (9, 10, 13)
    ) / len(data)


for i, b in enumerate(blobs):
    print(f"\n=== blob{i} ===")

    raw = base64.b64decode(b)

    print(
        f"  Base64 decoding: {len(raw)} bytes, "
        f"entropy {entropy(raw):.3f}, "
        f"readability {readable(raw):.2%}"
    )

    # Attempt a second Base64 decoding
    try:
        raw2 = base64.b64decode(raw, validate=True)

        print(
            f"  Double Base64: {len(raw2)} bytes, "
            f"entropy {entropy(raw2):.3f}, "
            f"readability {readable(raw2):.2%}"
        )

        out = path.with_suffix(f".blob{i}.double_b64.bin")
        out.write_bytes(raw2)

        print(f"  -> Saved to: {out}")

    except Exception as e:
        print(f"  Double Base64: failed ({e})")

    # Attempt a third Base64 decoding (if double decoding succeeds)
    try:
        raw2 = base64.b64decode(raw, validate=True)
        raw3 = base64.b64decode(raw2, validate=True)

        print(
            f"  Triple Base64: {len(raw3)} bytes, "
            f"entropy {entropy(raw3):.3f}, "
            f"readability {readable(raw3):.2%}"
        )

        out = path.with_suffix(f".blob{i}.triple_b64.bin")
        out.write_bytes(raw3)

        print(f"  -> Saved to: {out}")

    except Exception:
        pass
