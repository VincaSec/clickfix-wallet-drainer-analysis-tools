
#!/usr/bin/env python3

import re
import base64
import sys
from pathlib import Path
from collections import Counter

path = Path(sys.argv[1])
text = path.read_text(errors="replace")

# 1) Find all numbers used with the XOR operator (^)
candidates = set()

for m in re.finditer(r"\^\s*(0x[0-9a-fA-F]+|\d{1,4})", text):
    candidates.add(int(m.group(1), 0))

# Find XOR operations involving string characters, e.g. ^ 'a'
for m in re.finditer(r"\^\s*['\"](.)['\"]", text):
    candidates.add(ord(m.group(1)))

print("XOR key candidates:", sorted(candidates))

# 2) Find Base64 blobs
blobs = re.findall(r"['\"]([A-Za-z0-9+/]{100,}={0,2})['\"]", text)

# 3) Try decoding each blob with every candidate key and evaluate readability
def score(s):
    """Higher score indicates more readable text."""
    if not s:
        return 0

    printable = sum(
        1 for c in s
        if 32 <= ord(c) < 127 or c in "\n\r\t"
    )

    return printable / len(s)


best = []

for i, b in enumerate(blobs):
    try:
        raw = base64.b64decode(b)
    except Exception:
        continue

    # Try XOR decoding with each candidate key
    for k in candidates:
        dec = bytes(c ^ k for c in raw)

        try:
            s = dec.decode("utf-8")
        except UnicodeDecodeError:
            # Fall back to Latin-1 to avoid decoding errors
            s = dec.decode("latin-1")

        sc = score(s)

        if sc > 0.85 and (
            "function" in s
            or "var " in s
            or "return" in s
            or "eval" in s
        ):
            best.append((i, k, sc, s))

            out = path.with_suffix(f".blob{i}.xor{k}.txt")
            out.write_text(s, encoding="utf-8")

            print(
                f"[MATCH] blob{i}, key {k}, "
                f"score {sc:.2f} -> {out}"
            )

# 4) If no matches are found, try all keys from 1 to 255
if not best:
    print(
        "\nNo matches found using the identified keys — "
        "trying all keys from 1 to 255..."
    )

    for i, b in enumerate(blobs):
        try:
            raw = base64.b64decode(b)
        except Exception:
            continue

        for k in range(1, 256):
            dec = bytes(c ^ k for c in raw)

            try:
                s = dec.decode("utf-8")
            except UnicodeDecodeError:
                continue

            sc = score(s)

            if sc > 0.90 and (
                "function" in s
                or "eval" in s
                or "document" in s
            ):
                out = path.with_suffix(f".blob{i}.xor{k}.txt")
                out.write_text(s, encoding="utf-8")

                print(
                    f"[BRUTE-FORCE MATCH] blob{i}, key {k}, "
                    f"score {sc:.2f} -> {out}"
                )
                break
