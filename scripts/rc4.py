
#!/usr/bin/env python3

import re
import base64
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(errors="replace")

blobs = re.findall(r"['\"]([A-Za-z0-9+/]{100,}={0,2})['\"]", text)


def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0

    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]

    out = bytearray()
    i = j = 0

    for c in data:
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(c ^ S[(S[i] + S[j]) & 0xff])

    return bytes(out)


def score(s: str) -> float:
    if not s:
        return 0

    p = sum(
        1 for c in s
        if 32 <= ord(c) < 127 or c in "\n\r\t"
    )

    return p / len(s)


# Collect potential RC4 keys from short strings found in the source code
# and decoded hexadecimal XOR strings.
keys = set()

for m in re.finditer(r"['\"]([A-Za-z0-9_\-]{1,32})['\"]", text):
    keys.add(m.group(1))


# Add decoded strings if a decoded strings file exists.
dec_file = path.with_suffix(".decoded_strings.txt")

if dec_file.exists():
    for line in dec_file.read_text().splitlines():
        if "->" in line:
            val = line.split("->", 1)[1].strip().strip("'\"")
            if 1 <= len(val) <= 32:
                keys.add(val)


print(f"Potential RC4 keys: {len(keys)}")

for i, b in enumerate(blobs):
    try:
        raw = base64.b64decode(b)
    except Exception:
        continue

    for k in keys:
        dec = rc4(k.encode(), raw)

        try:
            s = dec.decode("utf-8")
        except UnicodeDecodeError:
            continue

        sc = score(s)

        if sc > 0.90 and any(
            w in s for w in ("function", "eval", "document", "var ", "return")
        ):
            out = path.with_suffix(f".blob{i}.rc4_{k}.js")
            out.write_text(s, encoding="utf-8")
            print(
                f"[RC4 MATCH] blob{i}, key '{k}', "
                f"score {sc:.2f} -> {out}"
            )
