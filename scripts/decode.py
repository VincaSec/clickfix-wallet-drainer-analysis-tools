
#!/usr/bin/env python3

import re
import base64
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(errors="replace")

# Find all strings containing 100+ characters that resemble Base64 data
blobs = re.findall(r"['\"]([A-Za-z0-9+/]{100,}={0,2})['\"]", text)

print(f"Base64 blobs found: {len(blobs)}\n")

for i, b in enumerate(blobs):
    try:
        decoded = base64.b64decode(b).decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[{i}] Decoding failed: {e}")
        continue

    out = path.with_suffix(f".blob{i}.txt")
    out.write_text(decoded, encoding="utf-8")

    print(f"[{i}] {len(b)} Base64 characters -> {len(decoded)} text characters -> {out}")
    print("    First 200 characters:")
    print("    " + decoded[:200].replace("\n", "\\n"))
    print()
