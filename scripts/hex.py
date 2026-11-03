
#!/usr/bin/env python3
"""
Decodes all (function(){var sXXX=KEY,h="HEX",...}) patterns found in a JavaScript file.
"""

import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(errors="replace")

# Pattern: var sXXXX=KEY, h="HEX", o="";for(...) ... ^sXXXX
pattern = re.compile(
    r'var\s+(s[0-9a-f]+)\s*=\s*(\d+)\s*,\s*h\s*=\s*"([0-9a-fA-F]+)"'
)

results = []
for m in pattern.finditer(text):
    var, key_str, hex_str = m.group(1), m.group(2), m.group(3)
    key = int(key_str)
    try:
        decoded = "".join(
            chr(int(hex_str[i:i+2], 16) ^ key)
            for i in range(0, len(hex_str), 2)
        )
    except Exception as e:
        decoded = f"<error: {e}>"
    results.append((var, key, hex_str, decoded))

print(f"Found {len(results)} obfuscated strings:\n")
for var, key, hex_str, decoded in results:
    print(f"  {var} = {key}  ->  {decoded!r}")

# Save the decoded string map for further analysis
out = path.with_suffix(".decoded_strings.txt")
with out.open("w", encoding="utf-8") as f:
    for var, key, hex_str, decoded in results:
        f.write(f"{var} = {key}  ->  {decoded}\n")

print(f"\nSaved to: {out}")
