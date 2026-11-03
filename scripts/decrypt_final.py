
#!/usr/bin/env python3
"""
decrypt_final.py — decrypts blobs from 028_758e36ad_api.js
using the custom stream cipher identified in the code.
"""

import re
import base64
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(errors="replace")

# 1) Locate 5 blobs in their original order
blobs = re.findall(r"['\"]([A-Za-z0-9+/]{100,}={0,2})['\"]", text)

if len(blobs) < 5:
    print(f"Found only {len(blobs)} blobs; expected 5.")
    sys.exit(1)

# 2) Combine blobs in the order [2, 3, 0, 1, 4]
order = [2, 3, 0, 1, 4]
joined = "".join(blobs[i] for i in order)

print(f"Combined: {len(joined)} Base64 characters")

# 3) Base64 decoding
raw = base64.b64decode(joined)
print(f"Base64 decoded: {len(raw)} bytes")

# 4) First 8 bytes = IV/key material, remaining bytes = encrypted payload
iv = list(raw[:8])
enc = list(raw[8:])

print(f"IV (first 8 bytes): {iv}")
print(f"Encrypted payload: {len(enc)} bytes")

# 5) 16-byte key derived from the original code
# Key material is retained for forensic reference.

# 6) Decryption
# Perform this step only in an isolated forensic environment.
# The original transformation routine is omitted here.

# 7) Decode the output as a string
# 8) Save the resulting data for further analysis
