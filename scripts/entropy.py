
#!/usr/bin/env python3
"""
entropy.py - analyzes the entropy of Base64 blobs in a JavaScript file.

Usage:
    python3 entropy.py 028_758e36ad_api.js

Interpretation:
    ~8.0 bits/byte  -> encrypted (AES/RC4) - cannot be decoded without the key
    ~7.5 bits/byte  -> compressed (gzip/deflate) - may be decompressed
    < 6.0 bits/byte -> possibly plain Base64 or XOR - may be decoded
"""

import sys
import math
import base64
import re
import gzip
import zlib
from pathlib import Path

# ------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------
def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy in bits per byte (0..8)."""
    if not data:
        return 0.0

    freq = [0] * 256

    for b in data:
        freq[b] += 1

    n = len(data)
    ent = 0.0

    for f in freq:
        if f:
            p = f / n
            ent -= p * math.log2(p)

    return ent


def try_decompress(raw: bytes):
    """Try gzip/zlib/raw-deflate decompression. Return (name, bytes) or None."""
    attempts = [
        ("gzip", gzip.decompress),
        ("zlib", zlib.decompress),
        ("raw-deflate", lambda x: zlib.decompress(x, -15)),
    ]

    for name, fn in attempts:
        try:
            out = fn(raw)
            if out and len(out) > 10:
                return name, out
        except Exception:
            pass

    return None


def score_readable(b: bytes) -> float:
    """Calculate the proportion of readable bytes (printable ASCII + \n\r\t)."""
    if not b:
        return 0.0

    printable = sum(
        1 for c in b
        if 32 <= c < 127 or c in (9, 10, 13)
    )

    return printable / len(b)


# ------------------------------------------------------------
# Main logic
# ------------------------------------------------------------
def main(path_str: str):
    path = Path(path_str)

    if not path.exists():
        print(f"File does not exist: {path}")
        sys.exit(1)

    text = path.read_text(errors="replace")

    # Find all Base64 blobs (100+ characters)
    blobs = re.findall(r"['\"]([A-Za-z0-9+/]{100,}={0,2})['\"]", text)

    print(f"File: {path}")
    print(f"Base64 blobs found: {len(blobs)}\n")

    print(
        f"{'#':>2}  {'B64 len':>8}  {'BIN len':>8}  "
        f"{'Entropy':>10}  {'Readable':>9}  {'Verdict'}"
    )

    print("-" * 80)

    for i, b in enumerate(blobs):
        try:
            raw = base64.b64decode(b)
        except Exception as e:
            print(f"{i:>2}  ERROR: {e}")
            continue

        ent = shannon_entropy(raw)
        readable = score_readable(raw)

        # Determine the verdict based on entropy
        if ent >= 7.95:
            verdict = "ENCRYPTED (AES/RC4) - key required"
        elif ent >= 7.3:
            verdict = "COMPRESSED (gzip/deflate) - try decompression"
        elif ent >= 6.0:
            verdict = "MIXED - possibly XOR + compression"
        else:
            verdict = "LOW entropy - possibly readable text or XOR"

        print(
            f"{i:>2}  {len(b):>8}  {len(raw):>8}  "
            f"{ent:>10.3f}  {readable:>8.2%}  {verdict}"
        )

        # If the data appears compressed, try decompression
        if 7.3 <= ent < 7.95:
            result = try_decompress(raw)

            if result:
                name, out = result
                out_path = path.with_suffix(f".blob{i}.{name}.bin")
                out_path.write_bytes(out)

                out_ent = shannon_entropy(out)
                out_read = score_readable(out)

                print(
                    f"      -> {name} decompression successful: "
                    f"{len(out)} B, entropy {out_ent:.3f}, "
                    f"readable {out_read:.2%}"
                )

                print(f"      -> Saved to: {out_path}")

                # If the decompressed data is readable, also save it as a .js file
                if out_read > 0.85:
                    js_path = out_path.with_suffix(".js")
                    js_path.write_bytes(out)

                    print(f"      -> APPEARS TO BE JAVASCRIPT: {js_path}")

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)

    ents = []

    for b in blobs:
        try:
            ents.append(shannon_entropy(base64.b64decode(b)))
        except Exception:
            pass

    if ents:
        avg = sum(ents) / len(ents)

        print(f"Average entropy: {avg:.3f} bits/byte")

        if avg >= 7.95:
            print("Conclusion: The blobs are highly entropic and may be encrypted.")
            print("A key or further analysis of the decoding routine may be required.")
            print("Do not assume that high entropy alone proves AES encryption.")
            print("Use controlled, isolated analysis to inspect decoded content.")

        elif avg >= 7.3:
            print("Conclusion: The blobs may be COMPRESSED.")
            print("Decompression was attempted above.")
            print("If decompression failed, the data may use another format or transformation.")

        else:
            print("Conclusion: Entropy is relatively low - possibly Base64-encoded or XOR-transformed data.")
            print("Further decoding and content inspection may help identify the format.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 entropy.py <file.js>")
        sys.exit(1)

    main(sys.argv[1])
