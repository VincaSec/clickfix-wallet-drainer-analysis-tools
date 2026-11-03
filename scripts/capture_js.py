
#!/usr/bin/env python3
"""
capture_js.py — captures all JavaScript files from a website and scans them for suspicious patterns.

Installation (once, inside a virtual environment):
    python3 -m venv ~/pw-env
    source ~/pw-env/bin/activate
    pip install --upgrade pip
    pip install playwright
    python -m playwright install --with-deps chromium

Usage:
    python capture_js.py https://www.politehnickasu.edu.rs/
"""

import sys
import os
import re
import hashlib
import base64
from pathlib import Path
from urllib.parse import urlparse

# ============================================================
# 0) CHECK PLAYWRIGHT INSTALLATION (before importing it)
# ============================================================
try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("ERROR: Playwright is not installed.")
    print("Run:")
    print("  python3 -m venv ~/pw-env && source ~/pw-env/bin/activate")
    print("  pip install playwright")
    print("  python -m playwright install --with-deps chromium")
    sys.exit(1)

# ============================================================
# CONFIGURATION
# ============================================================
OUT_DIR = Path("./js_capture")
MAX_SIZE = 5 * 1024 * 1024          # Skip JavaScript files larger than 5 MB
WAIT_AFTER_LOAD_MS = 8000           # Wait 8 seconds after networkidle

SUSPICIOUS_PATTERNS = [
    (r"atob\s*\(",                         "Base64 decoding (atob)"),
    (r"String\.fromCharCode\s*\(",         "fromCharCode"),
    (r"eval\s*\(",                         "eval()"),
    (r"unescape\s*\(",                     "unescape()"),
    (r"\\\\x[0-9a-f]{2}",                  "Hex escape (\\xNN)"),
    (r"new\s+Function\s*\(",               "new Function()"),
    (r"\[\s*\]\s*\[\s*['\"]filter['\"]\s*\]", "filter.constructor trick"),
    (r"document\.write\s*\(",              "document.write"),
    (r"window\.location\s*=",              "Location redirect"),
    (r"[A-Za-z0-9+/]{300,}={0,2}",         "Long Base64 blob"),
    (r"coin(hive|imp|miner)",              "Cryptominer keyword"),
    (r"__cf_chl|sucuri|404javascript",     "Scanner marker"),
    (r"XMLHttpRequest|fetch\s*\(",         "Network request"),
    (r"document\.cookie",                  "Cookie access"),
    (r"localStorage|sessionStorage",       "Storage access"),
    (r"\\x[0-9a-fA-F]{2}",                 "Raw \\xNN escape"),
    (r"\\u[0-9a-fA-F]{4}",                 "Raw \\uNNNN escape"),
]

TRUSTED_DOMAINS = {
    "politehnickasu.edu.rs", "www.politehnickasu.edu.rs",
    "google.com", "www.google.com", "googleapis.com", "fonts.googleapis.com",
    "gstatic.com", "fonts.gstatic.com", "google-analytics.com",
    "googletagmanager.com", "googlesyndication.com",
    "jquery.com", "code.jquery.com", "jsdelivr.net", "cdnjs.cloudflare.com",
    "cloudflare.com", "cdn.jsdelivr.net", "unpkg.com",
    "facebook.net", "connect.facebook.net",
    "wp.com", "wordpress.org", "gravatar.com",
}

# ============================================================
# HELPER FUNCTIONS
# ============================================================
def safe_name(url: str, idx: int) -> str:
    p = urlparse(url)
    name = p.path.rstrip("/").split("/")[-1] or "inline"
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    if not name.endswith(".js"):
        name += ".js"
    h = hashlib.md5(url.encode()).hexdigest()[:8]
    return f"{idx:03d}_{h}_{name}"


def is_trusted(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return any(host == d or host.endswith("." + d) for d in TRUSTED_DOMAINS)


def scan_content(text: str):
    hits = []
    for pattern, desc in SUSPICIOUS_PATTERNS:
        n = len(re.findall(pattern, text))
        if n > 0:
            hits.append((desc, n))
    return hits


def save_and_scan(path: Path, content: bytes, source_url: str, kind: str):
    path.write_bytes(content)
    text = content.decode("utf-8", errors="replace")
    hits = scan_content(text)

    print(f"\n{'='*70}")
    print(f"[{kind}] {source_url}")
    print(f"  -> {path}  ({len(content)} bytes)")
    if hits:
        print("  WARNING: SUSPICIOUS PATTERNS DETECTED:")
        for desc, n in hits:
            print(f"     - {desc}: {n} occurrence(s)")
    else:
        print("  No suspicious patterns detected.")
    return path.name, len(content), hits


def try_decode_obfuscated(path: Path):
    """Extract and decode Base64 blobs for further inspection."""
    text = path.read_text(errors="replace")
    blobs = re.findall(r"['\"]([A-Za-z0-9+/]{100,}={0,2})['\"]", text)
    for i, b in enumerate(blobs):
        try:
            decoded = base64.b64decode(b).decode("utf-8", errors="replace")
        except Exception:
            continue
        out = path.with_suffix(f".decoded{i}.txt")
        out.write_text(decoded, encoding="utf-8")
        print(f"  [decode] {out}  ({len(decoded)} characters)")


# ============================================================
# MAIN LOGIC
# ============================================================
def main(start_url: str):
    OUT_DIR.mkdir(exist_ok=True)
    print(f"Start URL: {start_url}")
    print(f"Output directory: {OUT_DIR.resolve()}\n")

    seen_urls = set()
    counter = 0
    suspicious = []

    with sync_playwright() as p:
        # Check whether the browser is installed
        try:
            browser = p.chromium.launch(headless=True)
        except Exception as e:
            print("ERROR: Chromium is not installed for Playwright.")
            print("Run: python -m playwright install --with-deps chromium")
            print("Details:", e)
            sys.exit(1)

        ctx = browser.new_context(
            user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/131.0.0.0 Safari/537.36"),
            locale="sr-RS",
        )
        page = ctx.new_page()

        # ---------- 1) Capture external JavaScript responses ----------
        def on_response(resp):
            nonlocal counter
            url = resp.url
            if url in seen_urls:
                return
            ct = (resp.headers.get("content-type") or "").lower()
            if "javascript" not in ct and not url.endswith(".js"):
                return
            seen_urls.add(url)
            try:
                body = resp.body()
            except Exception as e:
                print(f"  [skip] {url} — {e}")
                return
            if len(body) > MAX_SIZE:
                print(f"  [skip] {url} — file too large ({len(body)} bytes)")
                return
            counter += 1
            path = OUT_DIR / safe_name(url, counter)
            _, _, hits = save_and_scan(path, body, url, "EXTERNAL")
            if hits and not is_trusted(url):
                suspicious.append((path.name, url, hits))
            elif hits:
                suspicious.append((path.name, url, hits))

        page.on("response", on_response)

        # ---------- 2) Capture inline <script> blocks ----------
        def extract_inline():
            nonlocal counter
            try:
                scripts = page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('script:not([src])'))
                        .map(s => s.textContent || '')
                        .filter(t => t.trim().length > 0);
                }""")
            except Exception as e:
                print(f"  [inline error] {e}")
                return
            for i, code in enumerate(scripts):
                counter += 1
                name = f"{counter:03d}_inline_{i}.js"
                path = OUT_DIR / name
                content = code.encode("utf-8", errors="replace")
                fake_url = f"{start_url}#inline-script-{i}"
                _, _, hits = save_and_scan(path, content, fake_url, "INLINE")
                if hits:
                    suspicious.append((name, fake_url, hits))

        # ---------- 3) Load the website ----------
        try:
            page.goto(start_url, wait_until="networkidle", timeout=60000)
        except Exception as e:
            print(f"Error while loading the page: {e}")

        page.wait_for_timeout(WAIT_AFTER_LOAD_MS)

        # ---------- 4) Extract inline scripts ----------
        extract_inline()

        # ---------- 5) Save rendered HTML ----------
        try:
            html = page.content()
            (OUT_DIR / "_rendered.html").write_text(html, encoding="utf-8")
            print(f"\n[HTML] Rendered HTML saved ({len(html)} bytes)")
        except Exception as e:
            print(f"[HTML error] {e}")

        browser.close()

    # ============================================================
    # FINAL REPORT
    # ============================================================
    print("\n" + "=" * 70)
    print("FINAL REPORT")
    print("=" * 70)
    print(f"Total JavaScript files: {counter}")
    print(f"Saved to: {OUT_DIR.resolve()}")

    if suspicious:
        print(f"\nWARNING: SUSPICIOUS FILES ({len(suspicious)}):\n")
        for name, url, hits in suspicious:
            print(f"  {name}")
            print(f"    URL: {url}")
            for desc, n in hits:
                print(f"      - {desc}: {n} occurrence(s)")
            print()
        print("Attempting to decode Base64 blobs in suspicious files...")
        for name, _, _ in suspicious:
            try_decode_obfuscated(OUT_DIR / name)
    else:
        print("\nNo obviously suspicious JavaScript files detected.")

    # Save the report
    report = OUT_DIR / "_report.txt"
    with report.open("w", encoding="utf-8") as f:
        f.write(f"Start URL: {start_url}\n")
        f.write(f"Total JavaScript files: {counter}\n\n")
        if suspicious:
            for name, url, hits in suspicious:
                f.write(f"{name}\n  URL: {url}\n")
                for desc, n in hits:
                    f.write(f"    - {desc}: {n} occurrence(s)\n")
                f.write("\n")
        else:
            f.write("No suspicious files detected.\n")
    print(f"\nReport saved to: {report.resolve()}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python capture_js.py <URL>")
        sys.exit(1)
    main(sys.argv[1])
