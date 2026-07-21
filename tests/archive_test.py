#!/usr/bin/env python3
"""
Laelaps archive-aware scanning tests.

Game repacks bundle the installer/crack inside .zip / .7z archives. These build
inert archives (an EICAR-style recognition fixture as the "trojaned installer",
no working payload) and assert Laelaps expands them, scans each member in place,
names the offending inner file, and rolls the members up into the archive's verdict.

Fully offline. Run:  python3 tests/archive_test.py
"""
import io
import os
import sys
import tempfile
import zipfile

os.environ["LAELAPS_OFFLINE"] = "1"
os.environ.pop("ANTHROPIC_API_KEY", None)
os.environ.pop("OPENAI_API_KEY", None)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import laelaps as L  # noqa: E402

try:
    import py7zr
except Exception:
    py7zr = None

checks = []


def check(name, cond, extra=""):
    ok = bool(cond)
    checks.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{(' -> ' + extra) if extra and not ok else ''}")


TROJAN = (b"MZ" + b"\x90" * 80 + b"This program cannot be run in DOS mode\x00"
          b"VirtualAllocEx WriteProcessMemory CreateRemoteThread "
          b"LummaC2 lid=1 soft_id=2 Login Data wallet.dat "
          b"https://api.telegram.org/bot123456789:AAF_kd9slUabcd_ZZ00000000000/x")
BENIGN = b"just a readme for the repack, nothing to run here"

d = tempfile.mkdtemp(prefix="laelaps_arc_")

# a .zip bundling a trojaned installer + a benign file
with zipfile.ZipFile(os.path.join(d, "Installer.zip"), "w") as z:
    z.writestr("setup.exe", TROJAN)
    z.writestr("readme.txt", BENIGN)

# a nested zip: outer.zip -> inner.zip -> setup.exe
inner_buf = io.BytesIO()
with zipfile.ZipFile(inner_buf, "w") as iz:
    iz.writestr("setup.exe", TROJAN)
with zipfile.ZipFile(os.path.join(d, "outer.zip"), "w") as oz:
    oz.writestr("inner.zip", inner_buf.getvalue())

# a .7z bundling a trojaned installer (FitGirl-style), if py7zr is present
if py7zr is not None:
    with py7zr.SevenZipFile(os.path.join(d, "fitgirl-setup.7z"), "w") as z:
        z.writestr(TROJAN, "crack/setup.exe")

print("=== directory with bundled archives ===")
b = L.scan_directory(d, max_full_mb=64)
by = {v.relpath.replace("\\", "/"): v for v in b.files}
check("overall verdict is malicious", b.verdict == "malicious", b.verdict)
check("zip container flagged malicious", by.get("Installer.zip") and by["Installer.zip"].verdict == "malicious")
check("inner setup.exe flagged malicious",
      by.get("Installer.zip::setup.exe") and by["Installer.zip::setup.exe"].verdict == "malicious")
check("inner setup.exe attributed to LummaC2",
      by.get("Installer.zip::setup.exe") and
      any("Lumma" in f for f in by["Installer.zip::setup.exe"].families))
check("inner readme stays clean",
      by.get("Installer.zip::readme.txt") and by["Installer.zip::readme.txt"].verdict == "clean")
check("nested zip-in-zip member reached and flagged",
      by.get("outer.zip::inner.zip::setup.exe") and
      by["outer.zip::inner.zip::setup.exe"].verdict == "malicious")

if py7zr is not None:
    print("=== .7z expansion (the format repacks actually use) ===")
    check("7z container flagged malicious",
          by.get("fitgirl-setup.7z") and by["fitgirl-setup.7z"].verdict == "malicious")
    check("7z inner crack/setup.exe flagged",
          by.get("fitgirl-setup.7z::crack/setup.exe") and
          by["fitgirl-setup.7z::crack/setup.exe"].verdict == "malicious")

    print("=== single .7z file via scan_archive_file ===")
    b2 = L.scan_archive_file(os.path.join(d, "fitgirl-setup.7z"))
    check("single .7z scan is malicious", b2.verdict == "malicious", b2.verdict)
    check("single .7z lists the inner member",
          any("crack/setup.exe" in v.relpath for v in b2.files))
else:
    print("  (py7zr not installed; skipping .7z checks)")

print("=== --no-archives leaves archives opaque (no member expansion) ===")
bn = L.scan_directory(d, max_full_mb=64, expand_archives=False)
check("no '::' member entries when expansion disabled",
      not any("::" in v.relpath for v in bn.files))

print("=== password-protected 7z is suspicious even when opaque ===")
if py7zr is not None:
    locked = os.path.join(d, "locked.7z")
    made = False
    try:
        with py7zr.SevenZipFile(locked, "w", password="secret") as z:
            z.set_encrypted_header(True)
            z.writestr(TROJAN, "setup.exe")
        made = True
    except Exception:
        made = False
    if made:
        bl = L.scan_archive_file(locked)
        check("password-protected archive flagged suspicious+",
              bl.verdict in ("suspicious", "malicious"), bl.verdict)
    else:
        print("  (could not create an encrypted 7z here; skipping)")
else:
    print("  (py7zr not installed; skipping)")

passed, total = sum(checks), len(checks)
print(f"\n=== {passed}/{total} checks passed ===")
sys.exit(0 if passed == total else 1)
