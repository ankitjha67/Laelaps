#!/usr/bin/env python3
"""
Laelaps bulk / large-target scanner tests.

Simulates the real use case: a large game repack (as you'd pull from a torrent)
containing a trojaned installer, a benign readme, and a big data blob with an
executable smuggled in as an overlay. Asserts Laelaps flags the installer, keeps
the readme clean, samples the huge blob instead of reading it whole, and collapses
the tree to one malicious verdict that names the offender.

All samples are inert recognition fixtures - no working payload, no real
infrastructure. Fully offline.

Run:  python3 tests/bulk_test.py
Exit: 0 if every check passes, 1 otherwise.
"""
import json
import os
import subprocess
import sys
import tempfile

os.environ["LAELAPS_OFFLINE"] = "1"
os.environ.pop("ANTHROPIC_API_KEY", None)
os.environ.pop("OPENAI_API_KEY", None)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import laelaps as L  # noqa: E402

checks = []


def check(name, cond, extra=""):
    ok = bool(cond)
    checks.append(ok)
    tail = f"  -> {extra}" if (extra and not ok) else ""
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{tail}")


# ---- build a synthetic repack ------------------------------------------------
repack = tempfile.mkdtemp(prefix="laelaps_repack_")
# trojaned installer (small -> full analysis): PE marker + injection trio + Lumma markers
with open(os.path.join(repack, "setup.exe"), "wb") as f:
    f.write(b"MZ" + b"\x90" * 80 + b"This program cannot be run in DOS mode\x00"
            b"VirtualAllocEx WriteProcessMemory CreateRemoteThread "
            b"LummaC2 lid=1 soft_id=2 Login Data wallet.dat "
            b"https://api.telegram.org/bot123456789:AAF_kd9slUabcd_ZZ00000000000/x")
# benign readme
with open(os.path.join(repack, "readme.txt"), "w") as f:
    f.write("Thanks for downloading this game repack. Install and enjoy!")
# large opaque data blob with an executable smuggled in as an overlay
os.makedirs(os.path.join(repack, "data"), exist_ok=True)
blob = bytearray(2 * 1024 * 1024)
blob += b"MZ" + b"This program cannot be run in DOS mode\x00" + b"\x00" * 256
with open(os.path.join(repack, "data", "fg-01.bin"), "wb") as f:
    f.write(blob)

print("=== directory (repack) scan ===")
# max_full_mb=1 so the 2 MB blob exercises the sampled path
b = L.scan_directory(repack, max_full_mb=1)
by = {v.relpath.replace("\\", "/"): v for v in b.files}
check("overall verdict is malicious", b.verdict == "malicious", b.verdict)
check("all three files scanned", b.scanned == 3, str(b.scanned))
check("setup.exe -> malicious", by.get("setup.exe") and by["setup.exe"].verdict == "malicious")
check("setup.exe attributed to LummaC2",
      by.get("setup.exe") and any("Lumma" in fam for fam in by["setup.exe"].families))
check("readme.txt -> clean", by.get("readme.txt") and by["readme.txt"].verdict == "clean")
check("large blob was sampled (not read whole)", by.get("data/fg-01.bin") and by["data/fg-01.bin"].sampled)
check("blob's embedded executable surfaced",
      by.get("data/fg-01.bin") and "Embedded executable" in by["data/fg-01.bin"].top_reason)
check("setup.exe present in flagged list", any(v.relpath == "setup.exe" for v in b.flagged))
check("worst score is 100", b.score == 100.0, str(b.score))

print("=== large single-file sampled scan (200 MB sparse) ===")
big = os.path.join(repack, "huge.pak")
with open(big, "wb") as f:
    f.truncate(200 * 1024 * 1024)             # sparse zeros; not physically 200 MB on disk
    f.seek(200 * 1024 * 1024 - 200)
    f.write(b"MZ" + b"This program cannot be run in DOS mode\x00" + b"\x00" * 100)
rep = L.analyze_large_file(big)
check("reports true file size (200 MB)", rep.size_bytes == 200 * 1024 * 1024, str(rep.size_bytes))
check("hash is a partial head+tail fingerprint", rep.hashes.get("partial") == "true")
check("sampled-scan note present", any("sampled scan" in n for n in rep.notes))
check("embedded executable detected in overlay",
      any("Embedded executable" in s.title for s in rep.signals))
check("--full-hash yields a true sha256",
      bool(L.analyze_large_file(big, full_hash=True).hashes.get("sha256")))

print("=== CLI: directory scan exit code + JSON ===")
r = subprocess.run([sys.executable, os.path.join(ROOT, "laelaps.py"), repack, "--json", "--offline"],
                   capture_output=True, text=True)
check("CLI dir scan exits 1 (malicious)", r.returncode == 1, str(r.returncode))
parsed = {}
try:
    parsed = json.loads(r.stdout)
except Exception as e:
    check("CLI dir scan emits valid JSON", False, str(e))
else:
    check("CLI dir scan emits valid JSON", True)
check("CLI JSON verdict is malicious and directory-flagged",
      parsed.get("verdict") == "malicious" and parsed.get("is_directory") is True)

print("=== CLI: oversized single file routed to the sampled scanner ===")
r2 = subprocess.run([sys.executable, os.path.join(ROOT, "laelaps.py"), big, "--offline", "--report"],
                    capture_output=True, text=True)
check("CLI large-file report mentions the sampled scan", "sampled scan" in r2.stdout)

passed = sum(checks)
total = len(checks)
print(f"\n=== {passed}/{total} checks passed ===")
sys.exit(0 if passed == total else 1)
