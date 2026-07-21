#!/usr/bin/env python3
"""
Laelaps clustering-hash tests: authentihash (PE) and elf_symhash (ELF).

- authentihash is the Authenticode hash: the PE with its checksum and signature
  excluded, so the same code re-signed with a different certificate still matches.
  We test the core skip-logic directly (no signed PE needed) and graceful handling.
- elf_symhash is the imphash analog for ELF (md5 of sorted imported symbol names).
  We test it against real system ELF binaries, which are always present on Linux.

Fully offline. Run:  python3 tests/hashpivot_test.py
"""
import os
import sys

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


print("=== authentihash: checksum + signature excluded, code included ===")
base = bytearray(b"A" * 120)
CS, SE, CO, CZ = 64, 80, 96, 8   # checksum_off, security-entry_off, cert_off, cert_size
h0 = L._authentihash_core(bytes(base), CS, SE, CO, CZ)


def mutated(pos, repl):
    m = bytearray(base)
    m[pos:pos + len(repl)] = repl
    return bytes(m)


check("changing the CheckSum does not change the hash",
      L._authentihash_core(mutated(CS, b"ZZZZ"), CS, SE, CO, CZ) == h0)
check("changing the Security dir entry does not change the hash",
      L._authentihash_core(mutated(SE, b"YYYYYYYY"), CS, SE, CO, CZ) == h0)
check("changing the certificate blob does not change the hash",
      L._authentihash_core(mutated(CO, b"XXXXXXXX"), CS, SE, CO, CZ) == h0)
check("changing the code DOES change the hash",
      L._authentihash_core(mutated(0, b"B"), CS, SE, CO, CZ) != h0)
check("pe_authentihash(fake PE) is None (graceful)", L.pe_authentihash(b"MZ" + b"\x00" * 400) is None)
check("pe_authentihash(non-PE) is None", L.pe_authentihash(b"not a pe") is None)

print("=== elf_symhash against real system ELF binaries ===")
if L.get_lief() is None:
    print("  (lief not installed; skipping ELF checks)")
else:
    candidates = [sys.executable, "/bin/ls", "/bin/cat", "/bin/sh", "/usr/bin/env"]
    elves = [p for p in candidates if p and os.path.isfile(p) and open(p, "rb").read(4) == b"\x7fELF"]
    check("found at least one real ELF to test", len(elves) >= 1, str(elves))
    if elves:
        data = open(elves[0], "rb").read()
        h1 = L.elf_symhash(data)
        check("elf_symhash is a 32-char md5", isinstance(h1, str) and len(h1) == 32, str(h1))
        check("elf_symhash is deterministic", L.elf_symhash(data) == h1)
        rep = L.analyze_file_v2(elves[0], use_llm=False)
        check("elf_symhash surfaced in the report", rep.hashes.get("elf_symhash") == h1)
    # two different ELFs should hash differently (different import sets)
    distinct = []
    for p in elves:
        hh = L.elf_symhash(open(p, "rb").read())
        if hh and hh not in distinct:
            distinct.append(hh)
    if len(elves) >= 2:
        check("different ELFs produce different symbol hashes", len(distinct) >= 2, str(distinct))
    check("elf_symhash(fake ELF) is None", L.elf_symhash(b"\x7fELF" + b"\x00" * 60) is None)
    check("elf_symhash(non-ELF) is None", L.elf_symhash(b"MZ not an elf") is None)

passed, total = sum(checks), len(checks)
print(f"\n=== {passed}/{total} checks passed ===")
sys.exit(0 if passed == total else 1)
