#!/usr/bin/env python3
"""
Laelaps icon perceptual-hashing tests.

Fake installers and cracks in a download reuse a real brand/game icon, and a
dropper often ships the same payload under many names behind one icon. Laelaps
computes a perceptual icon hash (dhash) so those cluster together. These tests
cover the dhash, the PE .ico reconstruction, graceful handling of non-icon input,
and the bulk icon-reuse detector. Fully offline.

Run:  python3 tests/icon_test.py
"""
import io
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

try:
    from PIL import Image, ImageDraw
except Exception:
    print("Pillow not installed; skipping icon tests (they require PIL)")
    sys.exit(0)

checks = []


def check(name, cond, extra=""):
    ok = bool(cond)
    checks.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{(' -> ' + extra) if extra and not ok else ''}")


def badge(color, tweak=False):
    im = Image.new("RGB", (48, 48), "white")
    d = ImageDraw.Draw(im)
    d.rectangle([6, 6, 42, 42], fill=color)
    d.ellipse([16, 16, 32, 32], fill="white")
    if tweak:
        d.line([8, 8, 40, 40], fill="black", width=2)
    return im


def checkerboard():
    im = Image.new("RGB", (48, 48), "white")
    d = ImageDraw.Draw(im)
    for y in range(0, 48, 8):
        for x in range(0, 48, 8):
            if (x // 8 + y // 8) % 2 == 0:
                d.rectangle([x, y, x + 7, y + 7], fill="black")
    return im


def png_bytes(im):
    b = io.BytesIO()
    im.save(b, "PNG")
    return b.getvalue()


print("=== dhash basics ===")
a = png_bytes(badge("blue"))
a2 = png_bytes(badge("red"))            # same shape, recolored (icon reuse should still cluster)
near = png_bytes(badge("blue", tweak=True))
diff = png_bytes(checkerboard())        # genuinely different shape
ha, hna, hd, ha2 = (L.image_dhash(x) for x in (a, near, diff, a2))
check("dhash is 16 hex chars", isinstance(ha, str) and len(ha) == 16, str(ha))
check("identical image -> distance 0", L.image_dhash(a) == ha)
check("near-duplicate icon is close (<= 10)", L.icon_distance(ha, hna) <= 10, str(L.icon_distance(ha, hna)))
check("recolored same-shape icon is close (<= 10)", L.icon_distance(ha, ha2) <= 10, str(L.icon_distance(ha, ha2)))
check("different shape is far (> 12)", L.icon_distance(ha, hd) > 12, str(L.icon_distance(ha, hd)))

print("=== .ico reconstruction round-trip ===")
buf = io.BytesIO()
badge("blue").save(buf, format="ICO", sizes=[(32, 32)])
ico = buf.getvalue()
_res, _typ, count = struct.unpack_from("<HHH", ico, 0)
grp = struct.pack("<HHH", 0, 1, count)
icons = {}
off = 6
for i in range(count):
    bW, bH, bCC, bR, wP, wB, dwB, dwOff = struct.unpack_from("<BBBBHHII", ico, off)
    off += 16
    grp += struct.pack("<BBBBHHIH", bW, bH, bCC, bR, wP, wB, dwB, i + 1)
    icons[i + 1] = ico[dwOff:dwOff + dwB]
rebuilt = L._build_ico_from_group(grp, icons)
check("rebuilt a valid .ico from a GRPICONDIR", bool(rebuilt) and L.image_dhash(rebuilt) is not None)
check("rebuilt icon matches the original", rebuilt and L.icon_distance(L.image_dhash(rebuilt), L.image_dhash(ico)) <= 4)

print("=== graceful handling of non-icon input ===")
check("extract_pe_icon(fake PE) is None", L.extract_pe_icon(b"MZ" + b"\x00" * 300) is None)
check("extract_pe_icon(non-PE) is None", L.extract_pe_icon(b"not a pe at all") is None)
check("file_icon_dhash of a text type is None", L.file_icon_dhash(b"hello", "PowerShell script") is None)

print("=== surfaced in the report + bulk icon-reuse ===")
d = tempfile.mkdtemp(prefix="laelaps_icon_")
open(os.path.join(d, "SteamSetup.png"), "wb").write(a)
open(os.path.join(d, "GameCrack.png"), "wb").write(near)   # same icon as SteamSetup
open(os.path.join(d, "unrelated.png"), "wb").write(diff)   # different shape
rep = L.analyze_file_v2(os.path.join(d, "SteamSetup.png"), use_llm=False)
check("icon_dhash surfaced in the file report", bool(rep.hashes.get("icon_dhash")))
b = L.scan_directory(d, max_full_mb=64)
reuse_notes = [n for n in b.notes if "icon reuse" in n]
check("bulk flags the reused icon", bool(reuse_notes), str(b.notes))
check("reuse note names the two matching files, not the different one",
      reuse_notes and "SteamSetup.png" in reuse_notes[0] and "GameCrack.png" in reuse_notes[0]
      and "unrelated.png" not in reuse_notes[0], str(reuse_notes))

passed, total = sum(checks), len(checks)
print(f"\n=== {passed}/{total} checks passed ===")
sys.exit(0 if passed == total else 1)
