#!/usr/bin/env python3
"""
Laelaps attribution corpus - breadth check across malware families.

For each family, an inert sample carrying that family's PUBLIC string markers
(the same recognition tokens threat-intel teams publish) plus category-relevant
context is scanned; the test asserts Laelaps attributes the right family and the
right category. These samples are recognition fixtures, not working malware: no
payload, no entrypoint, no live infrastructure.

We deliberately do NOT download real/live samples (e.g. from MalwareBazaar or the
OWASP corpus): that is network-gated here and unsafe to detonate in a shared
container. The synthetic markers exercise the same attribution code path.

Also headless-renders the Streamlit report functions through a fake `st` so the
UI wiring is verified without a browser.

Run:  python3 tests/corpus_test.py
Exit: 0 if every family is attributed with the correct category, 1 otherwise.
"""
import os
import sys
import tempfile

os.environ["LAELAPS_OFFLINE"] = "1"
os.environ.pop("ANTHROPIC_API_KEY", None)
os.environ.pop("OPENAI_API_KEY", None)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import laelaps as L  # noqa: E402

TMP = tempfile.mkdtemp(prefix="laelaps_corpus_")

# (expected family substring, expected category, inert marker text)
CORPUS = [
    ("LummaC2", "infostealer",
     "LummaC2 lid=42 soft_id=7 Login Data wallet.dat "
     "https://api.telegram.org/bot123456789:AAF_kd9slUabcdefgh_ZZ0000000000000/x"),
    ("RedLine", "infostealer", "RedLine Leaf.xNet ScannedWallet BrowserExtension Login Data wallet.dat"),
    ("Vidar", "infostealer", "Vidar https://steamcommunity.com/profiles/76561199000000000 wallet.dat Login Data"),
    ("StealC", "infostealer", "StealC http://host/a1b2c3d4.php Login Data wallet.dat"),
    ("Raccoon", "infostealer", "Raccoon RecordBreaker https://t.me/rcconfig Login Data wallet.dat"),
    ("AgentTesla", "keylogger",
     "AgentTesla GetAsyncKeyState Login Data api.telegram.org/bot123456789:AAF_kd9slUabcd_ZZ00000000000/x"),
    ("Snake Keylogger", "keylogger",
     "Snake Keylogger GetAsyncKeyState api.telegram.org/bot123456789:AAF_kd9slUabcd_ZZ00000000000/x"),
    ("AsyncRAT", "rat", "AsyncRAT AsyncClient reverse shell remote desktop keylog"),
    ("Quasar", "rat", "Quasar Quasar.Common remote desktop GetAsyncKeyState Login Data"),
    ("njRAT", "rat", "njRAT Bladabindi njq8 remote shell keylog"),
    ("Remcos", "rat", "Remcos Breaking-Security remote control GetAsyncKeyState"),
    ("NanoCore", "rat", "NanoCore nanotechnology screen capture remote shell"),
    ("DCRat", "rat", "DCRat Dark Crystal keylog remote desktop"),
    ("Cobalt Strike", "framework", "beacon.dll ReflectiveLoader %s (admin) \\\\.\\pipe\\msse-1234"),
    ("Meterpreter", "framework", "meterpreter metsrv stdapi priv_passwd_get_sam_hashes"),
    ("Amadey", "loader", "Amadey http://host/index.php downloadfile fingerprint"),
    ("SmokeLoader", "loader", "SmokeLoader downloadfile IsDebuggerPresent"),
    ("Emotet", "loader", "Emotet downloadstring"),
    ("LockBit", "ransomware", "LockBit Restore-My-Files .lockbit vssadmin.exe delete shadows"),
    ("Conti", "ransomware", "conti CONTI_LOG your files have been encrypted"),
    ("BlackCat", "ransomware", "BlackCat ALPHV recover-files.txt your files have been encrypted"),
]

results = []
print("\n=== Laelaps attribution corpus (offline) ===\n")
print(f"{'expected family':<22} {'category':<12} {'attributed?':<11} verdict")
print("-" * 70)

for i, (fam_sub, cat, text) in enumerate(CORPUS):
    p = os.path.join(TMP, f"sample_{i:02d}.bin")
    with open(p, "w") as f:
        f.write(text + "\n")
    rep = L.analyze_file_v2(p)
    match = next((f for f in rep.families if fam_sub.lower() in f.family.lower()), None)
    cat_ok = bool(match) and match.category == cat
    fam_ok = bool(match)
    ok = fam_ok and cat_ok and rep.verdict != "clean"
    results.append(ok)
    got = (f"{match.family} ({match.category})" if match else "MISS")
    print(f"{fam_sub:<22} {cat:<12} {('yes' if fam_ok else 'NO'):<11} "
          f"{rep.verdict:<10} -> {got}")
    if not ok and not fam_ok:
        print(f"    families seen: {[f.family for f in rep.families]}")

passed = sum(results)
total = len(results)
print("-" * 70)
print(f"{passed}/{total} families attributed with correct category")

# --- headless Streamlit render wiring check --------------------------------
print("\n=== Streamlit report renderers (headless via fake st) ===")


class _FakeSt:
    """Records nothing; just proves every field access in the renderers is valid."""
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def columns(self, spec):
        n = spec if isinstance(spec, int) else len(spec)
        return [self] * n

    def __getattr__(self, _name):
        def _noop(*a, **k):
            return self
        return _noop


ui_ok = True
try:
    lumma = os.path.join(TMP, "sample_00.bin")
    rep = L.analyze_file_v2(lumma)
    L._streamlit_render_v2(rep, _FakeSt())
    ures = L.scan_url("https://setup-code.com/VSCode-Setup.exe", deep=False)
    L._streamlit_render_url(ures, _FakeSt())
    print("  [PASS] _streamlit_render_v2 + _streamlit_render_url access V2Report/URL fields cleanly")
except Exception as e:
    ui_ok = False
    print(f"  [FAIL] Streamlit renderer raised: {type(e).__name__}: {e}")

if passed == total and ui_ok:
    print("\nALL CORPUS + UI CHECKS PASS")
    sys.exit(0)
print("\nFAILURES present")
sys.exit(1)
