#!/usr/bin/env python3
"""
Laelaps IOC defanging tests.

Threat-intel reports and detection rules write indicators "defanged" so they are
not clickable/executable: hxxp://, 1.2.3[.]4, evil[.]com, user[@]host. Laelaps
refangs them so they are still extracted, AND treats a file dense with defanged
IOCs as reference/analysis content (real malware does not defang its own C2) so a
pasted report is not mistaken for the malware it describes.

Fully offline. Run:  python3 tests/defang_test.py
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

checks = []


def check(name, cond, extra=""):
    ok = bool(cond)
    checks.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{(' -> ' + extra) if extra and not ok else ''}")


print("=== refang restores defanged IOCs ===")
check("hxxp/hxxps -> http/https and [.] -> .",
      L.refang("hxxps://evil[.]com/x") == "https://evil.com/x",
      L.refang("hxxps://evil[.]com/x"))
check("bracketed-dot IPv4 refanged", L.refang("8[.]8[.]8[.]8") == "8.8.8.8")
check("[@] and [dot] refanged", L.refang("user[@]bad[dot]tld") == "user@bad.tld",
      L.refang("user[@]bad[dot]tld"))
check("(.) and {.} variants refanged", L.refang("a(.)b{.}c") == "a.b.c", L.refang("a(.)b{.}c"))
check("clean text is unchanged", L.refang("normal http://ok.com/path") == "normal http://ok.com/path")
check("count_defanged counts markers", L.count_defanged("hxxp://a[.]b x[@]y 1[.]2") == 4,
      str(L.count_defanged("hxxp://a[.]b x[@]y 1[.]2")))
check("count_defanged is 0 on clean text", L.count_defanged("nothing defanged here at all") == 0)

print("=== defanged IOCs are extracted ===")
iocs = L.v2_extract_iocs(["c2: hxxps://malware-c2[.]top/gate.php", "drop 45[.]66[.]77[.]88"])
check("refanged URL extracted", "https://malware-c2.top/gate.php" in iocs.get("urls", []), str(iocs.get("urls")))
check("refanged domain extracted", "malware-c2.top" in iocs.get("domains", []), str(iocs.get("domains")))
check("refanged IPv4 extracted", "45.66.77.88" in iocs.get("ipv4", []), str(iocs.get("ipv4")))

print("=== a threat-intel report is dampened, but its IOCs are surfaced ===")
report = ("LummaC2 infrastructure writeup. C2: hxxps://setup-code[.]com/gate and "
          "hxxps://code-setup[.]com/api; payloads at 193[.]43[.]12[.]5 and 45[.]66[.]77[.]88; "
          "exfil to hxxp://evil[.]top; drop mailbox report[@]bad[.]tld; panel hxxps://gate[.]xyz/p")
rp = os.path.join(tempfile.mkdtemp(), "lumma-report.txt")
open(rp, "w").write(report)
rep = L.analyze_file_v2(rp, use_llm=False)
check("report triaged as reference content", rep.reference_only is True)
check("report is NOT called malicious", rep.verdict != "malicious", rep.verdict)
check("report's IOCs are still extracted", sum(len(v) for v in rep.iocs.values()) >= 4,
      str(rep.iocs))

print("=== real malware (fanged IOCs, no defang) is not falsely dampened ===")
mal = os.path.join(tempfile.mkdtemp(), "stealer.bin")
open(mal, "wb").write(b"LummaC2 lid=1 soft_id=2 Login Data wallet.dat "
                      b"https://api.telegram.org/bot123456789:AAF_kd9slUabcd_ZZ00000000000/x")
repm = L.analyze_file_v2(mal, use_llm=False)
check("real stealer is not flagged reference_only", repm.reference_only is False)
check("real stealer stays malicious", repm.verdict == "malicious", repm.verdict)

passed, total = sum(checks), len(checks)
print(f"\n=== {passed}/{total} checks passed ===")
sys.exit(0 if passed == total else 1)
