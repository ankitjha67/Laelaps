#!/usr/bin/env python3
"""
LAELAPS - One-Stop Malware Detection, Attribution & Threat-Intel Engine (defensive)
===================================================================================
Laelaps is the hound of Greek myth fated to always catch what it hunts. This is a
single-file, DEFENSIVE malware analyzer: point it at a file, a URL, or a hash and it
fuses a deep static-analysis engine with a threat-intel attribution engine to tell
you WHAT the sample is (infostealer / RAT / loader / ransomware / banker / clipper /
keylogger), WHICH known family, WHAT it steals and how it exfiltrates, and HOW it is
distributed - then writes an analyst-grade threat report. It only inspects and
reports; it performs no malicious action. Same category as YARA, oletools,
VirusTotal tooling, or a SOC triage script.

This monolith combines two engines in one namespace:

  DEEP STATIC ENGINE (file-format aware)
    1.  Multi-hash reputation (VirusTotal, MalwareBazaar, ThreatFox)
    2.  YARA rule matching (built-in pack + custom directory)
    3.  Format-aware parsing (PE, ELF, Mach-O, PDF, Office/OLE, DEX/APK, scripts)
    4.  Entropy & packer detection (whole-file + sliding-window)
    5.  Static IOC extraction (URLs, IPs, domains, wallets, C2 patterns)
    6.  Suspicious API import heuristics (injection trio, hollowing, keylogger)
    7.  Macro / embedded-script analysis (VBA, XLM, PDF JS, PowerShell decode)
    8.  Archive expansion & recursive analysis (zip-slip / zip-bomb aware)
    9.  Steganography checks on images
    10. CVE / exploit pattern matching (Log4Shell, Follina, EternalBlue, ...)
    11. MITRE ATT&CK technique mapping
    12. LLM-powered verdict reasoning (optional)

  ATTRIBUTION & THREAT-INTEL ENGINE
    A. Malware family attribution (signature DB for ~30 major families)
    B. Loader / packer / wrapper detection (Electron, NSIS, Themida, VMProtect, ...)
    C. Electron / ASAR analysis
    D. .NET / CLR analysis
    E. Brand-impersonation / typosquat detection
    F. C2 protocol fingerprinting (Telegram, Discord webhook, dead-drops, gate.php)
    G. Credential / wallet target enumeration
    H. Behavioral capability profiling
    I. Persistence / autorun scanner
    J. Sigma-style behavioral correlation
    K. Family YARA pack
    L. URL / link scanner (structure + reputation, optional deep fetch)
    M. Analyst-grade threat-report generator

Usage:
    python laelaps.py <file>                 # full analysis + threat report
    python laelaps.py <file> --report        # only the Markdown report
    python laelaps.py <file> --json          # machine-readable
    python laelaps.py --url <url>            # scan a link (structure + reputation)
    python laelaps.py --url <url> --deep     # download the payload & analyze (sandbox!)
    python laelaps.py <md5|sha1|sha256>      # reputation-only hash lookup
    python laelaps.py <target> --offline     # never touch the network
    python laelaps.py --api                  # launch the REST API server
    python laelaps.py --ui                   # launch the Streamlit web UI

Optional environment (more keys = more coverage, all optional):
    VT_API_KEY, MB_API_KEY, ABUSECH_API_KEY, URLSCAN_API_KEY,
    ANTHROPIC_API_KEY, OPENAI_API_KEY, LAELAPS_YARA_RULES_DIR
    LAELAPS_OFFLINE=1  -> skip every network call

  !! AUTHORIZED ANALYSIS ONLY. Analyze unknown samples inside a disposable VM or
     container with no network egress. Reading a malicious file into memory for
     static analysis does not execute it, but do not run --deep against a live
     payload outside a sandbox. !!
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import json
import math
import os
import re
import shutil
import string
import struct
import subprocess
import sys
import tempfile
import time
import warnings
import zipfile
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

warnings.filterwarnings("ignore")

# ==============================================================================
# DEPENDENCY MANAGEMENT
# ==============================================================================

def _ensure(pkg: str, import_as: Optional[str] = None) -> Any:
    """Import package, pip-install if missing. Returns module or None on failure."""
    name = import_as or pkg.split("[")[0].replace("-", "_")
    try:
        return __import__(name)
    except ImportError:
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "-q", "--break-system-packages", pkg],
                stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            )
            return __import__(name)
        except Exception:
            return None


# Core dependencies (always needed)
requests = _ensure("requests")

# Optional analyzers (loaded lazily)
_pefile = None
_magic = None
_yara = None
_oletools = None
_pdfminer = None
_lief = None
_androguard = None
_PIL = None
_numpy = None
_tlsh = None
_anthropic = None
_openai = None

def get_pefile():
    global _pefile
    if _pefile is None:
        _pefile = _ensure("pefile")
    return _pefile

def get_magic():
    global _magic
    if _magic is None:
        _magic = _ensure("python-magic", "magic")
    return _magic

def get_yara():
    global _yara
    if _yara is None:
        _yara = _ensure("yara-python", "yara")
    return _yara

def get_oletools():
    global _oletools
    if _oletools is None:
        _ensure("oletools")
        try:
            from oletools import olevba, oleid, mraptor
            _oletools = {"olevba": olevba, "oleid": oleid, "mraptor": mraptor}
        except Exception:
            _oletools = {}
    return _oletools

def get_pdfminer():
    global _pdfminer
    if _pdfminer is None:
        _pdfminer = _ensure("pdfminer.six", "pdfminer")
    return _pdfminer

def get_lief():
    global _lief
    if _lief is None:
        _lief = _ensure("lief")
    return _lief

def get_androguard():
    global _androguard
    if _androguard is None:
        _androguard = _ensure("androguard")
    return _androguard

def get_pil():
    global _PIL
    if _PIL is None:
        _ensure("Pillow", "PIL")
        try:
            from PIL import Image
            _PIL = Image
        except Exception:
            _PIL = None
    return _PIL

def get_numpy():
    global _numpy
    if _numpy is None:
        _numpy = _ensure("numpy")
    return _numpy

def get_tlsh():
    global _tlsh
    if _tlsh is None:
        _tlsh = _ensure("python-tlsh", "tlsh")
    return _tlsh

def get_anthropic():
    global _anthropic
    if _anthropic is None:
        _anthropic = _ensure("anthropic")
    return _anthropic

def get_openai():
    global _openai
    if _openai is None:
        _openai = _ensure("openai")
    return _openai


# ==============================================================================
# DATA MODELS
# ==============================================================================

@dataclass
class Indicator:
    """A single indicator of compromise or suspicion."""
    layer: str                              # which detection layer produced this
    category: str                           # 'malicious' | 'suspicious' | 'informational'
    severity: str                           # 'critical' | 'high' | 'medium' | 'low' | 'info'
    title: str
    detail: str
    evidence: Optional[str] = None
    mitre_attack: List[str] = field(default_factory=list)
    confidence: float = 0.5                 # 0-1


@dataclass
class Verdict:
    """Final analysis verdict."""
    filepath: str
    filename: str
    size_bytes: int
    filetype: str
    hashes: Dict[str, str]
    verdict: str                            # 'malicious' | 'suspicious' | 'clean' | 'unknown'
    score: float                            # 0-100
    indicators: List[Indicator] = field(default_factory=list)
    families: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    ioc_extracted: Dict[str, List[str]] = field(default_factory=dict)
    reputation: Dict[str, Any] = field(default_factory=dict)
    llm_summary: Optional[str] = None
    analysis_time_seconds: float = 0.0
    timestamp: str = ""
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["indicators"] = [asdict(i) for i in self.indicators]
        return d


# ==============================================================================
# LAYER 1: HASH COMPUTATION
# ==============================================================================

def compute_hashes(data: bytes) -> Dict[str, str]:
    """Compute every common hash used in threat intel."""
    hashes = {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }
    # Fuzzy hashes for family attribution
    tlsh = get_tlsh()
    if tlsh:
        try:
            th = tlsh.hash(data)
            if th and th != "TNULL":
                hashes["tlsh"] = th
        except Exception:
            pass

    # ssdeep is often unavailable on Windows so we try but tolerate absence
    try:
        import ssdeep
        hashes["ssdeep"] = ssdeep.hash(data)
    except Exception:
        pass

    # imphash (import hash) computed later if PE

    return hashes


# ==============================================================================
# LAYER 2: FILE TYPE DETECTION
# ==============================================================================

MAGIC_SIGNATURES = {
    b"MZ": "PE (Windows Executable)",
    b"\x7fELF": "ELF (Linux Executable)",
    b"\xfe\xed\xfa\xce": "Mach-O 32-bit",
    b"\xfe\xed\xfa\xcf": "Mach-O 64-bit",
    b"\xca\xfe\xba\xbe": "Mach-O Universal / Java Class",
    b"\xcf\xfa\xed\xfe": "Mach-O 64-bit (LE)",
    b"PK\x03\x04": "ZIP / Office / JAR / APK",
    b"Rar!": "RAR archive",
    b"7z\xbc\xaf\x27\x1c": "7-Zip archive",
    b"\x1f\x8b\x08": "gzip",
    b"BZh": "bzip2",
    b"\xfd7zXZ\x00": "XZ",
    b"%PDF": "PDF document",
    b"\xd0\xcf\x11\xe0": "OLE (Legacy Office)",
    b"\x25\x21PS": "PostScript",
    b"\x89PNG": "PNG image",
    b"\xff\xd8\xff": "JPEG image",
    b"GIF8": "GIF image",
    b"BM": "BMP image",
    b"RIFF": "RIFF (AVI/WAV)",
    b"dex\n": "DEX (Android)",
    b"<!DOCTYPE": "HTML document",
    b"<html": "HTML document",
    b"<?xml": "XML document",
    b"#!/": "Shell script",
    b"@echo": "Batch script",
    b"function": "JavaScript",
    b"import ": "Python-like script",
}


def detect_filetype(data: bytes, filepath: str) -> str:
    """Detect file type via magic bytes + libmagic + extension fallback."""
    header = data[:64] if len(data) >= 64 else data

    # Try magic bytes first
    for sig, ftype in MAGIC_SIGNATURES.items():
        if header.startswith(sig):
            # ZIP polymorphism: disambiguate
            if sig == b"PK\x03\x04":
                if b"AndroidManifest.xml" in data[:100000]:
                    return "APK (Android package)"
                if b"word/" in data[:100000] or b"[Content_Types].xml" in data[:5000]:
                    return "OOXML (Office Open XML)"
                if b"META-INF/" in data[:100000]:
                    return "JAR / signed archive"
                return "ZIP archive"
            return ftype

    # libmagic if available
    magic = get_magic()
    if magic:
        try:
            return magic.from_buffer(data)
        except Exception:
            pass

    # Extension fallback
    ext = Path(filepath).suffix.lower()
    ext_map = {
        ".ps1": "PowerShell script",
        ".vbs": "VBScript",
        ".js": "JavaScript",
        ".hta": "HTML Application",
        ".lnk": "Windows shortcut",
        ".chm": "Compiled HTML Help",
        ".rtf": "Rich Text Format",
        ".doc": "MS Word (legacy)",
        ".xls": "MS Excel (legacy)",
        ".ppt": "MS PowerPoint (legacy)",
        ".docx": "MS Word",
        ".xlsx": "MS Excel",
        ".pptx": "MS PowerPoint",
    }
    return ext_map.get(ext, "Unknown / binary data")


# ==============================================================================
# LAYER 3: ENTROPY ANALYSIS
# ==============================================================================

def shannon_entropy(data: bytes) -> float:
    """Shannon entropy 0-8. >7.2 usually indicates encryption or compression."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def entropy_windows(data: bytes, window_size: int = 256) -> List[float]:
    """Sliding-window entropy for detecting mixed content."""
    if len(data) < window_size:
        return [shannon_entropy(data)]
    step = max(1, len(data) // 200)
    return [shannon_entropy(data[i:i + window_size]) for i in range(0, len(data) - window_size, step)]


def entropy_indicators(data: bytes) -> List[Indicator]:
    """Turn entropy stats into indicators."""
    indicators = []
    overall = shannon_entropy(data)

    if overall > 7.5:
        indicators.append(Indicator(
            layer="entropy",
            category="suspicious",
            severity="medium",
            title="Very high overall entropy",
            detail=f"Shannon entropy: {overall:.3f}/8.0 - suggests encryption, compression, or packing.",
            confidence=0.7,
        ))
    elif overall > 7.0:
        indicators.append(Indicator(
            layer="entropy",
            category="informational",
            severity="low",
            title="Elevated entropy",
            detail=f"Shannon entropy: {overall:.3f}/8.0 - possibly compressed content.",
            confidence=0.4,
        ))

    windows = entropy_windows(data)
    if windows:
        high_windows = sum(1 for w in windows if w > 7.5)
        if high_windows > 3 and high_windows < len(windows) * 0.9:
            indicators.append(Indicator(
                layer="entropy",
                category="suspicious",
                severity="medium",
                title="Mixed high-entropy regions",
                detail=f"{high_windows}/{len(windows)} sliding windows show packed/encrypted content - consistent with dropper/loader pattern.",
                confidence=0.6,
                mitre_attack=["T1027"],
            ))

    return indicators


# ==============================================================================
# LAYER 4: STRING EXTRACTION & IOC MINING
# ==============================================================================

STRING_MIN_LEN = 5

def extract_strings(data: bytes, min_len: int = STRING_MIN_LEN) -> Tuple[List[str], List[str]]:
    """Return (ascii_strings, unicode_strings)."""
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)

    ascii_strings = [m.decode("ascii", errors="ignore") for m in ascii_re.findall(data)]
    utf16_strings = [m.decode("utf-16-le", errors="ignore") for m in utf16_re.findall(data)]

    return ascii_strings, utf16_strings


IOC_PATTERNS = {
    "urls": re.compile(r"https?://[^\s\"'<>\\]{4,256}"),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
    "domains": re.compile(r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?){1,4}\b"),
    "emails": re.compile(r"[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "btc_addresses": re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b"),
    "eth_addresses": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "monero_addresses": re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
    "onion_urls": re.compile(r"[a-z2-7]{16,56}\.onion"),
    "registry_keys": re.compile(r"HK(?:LM|CU|CR|U|CC)\\[\\A-Za-z0-9_\-\. ]{5,256}"),
    "file_paths_win": re.compile(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\){0,10}[^\\/:*?\"<>|\r\n]{1,128}"),
    "file_paths_unix": re.compile(r"/(?:[a-zA-Z0-9_\-.]+/){1,10}[a-zA-Z0-9_\-.]+"),
    "mutex_names": re.compile(r"Global\\[A-Za-z0-9_\-\{\}]{5,64}"),
    "base64_blobs": re.compile(r"[A-Za-z0-9+/]{100,}={0,2}"),
    "user_agents": re.compile(r"Mozilla/[0-9.]+\s*\([^)]{5,200}\)"),
    "powershell_encoded": re.compile(r"(?i)-e(?:nc(?:oded)?(?:command)?)?\s+[A-Za-z0-9+/=]{40,}"),
    "hex_shellcode": re.compile(r"(?:\\x[0-9a-fA-F]{2}){20,}"),
}

# Domains commonly used as C2 pivots, TLDs frequently abused
SUSPICIOUS_TLD = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".click", ".download", ".stream", ".men", ".loan", ".party",
}

# Legitimate domains to filter noise
LEGIT_DOMAINS = {
    "microsoft.com", "windows.com", "google.com", "apple.com",
    "mozilla.org", "adobe.com", "oracle.com", "github.com",
    "w3.org", "schemas.microsoft.com", "verisign.com",
}


def extract_iocs(strings: List[str]) -> Dict[str, List[str]]:
    """Extract IOCs from the string corpus."""
    all_text = "\n".join(strings)
    iocs = {}
    for name, pattern in IOC_PATTERNS.items():
        matches = list(set(pattern.findall(all_text)))
        # Filter out obviously benign
        if name == "domains":
            matches = [
                d for d in matches
                if not any(legit in d.lower() for legit in LEGIT_DOMAINS)
                and "." in d and len(d) > 4 and len(d) < 100
                and not d.lower().endswith((".dll", ".exe", ".sys", ".png", ".jpg", ".txt", ".log"))
            ]
        if name == "ipv4":
            matches = [
                ip for ip in matches
                if not ip.startswith(("0.", "127.", "255.", "10.", "192.168.", "172."))
            ]
        if matches:
            iocs[name] = matches[:200]
    return iocs


def ioc_indicators(iocs: Dict[str, List[str]]) -> List[Indicator]:
    """Turn IOCs into indicators."""
    indicators = []

    if iocs.get("onion_urls"):
        indicators.append(Indicator(
            layer="ioc",
            category="suspicious",
            severity="high",
            title="Tor .onion address embedded",
            detail=f"Found {len(iocs['onion_urls'])} .onion address(es): {iocs['onion_urls'][:3]}",
            evidence=", ".join(iocs["onion_urls"][:5]),
            mitre_attack=["T1090.003"],
            confidence=0.85,
        ))

    if iocs.get("btc_addresses") or iocs.get("eth_addresses") or iocs.get("monero_addresses"):
        wallets = (iocs.get("btc_addresses", []) + iocs.get("eth_addresses", []) +
                   iocs.get("monero_addresses", []))
        indicators.append(Indicator(
            layer="ioc",
            category="suspicious",
            severity="high",
            title="Cryptocurrency wallet addresses embedded",
            detail=f"Found {len(wallets)} wallet address(es) - consistent with ransomware or clipper malware.",
            evidence=", ".join(wallets[:5]),
            mitre_attack=["T1486"],
            confidence=0.75,
        ))

    if iocs.get("powershell_encoded"):
        indicators.append(Indicator(
            layer="ioc",
            category="malicious",
            severity="critical",
            title="Encoded PowerShell command found",
            detail=f"Found {len(iocs['powershell_encoded'])} encoded PowerShell invocation(s) - nearly always malicious.",
            evidence=iocs["powershell_encoded"][0][:200] if iocs["powershell_encoded"] else "",
            mitre_attack=["T1059.001", "T1027"],
            confidence=0.9,
        ))

    if iocs.get("hex_shellcode"):
        indicators.append(Indicator(
            layer="ioc",
            category="malicious",
            severity="high",
            title="Hex-encoded shellcode-like pattern",
            detail=f"Found {len(iocs['hex_shellcode'])} sequence(s) of hex-encoded bytes that look like shellcode.",
            mitre_attack=["T1055"],
            confidence=0.7,
        ))

    if iocs.get("mutex_names"):
        indicators.append(Indicator(
            layer="ioc",
            category="suspicious",
            severity="medium",
            title="Global mutex names",
            detail=f"Found {len(iocs['mutex_names'])} global mutex(es) - used to prevent multiple infections.",
            evidence=", ".join(iocs["mutex_names"][:5]),
            mitre_attack=["T1480"],
            confidence=0.6,
        ))

    if iocs.get("domains"):
        sus = [d for d in iocs["domains"] if any(d.lower().endswith(tld) for tld in SUSPICIOUS_TLD)]
        if sus:
            indicators.append(Indicator(
                layer="ioc",
                category="suspicious",
                severity="medium",
                title="Domains on frequently-abused TLDs",
                detail=f"{len(sus)} domain(s) on abused TLDs (.tk, .ml, .xyz, etc.)",
                evidence=", ".join(sus[:10]),
                confidence=0.6,
            ))

    if iocs.get("urls"):
        indicators.append(Indicator(
            layer="ioc",
            category="informational",
            severity="info",
            title="URLs embedded",
            detail=f"Extracted {len(iocs['urls'])} URLs - review for C2 / staging infrastructure.",
            confidence=0.3,
        ))

    return indicators


# ==============================================================================
# LAYER 5: SUSPICIOUS STRING KEYWORDS
# ==============================================================================

SUSPICIOUS_KEYWORDS = {
    # Injection / evasion
    "VirtualAlloc":            ("PE injection primitive", "high", ["T1055"]),
    "VirtualAllocEx":          ("Remote memory allocation", "high", ["T1055"]),
    "WriteProcessMemory":      ("Remote process write", "high", ["T1055"]),
    "CreateRemoteThread":      ("Remote thread injection", "high", ["T1055.001"]),
    "QueueUserAPC":            ("APC injection", "high", ["T1055.004"]),
    "SetWindowsHookEx":        ("Global hook - keylogger primitive", "high", ["T1056.001"]),
    "GetAsyncKeyState":        ("Keylogger primitive", "high", ["T1056.001"]),
    "GetForegroundWindow":     ("Window-context tracking", "medium", ["T1056"]),
    "NtUnmapViewOfSection":    ("Process hollowing", "critical", ["T1055.012"]),
    "ZwUnmapViewOfSection":    ("Process hollowing (nt)", "critical", ["T1055.012"]),
    # Persistence
    "CurrentVersion\\Run":     ("Run key persistence", "high", ["T1547.001"]),
    "CurrentVersion\\RunOnce": ("RunOnce persistence", "high", ["T1547.001"]),
    "schtasks":                ("Scheduled task", "medium", ["T1053.005"]),
    "sc create":               ("Windows service creation", "medium", ["T1543.003"]),
    "Winlogon":                ("Winlogon persistence", "high", ["T1547.004"]),
    "Image File Execution":    ("IFEO persistence", "high", ["T1546.012"]),
    # Anti-analysis
    "IsDebuggerPresent":       ("Debugger detection", "medium", ["T1622"]),
    "CheckRemoteDebugger":     ("Remote debugger check", "medium", ["T1622"]),
    "NtQueryInformationProc":  ("Info-class debug check", "medium", ["T1622"]),
    "OutputDebugString":       ("Debug string output", "low", []),
    "GetTickCount":            ("Timing-based sandbox evasion", "medium", ["T1497.003"]),
    "QueryPerformanceCounter": ("Timing evasion", "medium", ["T1497.003"]),
    "Sleep":                   ("Delayed execution - sandbox evasion", "low", ["T1497.003"]),
    "VBoxService":             ("VirtualBox detection", "high", ["T1497.001"]),
    "vmware":                  ("VMware detection", "high", ["T1497.001"]),
    "Wireshark":               ("Anti-analysis tool detection", "medium", ["T1518.001"]),
    "SbieDll":                 ("Sandboxie detection", "high", ["T1497.001"]),
    # C2 / network
    "InternetOpen":            ("HTTP client init", "medium", ["T1071.001"]),
    "InternetConnect":         ("HTTP connect", "medium", ["T1071.001"]),
    "HttpSendRequest":         ("HTTP send", "medium", ["T1071.001"]),
    "WSAStartup":              ("Socket init", "medium", ["T1071"]),
    "connect":                 ("TCP connect", "low", ["T1071"]),
    "URLDownloadToFile":       ("Download-and-execute primitive", "high", ["T1105"]),
    # Credential access
    "SamiAcct":                ("SAM account access", "critical", ["T1003.002"]),
    "LSASS":                   ("LSASS access", "critical", ["T1003.001"]),
    "MiniDumpWriteDump":       ("Process dump - LSASS dumping", "critical", ["T1003.001"]),
    "vaultcli":                ("Windows Vault access", "high", ["T1555.004"]),
    "keychain":                ("macOS Keychain access", "high", ["T1555.001"]),
    "Login Data":              ("Chrome credential DB", "high", ["T1555.003"]),
    "wallet.dat":              ("Bitcoin wallet file", "high", ["T1005"]),
    # Ransomware indicators
    "your files have been":    ("Ransom note pattern", "critical", ["T1486"]),
    "decrypt":                 ("Decryption reference", "medium", ["T1486"]),
    "bitcoin":                 ("Bitcoin reference", "medium", ["T1486"]),
    "ransom":                  ("Ransom keyword", "critical", ["T1486"]),
    "encrypted":               ("Encryption reference", "low", []),
    "AES_encrypt":             ("AES encryption call", "medium", []),
    "CryptEncrypt":            ("Windows crypto encrypt", "medium", ["T1486"]),
    # Living-off-the-land
    "powershell.exe":          ("PowerShell invocation", "medium", ["T1059.001"]),
    "cmd.exe /c":              ("Cmd invocation", "medium", ["T1059.003"]),
    "cscript":                 ("Windows Script Host", "medium", ["T1059.005"]),
    "wscript":                 ("Windows Script Host", "medium", ["T1059.005"]),
    "mshta":                   ("HTA execution", "high", ["T1218.005"]),
    "rundll32":                ("Rundll32 abuse", "medium", ["T1218.011"]),
    "regsvr32":                ("Regsvr32 abuse", "medium", ["T1218.010"]),
    "certutil":                ("Certutil download primitive", "high", ["T1105"]),
    "bitsadmin":               ("BITS transfer", "medium", ["T1197"]),
    # Discovery
    "GetSystemInfo":           ("System info gathering", "low", ["T1082"]),
    "GetComputerName":         ("Host discovery", "low", ["T1082"]),
    "GetUserName":             ("User discovery", "low", ["T1033"]),
    # Exploit strings
    "${jndi:":                 ("Log4Shell payload", "critical", ["T1190"]),
    "$(ping":                  ("Command injection payload", "high", ["T1190"]),
    "MSDTJS":                  ("Follina exploit marker", "critical", ["T1203"]),
    "ms-msdt:":                ("Follina URI scheme", "critical", ["T1203"]),
    "EternalBlue":             ("EternalBlue reference", "critical", ["T1210"]),
    "MS17-010":                ("EternalBlue CVE ref", "critical", ["T1210"]),
    "PrintNightmare":          ("PrintNightmare reference", "critical", ["T1068"]),
    "%COMSPEC%":               ("Command shell env", "low", []),
    # Reflective / shellcode
    "ReflectiveLoader":        ("Reflective DLL loader", "critical", ["T1620"]),
    "\\x90\\x90\\x90":         ("NOP sled hex", "high", ["T1055"]),
}


def keyword_indicators(strings: List[str]) -> List[Indicator]:
    """Match suspicious keywords."""
    indicators = []
    corpus_lower = "\n".join(strings).lower()

    hits: Dict[str, Tuple[str, str, List[str]]] = {}
    for keyword, meta in SUSPICIOUS_KEYWORDS.items():
        if keyword.lower() in corpus_lower:
            hits[keyword] = meta

    # Bucket by MITRE tactic for cleaner output
    by_severity = defaultdict(list)
    for kw, (desc, sev, mitre) in hits.items():
        by_severity[sev].append((kw, desc, mitre))

    for sev in ("critical", "high", "medium", "low"):
        if sev in by_severity:
            items = by_severity[sev]
            all_mitre = list(set(m for _, _, mitre in items for m in mitre))
            conf = {"critical": 0.9, "high": 0.75, "medium": 0.55, "low": 0.3}[sev]
            indicators.append(Indicator(
                layer="keyword",
                category="malicious" if sev in ("critical", "high") else "suspicious",
                severity=sev,
                title=f"{len(items)} {sev}-severity keyword(s) matched",
                detail="; ".join(f"{kw} ({desc})" for kw, desc, _ in items[:15]),
                mitre_attack=all_mitre,
                confidence=conf,
            ))

    return indicators


# ==============================================================================
# LAYER 6: PE ANALYSIS
# ==============================================================================

# Suspicious import combinations
INJECTION_TRIO = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}
HOLLOWING_APIS = {"NtUnmapViewOfSection", "ZwUnmapViewOfSection", "SetThreadContext", "ResumeThread"}
KEYLOGGER_APIS = {"SetWindowsHookEx", "GetAsyncKeyState", "GetForegroundWindow"}


def analyze_pe(data: bytes) -> Tuple[List[Indicator], Dict[str, Any]]:
    """Analyze a PE (Windows exe/dll)."""
    indicators = []
    meta = {}

    pe_module = get_pefile()
    if not pe_module:
        return indicators, meta

    try:
        pe = pe_module.PE(data=data, fast_load=False)
    except Exception as e:
        indicators.append(Indicator(
            layer="pe",
            category="informational",
            severity="info",
            title="PE parse error",
            detail=f"pefile could not parse: {e}",
            confidence=0.2,
        ))
        return indicators, meta

    try:
        # Machine architecture
        machine = pe_module.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, "unknown")
        meta["machine"] = str(machine)

        # Compile timestamp
        try:
            ts = pe.FILE_HEADER.TimeDateStamp
            compile_time = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
            meta["compile_time"] = compile_time
            if ts > int(time.time()):
                indicators.append(Indicator(
                    layer="pe",
                    category="suspicious",
                    severity="medium",
                    title="Future compile timestamp",
                    detail=f"Compile timestamp is in the future ({compile_time}) - likely tampered.",
                    confidence=0.75,
                    mitre_attack=["T1070.006"],
                ))
            elif ts < 946684800:  # < year 2000
                indicators.append(Indicator(
                    layer="pe",
                    category="suspicious",
                    severity="low",
                    title="Very old compile timestamp",
                    detail=f"Compile timestamp predates 2000 ({compile_time}) - possibly zeroed or tampered.",
                    confidence=0.5,
                    mitre_attack=["T1070.006"],
                ))
        except Exception:
            pass

        # Sections
        sus_sections = []
        for section in pe.sections:
            name = section.Name.decode(errors="ignore").strip("\x00")
            entropy = section.get_entropy()
            raw_size = section.SizeOfRawData
            virt_size = section.Misc_VirtualSize
            characteristics = section.Characteristics

            # Writable + executable = red flag
            if (characteristics & 0x80000000) and (characteristics & 0x20000000):
                sus_sections.append(name)
                indicators.append(Indicator(
                    layer="pe",
                    category="suspicious",
                    severity="high",
                    title=f"Section '{name}' is writable AND executable",
                    detail="W+X sections are typically used by packers, self-modifying code, or unpackers.",
                    confidence=0.85,
                    mitre_attack=["T1027.002"],
                ))
            if entropy > 7.5:
                indicators.append(Indicator(
                    layer="pe",
                    category="suspicious",
                    severity="medium",
                    title=f"High entropy in section '{name}'",
                    detail=f"Section entropy {entropy:.3f}/8.0 - likely packed or encrypted.",
                    confidence=0.7,
                    mitre_attack=["T1027.002"],
                ))
            if virt_size > raw_size * 3 and virt_size > 0x10000:
                indicators.append(Indicator(
                    layer="pe",
                    category="suspicious",
                    severity="medium",
                    title=f"Section '{name}' virtual size >> raw size",
                    detail=f"Virtual size ({virt_size}) is much larger than raw ({raw_size}) - unpacker unpacking to this section.",
                    confidence=0.7,
                    mitre_attack=["T1027.002"],
                ))

            # Suspicious names
            packer_hint_names = {".upx", "upx0", "upx1", "upx2", ".themida", ".vmp0", ".vmp1", ".aspack", ".mpress"}
            if name.lower() in packer_hint_names:
                packer = name.strip(".").upper()
                indicators.append(Indicator(
                    layer="pe",
                    category="suspicious",
                    severity="medium",
                    title=f"Known packer section '{name}'",
                    detail=f"Section name matches known packer ({packer}).",
                    confidence=0.85,
                    mitre_attack=["T1027.002"],
                ))
                meta["packer"] = packer

        meta["sections"] = [
            {
                "name": s.Name.decode(errors="ignore").strip("\x00"),
                "entropy": round(s.get_entropy(), 3),
                "raw_size": s.SizeOfRawData,
                "virtual_size": s.Misc_VirtualSize,
            }
            for s in pe.sections
        ]

        # Imports
        imported_apis = set()
        imported_dlls = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors="ignore").lower()
                imported_dlls.append(dll)
                for imp in entry.imports:
                    if imp.name:
                        imported_apis.add(imp.name.decode(errors="ignore"))

        meta["imported_dlls"] = imported_dlls
        meta["imported_api_count"] = len(imported_apis)

        # imphash for family clustering
        try:
            imphash = pe.get_imphash()
            if imphash:
                meta["imphash"] = imphash
        except Exception:
            pass

        # API-combo heuristics
        if INJECTION_TRIO.issubset(imported_apis):
            indicators.append(Indicator(
                layer="pe",
                category="malicious",
                severity="critical",
                title="Complete process-injection API trio",
                detail="Imports VirtualAllocEx + WriteProcessMemory + CreateRemoteThread - classic process injection primitives.",
                confidence=0.9,
                mitre_attack=["T1055.001", "T1055.002"],
            ))
        if HOLLOWING_APIS.intersection(imported_apis):
            hit = HOLLOWING_APIS.intersection(imported_apis)
            indicators.append(Indicator(
                layer="pe",
                category="malicious",
                severity="critical",
                title="Process-hollowing APIs present",
                detail=f"Imports: {', '.join(hit)} - process hollowing / RunPE primitive.",
                confidence=0.9,
                mitre_attack=["T1055.012"],
            ))
        if KEYLOGGER_APIS.issubset(imported_apis):
            indicators.append(Indicator(
                layer="pe",
                category="malicious",
                severity="high",
                title="Keylogger API pattern",
                detail="Full keylogger primitive: SetWindowsHookEx + GetAsyncKeyState + GetForegroundWindow.",
                confidence=0.85,
                mitre_attack=["T1056.001"],
            ))

        if imported_apis and len(imported_apis) < 10:
            indicators.append(Indicator(
                layer="pe",
                category="suspicious",
                severity="medium",
                title=f"Suspiciously few imports ({len(imported_apis)})",
                detail="Very small import table often indicates packing - real APIs resolved at runtime via GetProcAddress.",
                confidence=0.65,
                mitre_attack=["T1027.002"],
            ))

        # Overlay (data appended after the PE)
        overlay = pe.get_overlay_data_start_offset()
        if overlay:
            overlay_size = len(data) - overlay
            if overlay_size > 1024:
                overlay_entropy = shannon_entropy(data[overlay:])
                indicators.append(Indicator(
                    layer="pe",
                    category="suspicious" if overlay_entropy > 7 else "informational",
                    severity="medium" if overlay_entropy > 7 else "low",
                    title=f"PE overlay: {overlay_size} bytes appended (entropy {overlay_entropy:.2f})",
                    detail="Data appended after PE structure - commonly used to smuggle payloads or configs.",
                    confidence=0.7 if overlay_entropy > 7 else 0.4,
                    mitre_attack=["T1027"] if overlay_entropy > 7 else [],
                ))

        # Digital signature
        try:
            if hasattr(pe, "DIRECTORY_ENTRY_SECURITY") or pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress != 0:
                meta["signed"] = True
                indicators.append(Indicator(
                    layer="pe",
                    category="informational",
                    severity="info",
                    title="File is digitally signed",
                    detail="Signature verification not performed - check with sigcheck/osslsigncode for validity.",
                    confidence=0.3,
                ))
            else:
                meta["signed"] = False
        except Exception:
            pass

        # Resources - TLS callbacks
        if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
            indicators.append(Indicator(
                layer="pe",
                category="suspicious",
                severity="medium",
                title="TLS callbacks present",
                detail="TLS callbacks execute before the entrypoint - commonly used for anti-debug tricks.",
                confidence=0.65,
                mitre_attack=["T1027"],
            ))

    except Exception as e:
        indicators.append(Indicator(
            layer="pe",
            category="informational",
            severity="info",
            title="Partial PE analysis",
            detail=f"Some PE analysis failed: {e}",
            confidence=0.2,
        ))
    finally:
        try:
            pe.close()
        except Exception:
            pass

    return indicators, meta


# ==============================================================================
# LAYER 7: ELF ANALYSIS
# ==============================================================================

def analyze_elf(data: bytes) -> Tuple[List[Indicator], Dict[str, Any]]:
    """Analyze an ELF binary."""
    indicators = []
    meta = {}

    lief = get_lief()
    if not lief:
        return indicators, meta

    try:
        binary = lief.parse(list(data))
        if binary is None:
            return indicators, meta

        # Note: lief has multiple format APIs; we handle only ELF here
        try:
            meta["elf_class"] = str(binary.header.identity_class)
            meta["machine"] = str(binary.header.machine_type)
            meta["entrypoint"] = hex(binary.header.entrypoint)
        except Exception:
            pass

        # Imported symbols (dynamic)
        try:
            imports = [s.name for s in binary.imported_symbols][:200]
            meta["imported_symbols_sample"] = imports[:50]

            # Look for suspicious combos
            imp_set = set(imports)
            if {"ptrace"}.issubset(imp_set):
                indicators.append(Indicator(
                    layer="elf",
                    category="suspicious",
                    severity="medium",
                    title="ptrace anti-debug usage",
                    detail="Binary imports ptrace - commonly used to detect or prevent debugging.",
                    confidence=0.7,
                    mitre_attack=["T1622"],
                ))
            if imp_set.intersection({"system", "execve", "execl", "popen"}):
                indicators.append(Indicator(
                    layer="elf",
                    category="informational",
                    severity="low",
                    title="Command execution APIs imported",
                    detail=f"Imports: {imp_set.intersection({'system','execve','execl','popen'})}",
                    confidence=0.4,
                ))
            if imp_set.intersection({"socket", "connect", "bind", "listen"}):
                indicators.append(Indicator(
                    layer="elf",
                    category="informational",
                    severity="low",
                    title="Networking APIs",
                    detail="Binary uses network sockets.",
                    confidence=0.3,
                    mitre_attack=["T1071"],
                ))
        except Exception:
            pass

        # Section entropy
        try:
            for section in binary.sections:
                name = section.name
                if section.size > 1024:
                    section_data = bytes(section.content)
                    ent = shannon_entropy(section_data)
                    if ent > 7.5 and name not in (".rodata", ".data"):
                        indicators.append(Indicator(
                            layer="elf",
                            category="suspicious",
                            severity="medium",
                            title=f"High-entropy section '{name}'",
                            detail=f"Section entropy {ent:.3f}/8.0 - possibly packed.",
                            confidence=0.7,
                            mitre_attack=["T1027.002"],
                        ))
        except Exception:
            pass

        # Stripped?
        try:
            if not binary.symbols:
                indicators.append(Indicator(
                    layer="elf",
                    category="informational",
                    severity="info",
                    title="Binary is stripped",
                    detail="No symbol table - normal for stripped release builds but also common for malware.",
                    confidence=0.2,
                ))
        except Exception:
            pass

    except Exception as e:
        indicators.append(Indicator(
            layer="elf",
            category="informational",
            severity="info",
            title="ELF parse issue",
            detail=str(e),
            confidence=0.2,
        ))

    return indicators, meta


# ==============================================================================
# LAYER 8: OFFICE / OLE / VBA ANALYSIS
# ==============================================================================

def analyze_office(data: bytes, filepath: str) -> List[Indicator]:
    """Analyze Office documents for macros, DDE, and other Office attacks."""
    indicators = []

    tools = get_oletools()
    if not tools:
        return indicators

    olevba = tools.get("olevba")
    if not olevba:
        return indicators

    try:
        parser = olevba.VBA_Parser(filepath, data=data)
        has_macros = parser.detect_vba_macros() or parser.detect_xlm_macros()

        if not has_macros:
            indicators.append(Indicator(
                layer="office",
                category="informational",
                severity="info",
                title="No macros found",
                detail="Document contains no VBA or XLM macros.",
                confidence=0.3,
            ))
            parser.close()
            return indicators

        # Extract macros
        macro_code_blocks = []
        for (filename, stream_path, vba_filename, vba_code) in parser.extract_all_macros():
            if vba_code:
                macro_code_blocks.append(vba_code)

        if not macro_code_blocks and parser.detect_xlm_macros():
            indicators.append(Indicator(
                layer="office",
                category="malicious",
                severity="critical",
                title="Excel 4.0 (XLM) macros present",
                detail="Legacy Excel 4.0 macros - nearly always malicious in modern documents.",
                confidence=0.9,
                mitre_attack=["T1059.005"],
            ))
            parser.close()
            return indicators

        all_macro_code = "\n".join(macro_code_blocks)

        # olevba's analysis
        try:
            results = parser.analyze_macros()
            # results is a list of (kw_type, keyword, description)
            severity_counts = {"AutoExec": [], "Suspicious": [], "IOC": []}
            for kw_type, keyword, description in results:
                if kw_type in severity_counts:
                    severity_counts[kw_type].append((keyword, description))

            if severity_counts["AutoExec"]:
                indicators.append(Indicator(
                    layer="office",
                    category="malicious",
                    severity="critical",
                    title="Auto-executing macro triggers",
                    detail=f"Auto-exec triggers: {[k for k,_ in severity_counts['AutoExec']]}",
                    confidence=0.9,
                    mitre_attack=["T1204.002", "T1137"],
                ))

            if severity_counts["Suspicious"]:
                sus_kws = severity_counts["Suspicious"]
                indicators.append(Indicator(
                    layer="office",
                    category="malicious",
                    severity="high",
                    title=f"{len(sus_kws)} suspicious macro APIs used",
                    detail="; ".join(f"{k}: {d}" for k, d in sus_kws[:15]),
                    confidence=0.85,
                    mitre_attack=["T1059.005", "T1105"],
                ))

            if severity_counts["IOC"]:
                indicators.append(Indicator(
                    layer="office",
                    category="malicious",
                    severity="high",
                    title=f"IOCs embedded in macros ({len(severity_counts['IOC'])})",
                    detail="; ".join(f"{k}" for k, _ in severity_counts["IOC"][:10]),
                    confidence=0.85,
                ))
        except Exception:
            pass

        # Check for obfuscation patterns
        obfuscation_patterns = [
            (r"Chr\s*\(\s*\d+\s*\)\s*&", "Chr()-concat obfuscation"),
            (r"\bStrReverse\b", "StrReverse obfuscation"),
            (r"\bCallByName\b", "CallByName dynamic dispatch"),
            (r"\bExecute\b", "VBA Execute statement"),
            (r"\bShell\b", "VBA Shell command"),
            (r"CreateObject\s*\(\s*[\"']Shell", "WScript.Shell instantiation"),
            (r"CreateObject\s*\(\s*[\"']WScript\.Shell", "WScript.Shell instantiation"),
            (r"powershell", "PowerShell invocation from VBA"),
            (r"MSXML2\.XMLHTTP", "XMLHTTP downloader"),
            (r"WinHttp\.WinHttpRequest", "WinHTTP downloader"),
        ]

        found_patterns = []
        for pattern, desc in obfuscation_patterns:
            if re.search(pattern, all_macro_code, re.IGNORECASE):
                found_patterns.append(desc)

        if found_patterns:
            indicators.append(Indicator(
                layer="office",
                category="malicious",
                severity="high",
                title="Macro obfuscation / downloader patterns",
                detail="; ".join(found_patterns),
                confidence=0.85,
                mitre_attack=["T1059.005", "T1105", "T1027"],
            ))

        # DDE
        if b"DDEAUTO" in data or b"DDE " in data:
            indicators.append(Indicator(
                layer="office",
                category="malicious",
                severity="critical",
                title="DDE (Dynamic Data Exchange) present",
                detail="DDE fields can execute arbitrary commands without macros being enabled.",
                confidence=0.9,
                mitre_attack=["T1559.002"],
            ))

        # OLE embeddings (Follina / equation editor exploits)
        if b"MSDT" in data or b"ms-msdt:" in data.lower():
            indicators.append(Indicator(
                layer="office",
                category="malicious",
                severity="critical",
                title="Follina (CVE-2022-30190) exploit pattern",
                detail="MSDT URI scheme reference - Follina RCE exploit.",
                confidence=0.95,
                mitre_attack=["T1203"],
            ))

        # Equation editor exploit
        if b"Equation.3" in data:
            indicators.append(Indicator(
                layer="office",
                category="malicious",
                severity="critical",
                title="Equation Editor OLE object",
                detail="Equation Editor is unpatched and abused by CVE-2017-11882 / CVE-2018-0802.",
                confidence=0.9,
                mitre_attack=["T1203"],
            ))

        parser.close()

    except Exception as e:
        indicators.append(Indicator(
            layer="office",
            category="informational",
            severity="info",
            title="Office parse issue",
            detail=str(e),
            confidence=0.2,
        ))

    return indicators


# ==============================================================================
# LAYER 9: PDF ANALYSIS
# ==============================================================================

PDF_SUSPICIOUS_KEYWORDS = {
    b"/JS":               ("JavaScript", "high", ["T1059.007"]),
    b"/JavaScript":       ("JavaScript action", "high", ["T1059.007"]),
    b"/AA":               ("Additional actions", "high", ["T1204"]),
    b"/OpenAction":       ("Auto-open action", "high", ["T1204"]),
    b"/Launch":           ("Launch action", "critical", ["T1204"]),
    b"/EmbeddedFile":     ("Embedded file", "high", ["T1027"]),
    b"/EmbeddedFiles":    ("Embedded files", "high", ["T1027"]),
    b"/URI":              ("URL reference", "low", []),
    b"/SubmitForm":       ("Submit form", "medium", []),
    b"/RichMedia":        ("RichMedia (Flash-era exploit vector)", "high", ["T1203"]),
    b"/XFA":              ("XFA form (exploit surface)", "medium", ["T1203"]),
    b"/JBIG2Decode":      ("JBIG2 (CVE-2021-30860 vector)", "critical", ["T1203"]),
}


def analyze_pdf(data: bytes) -> List[Indicator]:
    """Structural PDF analysis."""
    indicators = []

    if not data.startswith(b"%PDF"):
        return indicators

    # Simple keyword count
    hits = []
    for kw, (desc, sev, mitre) in PDF_SUSPICIOUS_KEYWORDS.items():
        count = data.count(kw)
        if count > 0:
            hits.append((kw.decode(), desc, sev, mitre, count))

    for kw, desc, sev, mitre, count in hits:
        conf = {"critical": 0.85, "high": 0.75, "medium": 0.55, "low": 0.3}[sev]
        indicators.append(Indicator(
            layer="pdf",
            category="malicious" if sev in ("critical", "high") else "suspicious",
            severity=sev,
            title=f"PDF: {kw} ({desc})",
            detail=f"Occurrences: {count}",
            confidence=conf,
            mitre_attack=mitre,
        ))

    # Object stream count
    obj_count = data.count(b"obj\n") + data.count(b"obj\r")
    stream_count = data.count(b"stream\n") + data.count(b"stream\r")

    if stream_count > 20 and obj_count > stream_count * 2:
        indicators.append(Indicator(
            layer="pdf",
            category="suspicious",
            severity="medium",
            title="Unusual object-to-stream ratio",
            detail=f"{obj_count} objects, {stream_count} streams - possible obfuscation.",
            confidence=0.55,
        ))

    # Hex-encoded content in stream
    if re.search(rb"stream\s+[<>0-9a-fA-F\s]{500,}\s+endstream", data):
        indicators.append(Indicator(
            layer="pdf",
            category="suspicious",
            severity="medium",
            title="Hex-encoded PDF stream",
            detail="Stream content is hex-encoded - obfuscation.",
            confidence=0.65,
            mitre_attack=["T1027"],
        ))

    # /ObjStm object streams (common obfuscation)
    if data.count(b"/ObjStm") > 5:
        indicators.append(Indicator(
            layer="pdf",
            category="suspicious",
            severity="medium",
            title="Multiple /ObjStm object streams",
            detail=f"{data.count(b'/ObjStm')} object streams - often used to hide malicious objects.",
            confidence=0.6,
        ))

    return indicators


# ==============================================================================
# LAYER 10: SCRIPT ANALYSIS
# ==============================================================================

SCRIPT_SUSPICIOUS = {
    # PowerShell
    r"(?i)\biex\b\s*\(":                    ("Invoke-Expression", "critical", ["T1059.001"]),
    r"(?i)Invoke-Expression":               ("Invoke-Expression", "critical", ["T1059.001"]),
    r"(?i)DownloadString":                  ("PowerShell downloader", "critical", ["T1105"]),
    r"(?i)DownloadFile":                    ("Download-to-file", "critical", ["T1105"]),
    r"(?i)-EncodedCommand":                 ("Encoded PowerShell", "critical", ["T1027"]),
    r"(?i)-ExecutionPolicy\s+Bypass":       ("ExecutionPolicy bypass", "high", ["T1562.001"]),
    r"(?i)-WindowStyle\s+Hidden":           ("Hidden window", "high", ["T1564.003"]),
    r"(?i)\[System\.Reflection\.Assembly\]": ("Reflection.Assembly load", "high", ["T1620"]),
    r"(?i)\[Convert\]::FromBase64String":   ("Base64 decode", "medium", ["T1027"]),
    r"(?i)\[System\.Text\.Encoding\]":      ("Text encoding usage", "medium", []),
    r"(?i)Invoke-Mimikatz":                 ("Mimikatz invocation", "critical", ["T1003"]),
    r"(?i)Invoke-Shellcode":                ("Shellcode invocation", "critical", ["T1055"]),
    r"(?i)Add-MpPreference.*ExclusionPath": ("Defender exclusion added", "high", ["T1562.001"]),
    # JS
    r"eval\s*\(":                           ("eval()", "high", ["T1027"]),
    r"unescape\s*\(":                       ("unescape()", "medium", ["T1027"]),
    r"String\.fromCharCode":                ("String.fromCharCode", "medium", ["T1027"]),
    r"document\.write\s*\(":                ("document.write", "low", []),
    r"ActiveXObject":                       ("ActiveX instantiation", "high", ["T1059.007"]),
    r"WScript\.Shell":                      ("WScript.Shell", "critical", ["T1059.005"]),
    r"Shell\.Application":                  ("Shell.Application", "high", ["T1059.005"]),
    # VBS
    r"CreateObject\s*\(\s*[\"']WScript":    ("WScript CreateObject", "high", ["T1059.005"]),
    r"CreateObject\s*\(\s*[\"']Scripting":  ("Scripting.FileSystemObject", "high", []),
    # Batch
    r"powershell\s+-":                      ("Powershell wrapped", "high", ["T1059.001"]),
    r"@echo\s+off":                         ("Batch script marker", "info", []),
    # Bash
    r"curl\s+.+?\s*\|\s*(?:bash|sh)":       ("curl-pipe-shell", "critical", ["T1105"]),
    r"wget\s+.+?\s*\|\s*(?:bash|sh)":       ("wget-pipe-shell", "critical", ["T1105"]),
    r"base64\s+-d":                         ("base64 decode", "medium", ["T1027"]),
    r"/dev/tcp/":                           ("Bash TCP reverse shell", "critical", ["T1059.004"]),
    r"nc\s+-e":                             ("Netcat reverse shell", "critical", ["T1059.004"]),
    r"chmod\s+\+x":                         ("Make executable", "medium", []),
}


def analyze_script(data: bytes) -> List[Indicator]:
    """Analyze script content (PS1, VBS, JS, Bash, Batch)."""
    indicators = []
    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        return indicators

    hits_by_sev: Dict[str, List[Tuple[str, str, List[str]]]] = defaultdict(list)
    for pattern, (desc, sev, mitre) in SCRIPT_SUSPICIOUS.items():
        if re.search(pattern, text):
            hits_by_sev[sev].append((pattern, desc, mitre))

    for sev, items in hits_by_sev.items():
        if sev == "info":
            continue
        all_mitre = list(set(m for _, _, mitre in items for m in mitre))
        conf = {"critical": 0.9, "high": 0.75, "medium": 0.55, "low": 0.3}.get(sev, 0.4)
        indicators.append(Indicator(
            layer="script",
            category="malicious" if sev in ("critical", "high") else "suspicious",
            severity=sev,
            title=f"{len(items)} {sev}-severity script pattern(s)",
            detail="; ".join(f"{desc}" for _, desc, _ in items[:15]),
            mitre_attack=all_mitre,
            confidence=conf,
        ))

    # Detect base64 blobs and try to decode
    for m in re.finditer(r"[A-Za-z0-9+/=]{80,}", text):
        blob = m.group()
        try:
            decoded = base64.b64decode(blob + "===", validate=False)
            # UTF-16-LE for encoded PowerShell
            for enc in ("utf-16-le", "utf-8"):
                try:
                    decoded_text = decoded.decode(enc, errors="ignore")
                    if any(kw in decoded_text.lower() for kw in ["invoke-", "downloadstring", "iex", "shellcode", "add-mppreference"]):
                        indicators.append(Indicator(
                            layer="script",
                            category="malicious",
                            severity="critical",
                            title="Base64-encoded malicious payload decoded",
                            detail=f"Decoded blob contains suspicious tokens.",
                            evidence=decoded_text[:300],
                            confidence=0.9,
                            mitre_attack=["T1027", "T1059.001"],
                        ))
                        break
                except Exception:
                    continue
        except Exception:
            continue

    return indicators


# ==============================================================================
# LAYER 11: APK / DEX ANALYSIS
# ==============================================================================

DANGEROUS_ANDROID_PERMISSIONS = {
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.WRITE_SETTINGS",
    "android.permission.INSTALL_PACKAGES",
}


def analyze_apk(data: bytes, filepath: str) -> List[Indicator]:
    """Basic APK triage - permissions, embedded native libs, DEX."""
    indicators = []

    if not data.startswith(b"PK\x03\x04"):
        return indicators

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = z.namelist()
            if "AndroidManifest.xml" not in names:
                return indicators

            # Try androguard for parsed manifest
            aguard = get_androguard()
            if aguard:
                try:
                    from androguard.core.bytecodes.apk import APK
                    apk = APK(filepath)
                    perms = set(apk.get_permissions())
                    dangerous = perms & DANGEROUS_ANDROID_PERMISSIONS
                    if dangerous:
                        indicators.append(Indicator(
                            layer="apk",
                            category="suspicious",
                            severity="high",
                            title=f"{len(dangerous)} dangerous permission(s)",
                            detail=", ".join(sorted(dangerous)),
                            confidence=0.7,
                        ))
                    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in perms:
                        indicators.append(Indicator(
                            layer="apk",
                            category="malicious",
                            severity="critical",
                            title="Requests Accessibility Service",
                            detail="Accessibility abuse is the hallmark of Android banking trojans and RATs.",
                            confidence=0.85,
                            mitre_attack=["T1417.002"],
                        ))
                    if apk.get_max_sdk_version() and int(apk.get_max_sdk_version()) < 23:
                        indicators.append(Indicator(
                            layer="apk",
                            category="suspicious",
                            severity="medium",
                            title="Low maxSdkVersion",
                            detail="Targets old Android - common evasion for runtime-perm restrictions.",
                            confidence=0.5,
                        ))
                except Exception:
                    pass

            # Native library scan
            native_libs = [n for n in names if n.endswith(".so")]
            if native_libs:
                indicators.append(Indicator(
                    layer="apk",
                    category="informational",
                    severity="info",
                    title=f"Contains {len(native_libs)} native .so libraries",
                    detail="Native libs increase analysis difficulty.",
                    confidence=0.3,
                ))

            # DEX count
            dex_count = sum(1 for n in names if n.endswith(".dex"))
            if dex_count > 3:
                indicators.append(Indicator(
                    layer="apk",
                    category="suspicious",
                    severity="medium",
                    title=f"{dex_count} DEX files",
                    detail="Many DEX files often indicate a dropper carrying additional payloads.",
                    confidence=0.55,
                ))

    except Exception as e:
        indicators.append(Indicator(
            layer="apk",
            category="informational",
            severity="info",
            title="APK parse issue",
            detail=str(e),
            confidence=0.2,
        ))

    return indicators


# ==============================================================================
# LAYER 12: ARCHIVE HANDLING
# ==============================================================================

def analyze_archive(data: bytes) -> Tuple[List[Indicator], List[Tuple[str, bytes]]]:
    """Peek inside archives; return indicators + list of (name, data) to scan recursively."""
    indicators = []
    inner_files: List[Tuple[str, bytes]] = []

    if not data.startswith(b"PK\x03\x04"):
        return indicators, inner_files

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            info_list = z.infolist()

            # Suspicious archive patterns
            executable_exts = (".exe", ".dll", ".scr", ".pif", ".com", ".bat", ".cmd",
                              ".ps1", ".vbs", ".js", ".jse", ".vbe", ".wsf", ".hta",
                              ".jar", ".apk", ".msi", ".lnk")
            exec_files = [i.filename for i in info_list
                          if i.filename.lower().endswith(executable_exts)]

            if exec_files:
                indicators.append(Indicator(
                    layer="archive",
                    category="suspicious",
                    severity="medium",
                    title=f"{len(exec_files)} executable(s) in archive",
                    detail="; ".join(exec_files[:10]),
                    confidence=0.6,
                ))

            # Path traversal / Zip Slip
            for i in info_list:
                if ".." in i.filename or i.filename.startswith("/") or i.filename.startswith("\\"):
                    indicators.append(Indicator(
                        layer="archive",
                        category="malicious",
                        severity="high",
                        title="Path traversal in archive (Zip Slip)",
                        detail=f"Entry: {i.filename}",
                        confidence=0.85,
                    ))

            # Zip bomb: compression ratio
            for i in info_list:
                if i.file_size > 0 and i.compress_size > 0:
                    ratio = i.file_size / i.compress_size
                    if ratio > 1000 and i.file_size > 10_000_000:
                        indicators.append(Indicator(
                            layer="archive",
                            category="suspicious",
                            severity="high",
                            title="Possible zip bomb",
                            detail=f"Entry '{i.filename}' compresses at {ratio:.0f}:1 to {i.file_size} bytes.",
                            confidence=0.8,
                        ))

            # Password-protected: force us to bail
            for i in info_list:
                if i.flag_bits & 0x1:
                    indicators.append(Indicator(
                        layer="archive",
                        category="suspicious",
                        severity="high",
                        title="Password-protected archive contents",
                        detail=f"Cannot inspect: {i.filename} - password-required archives are a common malware delivery trick.",
                        confidence=0.75,
                        mitre_attack=["T1027.013"],
                    ))
                    return indicators, inner_files

            # Extract small entries for recursive scan
            for i in info_list[:20]:  # cap
                if i.file_size < 20_000_000 and not i.is_dir():
                    try:
                        inner_data = z.read(i.filename)
                        inner_files.append((i.filename, inner_data))
                    except Exception:
                        continue

    except Exception as e:
        indicators.append(Indicator(
            layer="archive",
            category="informational",
            severity="info",
            title="Archive parse issue",
            detail=str(e),
            confidence=0.2,
        ))

    return indicators, inner_files


# ==============================================================================
# LAYER 13: STEGANOGRAPHY / IMAGE CHECKS
# ==============================================================================

def analyze_image(data: bytes) -> List[Indicator]:
    """Look for steganography signals in images."""
    indicators = []

    is_png = data.startswith(b"\x89PNG")
    is_jpeg = data.startswith(b"\xff\xd8\xff")

    if not (is_png or is_jpeg):
        return indicators

    # Trailing data after end marker
    if is_jpeg:
        end = data.rfind(b"\xff\xd9")
        if end != -1 and end < len(data) - 4:
            trailing = data[end + 2:]
            trailing_entropy = shannon_entropy(trailing)
            indicators.append(Indicator(
                layer="steg",
                category="suspicious",
                severity="high" if trailing_entropy > 7 else "medium",
                title=f"Data appended after JPEG end ({len(trailing)} bytes)",
                detail=f"Entropy of appended data: {trailing_entropy:.2f}. Common polyglot / stego technique.",
                confidence=0.85 if trailing_entropy > 7 else 0.55,
                mitre_attack=["T1027.003"],
            ))
    if is_png:
        end = data.rfind(b"IEND\xaeB`\x82")
        if end != -1 and end < len(data) - 10:
            trailing = data[end + 8:]
            trailing_entropy = shannon_entropy(trailing)
            indicators.append(Indicator(
                layer="steg",
                category="suspicious",
                severity="high" if trailing_entropy > 7 else "medium",
                title=f"Data appended after PNG IEND ({len(trailing)} bytes)",
                detail=f"Entropy of appended data: {trailing_entropy:.2f}. Common polyglot / stego technique.",
                confidence=0.85 if trailing_entropy > 7 else 0.55,
                mitre_attack=["T1027.003"],
            ))

    # LSB check on PNG
    pil = get_pil()
    numpy = get_numpy()
    if is_png and pil and numpy:
        try:
            img = pil.open(io.BytesIO(data))
            if img.mode in ("RGB", "RGBA"):
                arr = numpy.array(img)
                lsb = arr & 1
                # If LSBs are uniformly distributed, could be stego
                mean = float(lsb.mean())
                if 0.48 < mean < 0.52 and arr.size > 100_000:
                    indicators.append(Indicator(
                        layer="steg",
                        category="informational",
                        severity="low",
                        title="LSB distribution close to 0.5",
                        detail=f"LSB mean = {mean:.4f} - statistically consistent with LSB steganography (but also normal for photos).",
                        confidence=0.35,
                        mitre_attack=["T1027.003"],
                    ))
        except Exception:
            pass

    return indicators


# ==============================================================================
# LAYER 14: YARA MATCHING
# ==============================================================================

BUILTIN_YARA_RULES = r"""
rule Suspicious_PowerShell_Downloader
{
    strings:
        $s1 = "DownloadString" nocase
        $s2 = "IEX" nocase
        $s3 = "Invoke-Expression" nocase
        $s4 = "System.Net.WebClient" nocase
    condition:
        2 of them
}

rule Suspicious_Base64_PS_Command
{
    strings:
        $enc = /-e(nc|ncoded)?(command)?\s+[A-Za-z0-9+\/=]{40,}/ nocase
    condition:
        $enc
}

rule PE_Injection_Trio
{
    strings:
        $a = "VirtualAllocEx"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
    condition:
        all of them
}

rule ProcessHollowing
{
    strings:
        $a = "NtUnmapViewOfSection"
        $b = "ZwUnmapViewOfSection"
        $c = "SetThreadContext"
    condition:
        1 of ($a, $b) and $c
}

rule Ransomware_Note_Keywords
{
    strings:
        $a = "your files have been encrypted" nocase
        $b = "your data has been encrypted" nocase
        $c = "to decrypt" nocase
        $d = "send bitcoin" nocase
        $e = "your personal id" nocase
        $f = "TOR browser" nocase
        $g = "how to buy bitcoin" nocase
    condition:
        2 of them
}

rule Mimikatz_Strings
{
    strings:
        $a = "mimikatz" nocase
        $b = "gentilkiwi" nocase
        $c = "sekurlsa" nocase
        $d = "lsadump" nocase
        $e = "kerberos::" nocase
    condition:
        2 of them
}

rule Log4Shell_Payload
{
    strings:
        $a = "${jndi:ldap:"
        $b = "${jndi:rmi:"
        $c = "${jndi:dns:"
        $d = "${jndi:ldaps:"
        $e = "${${lower:j}ndi"
    condition:
        any of them
}

rule Follina_MSDT
{
    strings:
        $a = "ms-msdt:" nocase
        $b = "IT_BrowseForFile" nocase
        $c = "MSDTJS" nocase
    condition:
        1 of them
}

rule UPX_Packer
{
    strings:
        $a = "UPX!"
        $b = "UPX0"
        $c = "UPX1"
    condition:
        2 of them
}

rule Cobalt_Strike_Beacon_Config
{
    strings:
        $a = "beacon.dll" nocase
        $b = "%s (admin)" nocase
        $c = "ReflectiveLoader"
        $d = { 00 01 00 01 00 02 } // config sentinel
    condition:
        2 of them
}

rule Meterpreter_Strings
{
    strings:
        $a = "metsrv.dll" nocase
        $b = "meterpreter" nocase
        $c = "stdapi" nocase
        $d = "priv_passwd_get_sam_hashes" nocase
    condition:
        2 of them
}

rule Bitcoin_Wallet_Reference
{
    strings:
        $a = "wallet.dat" nocase
        $b = "electrum" nocase
        $c = "MultiBit" nocase
    condition:
        any of them
}

rule LNK_Attack_Pattern
{
    strings:
        $a = "cmd.exe" nocase
        $b = "powershell" nocase
        $c = "mshta" nocase
        $d = "rundll32" nocase
    condition:
        uint16(0) == 0x004C and any of them
}

rule Reverse_Shell_Unix
{
    strings:
        $a = "/dev/tcp/"
        $b = "bash -i"
        $c = "sh -i"
        $d = "nc -e"
        $e = "socat exec"
    condition:
        2 of them
}
"""


def analyze_yara(data: bytes, extra_rules_dir: Optional[str] = None) -> List[Indicator]:
    """Run YARA rules."""
    indicators = []
    yara = get_yara()
    if not yara:
        return indicators

    try:
        # Compile builtin
        rules_source = {"builtin": BUILTIN_YARA_RULES}

        # Load extras
        extra_dir = extra_rules_dir or os.environ.get("LAELAPS_YARA_RULES_DIR")
        if extra_dir and os.path.isdir(extra_dir):
            for rule_file in Path(extra_dir).rglob("*.yar*"):
                try:
                    with open(rule_file, "r", encoding="utf-8", errors="ignore") as f:
                        rules_source[f"ext_{rule_file.stem}"] = f.read()
                except Exception:
                    continue

        try:
            rules = yara.compile(sources=rules_source)
        except Exception as e:
            # Fall back to builtin only
            try:
                rules = yara.compile(source=BUILTIN_YARA_RULES)
            except Exception:
                return indicators

        matches = rules.match(data=data, timeout=30)
        for match in matches:
            severity = "high"
            if "Ransomware" in match.rule or "Log4Shell" in match.rule or "Follina" in match.rule:
                severity = "critical"
            elif "Suspicious" in match.rule or "Packer" in match.rule:
                severity = "medium"

            mitre = []
            if "Injection" in match.rule or "Hollowing" in match.rule:
                mitre = ["T1055"]
            if "Ransomware" in match.rule:
                mitre = ["T1486"]
            if "Log4Shell" in match.rule or "Follina" in match.rule:
                mitre = ["T1190", "T1203"]
            if "Mimikatz" in match.rule:
                mitre = ["T1003"]
            if "PowerShell" in match.rule:
                mitre = ["T1059.001"]

            indicators.append(Indicator(
                layer="yara",
                category="malicious" if severity in ("critical", "high") else "suspicious",
                severity=severity,
                title=f"YARA rule: {match.rule}",
                detail=f"Matched strings: {[s.identifier for s in match.strings][:10]}" if match.strings else "Rule matched.",
                mitre_attack=mitre,
                confidence=0.85 if severity in ("critical", "high") else 0.6,
            ))

    except Exception as e:
        indicators.append(Indicator(
            layer="yara",
            category="informational",
            severity="info",
            title="YARA scan error",
            detail=str(e),
            confidence=0.1,
        ))

    return indicators


# ==============================================================================
# LAYER 15: THREAT INTELLIGENCE LOOKUPS
# ==============================================================================

def check_virustotal(sha256: str) -> Dict[str, Any]:
    """Query VirusTotal by hash."""
    api_key = os.environ.get("VT_API_KEY")
    if not api_key or os.environ.get("LAELAPS_OFFLINE"):
        return {}

    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": api_key},
            timeout=15,
        )
        if r.status_code == 200:
            data = r.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()) if stats else 0,
                "first_seen": attrs.get("first_submission_date"),
                "last_seen": attrs.get("last_analysis_date"),
                "reputation": attrs.get("reputation"),
                "names": attrs.get("names", [])[:10],
                "popular_labels": [
                    r.get("popular_threat_name", [])
                    for r in attrs.get("popular_threat_classification", {}).get("popular_threat_name", [])
                ][:5],
                "type_description": attrs.get("type_description"),
            }
        elif r.status_code == 404:
            return {"found": False}
        else:
            return {"error": f"VT returned {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def check_malwarebazaar(sha256: str) -> Dict[str, Any]:
    """Query MalwareBazaar."""
    if os.environ.get("LAELAPS_OFFLINE"):
        return {}

    try:
        api_key = os.environ.get("MB_API_KEY", "")
        headers = {"Auth-Key": api_key} if api_key else {}
        r = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": sha256},
            headers=headers,
            timeout=15,
        )
        if r.status_code == 200:
            js = r.json()
            if js.get("query_status") == "ok":
                sample = js.get("data", [{}])[0]
                return {
                    "found": True,
                    "signature": sample.get("signature"),
                    "file_type": sample.get("file_type"),
                    "tags": sample.get("tags", []),
                    "first_seen": sample.get("first_seen"),
                    "delivery_method": sample.get("delivery_method"),
                }
            return {"found": False}
    except Exception as e:
        return {"error": str(e)}

    return {}


def check_threatfox(hash_value: str) -> Dict[str, Any]:
    """Query ThreatFox (abuse.ch) by hash."""
    if os.environ.get("LAELAPS_OFFLINE"):
        return {}

    try:
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_hash", "hash": hash_value},
            timeout=15,
        )
        if r.status_code == 200:
            js = r.json()
            if js.get("query_status") == "ok":
                iocs = js.get("data", [])
                if iocs:
                    return {
                        "found": True,
                        "malware_family": iocs[0].get("malware"),
                        "ioc_type": iocs[0].get("ioc_type"),
                        "confidence": iocs[0].get("confidence_level"),
                        "tags": iocs[0].get("tags", []),
                    }
                return {"found": False}
    except Exception as e:
        return {"error": str(e)}
    return {}


def reputation_indicators(rep: Dict[str, Any]) -> List[Indicator]:
    """Turn reputation results into indicators."""
    indicators = []

    vt = rep.get("virustotal", {})
    if vt.get("found") and vt.get("malicious", 0) > 0:
        mal = vt["malicious"]
        total = vt.get("total_engines", 1)
        pct = (mal / total) * 100 if total else 0

        if pct >= 50:
            sev = "critical"
            cat = "malicious"
            conf = 0.98
        elif pct >= 20:
            sev = "high"
            cat = "malicious"
            conf = 0.9
        elif pct >= 5:
            sev = "high"
            cat = "suspicious"
            conf = 0.8
        else:
            sev = "medium"
            cat = "suspicious"
            conf = 0.6

        indicators.append(Indicator(
            layer="reputation",
            category=cat,
            severity=sev,
            title=f"VirusTotal: {mal}/{total} engines detect ({pct:.0f}%)",
            detail=f"Threat labels: {vt.get('popular_labels', [])}",
            confidence=conf,
        ))

    mb = rep.get("malwarebazaar", {})
    if mb.get("found"):
        indicators.append(Indicator(
            layer="reputation",
            category="malicious",
            severity="critical",
            title=f"MalwareBazaar known sample: {mb.get('signature', 'unknown')}",
            detail=f"Tags: {mb.get('tags', [])}, first seen: {mb.get('first_seen')}",
            confidence=0.98,
        ))

    tf = rep.get("threatfox", {})
    if tf.get("found"):
        indicators.append(Indicator(
            layer="reputation",
            category="malicious",
            severity="critical",
            title=f"ThreatFox known IOC: {tf.get('malware_family', 'unknown')}",
            detail=f"IOC type: {tf.get('ioc_type')}, confidence: {tf.get('confidence')}",
            confidence=0.95,
        ))

    return indicators


# ==============================================================================
# LAYER 16: LLM VERDICT LAYER
# ==============================================================================

def llm_verdict(verdict: Verdict) -> Optional[str]:
    """Use an LLM to write a plain-English verdict summary. Optional."""
    if os.environ.get("LAELAPS_OFFLINE"):
        return None

    # Prefer Anthropic if key available
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    openai_key = os.environ.get("OPENAI_API_KEY")

    if not (anthropic_key or openai_key):
        return None

    # Prepare a compact summary for the model
    summary = {
        "file": verdict.filename,
        "size": verdict.size_bytes,
        "type": verdict.filetype,
        "sha256": verdict.hashes.get("sha256"),
        "verdict": verdict.verdict,
        "score": verdict.score,
        "top_indicators": [
            {
                "layer": ind.layer,
                "severity": ind.severity,
                "title": ind.title,
                "detail": ind.detail[:300],
            }
            for ind in sorted(verdict.indicators, key=lambda i: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(i.severity, 5))[:20]
        ],
        "reputation": verdict.reputation,
        "iocs_summary": {k: v[:5] for k, v in verdict.ioc_extracted.items()},
        "mitre_techniques": verdict.mitre_techniques,
        "families": verdict.families,
    }

    prompt = f"""You are a senior malware analyst. Below is the output of a multi-engine static analysis of a file. Write a concise verdict summary (3-6 paragraphs):

1. Overall verdict and confidence (state clearly: is this malicious, suspicious, or clean?)
2. Most compelling evidence (the top 3-5 indicators that drove the verdict)
3. Likely malware family or capability class (if identifiable)
4. Recommended next steps for the analyst (deeper analysis techniques, containment, etc.)
5. Caveats - what static analysis alone can't tell us

Be direct and technical. This goes to another analyst, not an executive.

ANALYSIS DATA:
{json.dumps(summary, indent=2, default=str)}
"""

    # Try Anthropic
    if anthropic_key:
        anth = get_anthropic()
        if anth:
            try:
                client = anth.Anthropic(api_key=anthropic_key)
                resp = client.messages.create(
                    model="claude-sonnet-5",
                    max_tokens=1500,
                    messages=[{"role": "user", "content": prompt}],
                )
                return resp.content[0].text
            except Exception as e:
                pass

    # Fallback to OpenAI
    if openai_key:
        oai = get_openai()
        if oai:
            try:
                client = oai.OpenAI(api_key=openai_key)
                resp = client.chat.completions.create(
                    model="gpt-4o",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=1500,
                )
                return resp.choices[0].message.content
            except Exception:
                pass

    return None


# ==============================================================================
# ORCHESTRATOR
# ==============================================================================

SEVERITY_WEIGHT = {"critical": 30, "high": 15, "medium": 6, "low": 2, "info": 0}
CATEGORY_MULT = {"malicious": 1.0, "suspicious": 0.7, "informational": 0.2}


def score_verdict(indicators: List[Indicator]) -> Tuple[float, str]:
    """Compute overall 0-100 score and verdict label."""
    if not indicators:
        return 0.0, "unknown"

    raw = 0.0
    for ind in indicators:
        raw += (
            SEVERITY_WEIGHT.get(ind.severity, 0)
            * CATEGORY_MULT.get(ind.category, 0.5)
            * ind.confidence
        )

    # Saturate to 100
    score = min(100.0, raw)

    if score >= 60:
        return score, "malicious"
    if score >= 25:
        return score, "suspicious"
    if score >= 5:
        return score, "unknown"
    return score, "clean"


def extract_families(indicators: List[Indicator], reputation: Dict) -> List[str]:
    """Extract malware family attributions."""
    families = set()

    # From reputation
    mb = reputation.get("malwarebazaar", {})
    if mb.get("signature"):
        families.add(mb["signature"])

    tf = reputation.get("threatfox", {})
    if tf.get("malware_family"):
        families.add(tf["malware_family"])

    vt = reputation.get("virustotal", {})
    for label in vt.get("popular_labels", []):
        if label:
            if isinstance(label, list):
                families.update(str(l) for l in label if l)
            else:
                families.add(str(label))

    # From YARA rule names
    for ind in indicators:
        if ind.layer == "yara":
            title = ind.title.replace("YARA rule: ", "")
            for family_hint in ["Mimikatz", "Cobalt_Strike", "Meterpreter", "Ransomware", "Log4Shell", "Follina"]:
                if family_hint in title:
                    families.add(family_hint.replace("_", " "))

    return sorted(families)


def analyze_file(
    filepath: str,
    yara_rules_dir: Optional[str] = None,
    recursive_depth: int = 1,
    _current_depth: int = 0,
) -> Verdict:
    """The full analysis pipeline for a single file."""
    start = time.time()

    filepath = os.path.abspath(filepath)
    filename = os.path.basename(filepath)

    with open(filepath, "rb") as f:
        data = f.read()

    verdict = Verdict(
        filepath=filepath,
        filename=filename,
        size_bytes=len(data),
        filetype="",
        hashes={},
        verdict="unknown",
        score=0.0,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    if not data:
        verdict.errors.append("File is empty")
        return verdict

    all_indicators: List[Indicator] = []

    try:
        # Layer 1: hashes
        verdict.hashes = compute_hashes(data)

        # Layer 2: filetype
        verdict.filetype = detect_filetype(data, filepath)

        # Layer 3: entropy
        all_indicators.extend(entropy_indicators(data))

        # Layer 4: strings + IOC extraction
        ascii_strs, unicode_strs = extract_strings(data)
        all_strings = ascii_strs + unicode_strs
        iocs = extract_iocs(all_strings)
        verdict.ioc_extracted = iocs
        all_indicators.extend(ioc_indicators(iocs))

        # Layer 5: keyword hunt
        all_indicators.extend(keyword_indicators(all_strings))

        # Layer 6: PE
        if verdict.filetype.startswith("PE"):
            pe_ind, pe_meta = analyze_pe(data)
            all_indicators.extend(pe_ind)
            if "imphash" in pe_meta:
                verdict.hashes["imphash"] = pe_meta["imphash"]

        # Layer 7: ELF
        if verdict.filetype.startswith("ELF"):
            elf_ind, _ = analyze_elf(data)
            all_indicators.extend(elf_ind)

        # Layer 8: Office
        if any(x in verdict.filetype for x in ("Office", "OOXML", "OLE", "Word", "Excel", "PowerPoint")):
            all_indicators.extend(analyze_office(data, filepath))

        # Layer 9: PDF
        if "PDF" in verdict.filetype:
            all_indicators.extend(analyze_pdf(data))

        # Layer 10: Scripts
        script_types = ["PowerShell", "VBScript", "JavaScript", "Shell script", "Batch",
                        "HTML Application", "Python-like", "HTA"]
        if any(t in verdict.filetype for t in script_types):
            all_indicators.extend(analyze_script(data))
        elif len(data) < 500_000:  # small enough to also try as script
            try:
                sample = data[:5000].decode("utf-8", errors="strict")
                if any(marker in sample for marker in ["<?php", "#!/bin/", "@echo", "function ", "$env:", "Set-", "$("]):
                    all_indicators.extend(analyze_script(data))
            except UnicodeDecodeError:
                pass

        # Layer 11: APK
        if "APK" in verdict.filetype:
            all_indicators.extend(analyze_apk(data, filepath))

        # Layer 12: Archives (recursive)
        if "ZIP" in verdict.filetype or "OOXML" in verdict.filetype or "APK" in verdict.filetype:
            arch_ind, inner = analyze_archive(data)
            all_indicators.extend(arch_ind)

            # Recurse into inner files
            if _current_depth < recursive_depth and inner:
                for inner_name, inner_data in inner[:5]:  # cap
                    try:
                        # Save inner to temp for recursive analysis
                        with tempfile.NamedTemporaryFile(
                            suffix=f"__{os.path.basename(inner_name)}",
                            delete=False,
                        ) as tf:
                            tf.write(inner_data)
                            tf_path = tf.name
                        try:
                            inner_verdict = analyze_file(
                                tf_path,
                                yara_rules_dir=yara_rules_dir,
                                recursive_depth=recursive_depth,
                                _current_depth=_current_depth + 1,
                            )
                            # Elevate inner malicious indicators
                            for ind in inner_verdict.indicators:
                                if ind.severity in ("critical", "high"):
                                    ind.detail = f"[in archive entry '{inner_name}'] " + ind.detail
                                    all_indicators.append(ind)
                        finally:
                            try:
                                os.unlink(tf_path)
                            except Exception:
                                pass
                    except Exception:
                        continue

        # Layer 13: Steganography
        if "image" in verdict.filetype.lower() or "PNG" in verdict.filetype or "JPEG" in verdict.filetype:
            all_indicators.extend(analyze_image(data))

        # Layer 14: YARA
        all_indicators.extend(analyze_yara(data, extra_rules_dir=yara_rules_dir))

        # Layer 15: reputation (network)
        rep = {}
        sha256 = verdict.hashes.get("sha256")
        if sha256 and not os.environ.get("LAELAPS_OFFLINE"):
            rep["virustotal"] = check_virustotal(sha256)
            rep["malwarebazaar"] = check_malwarebazaar(sha256)
            rep["threatfox"] = check_threatfox(sha256)

        verdict.reputation = rep
        all_indicators.extend(reputation_indicators(rep))

    except Exception as e:
        verdict.errors.append(f"Analysis error: {type(e).__name__}: {e}")

    # Dedupe (same layer + title)
    seen = set()
    deduped = []
    for ind in all_indicators:
        key = (ind.layer, ind.title)
        if key not in seen:
            seen.add(key)
            deduped.append(ind)
    all_indicators = deduped

    verdict.indicators = all_indicators
    verdict.score, verdict.verdict = score_verdict(all_indicators)

    # MITRE aggregation
    verdict.mitre_techniques = sorted(set(
        t for ind in all_indicators for t in ind.mitre_attack
    ))

    # Families
    verdict.families = extract_families(all_indicators, verdict.reputation)

    # LLM summary
    verdict.llm_summary = llm_verdict(verdict)

    verdict.analysis_time_seconds = round(time.time() - start, 2)

    return verdict


# ==============================================================================
# HASH-ONLY MODE (no file, just reputation lookup)
# ==============================================================================

def analyze_hash(hash_value: str) -> Dict[str, Any]:
    """Reputation-only lookup for a hash."""
    result = {"hash": hash_value, "reputation": {}}
    result["reputation"]["virustotal"] = check_virustotal(hash_value)
    result["reputation"]["malwarebazaar"] = check_malwarebazaar(hash_value)
    result["reputation"]["threatfox"] = check_threatfox(hash_value)
    return result


# ==============================================================================
# URL FETCH MODE
# ==============================================================================

def fetch_and_analyze(url: str, yara_rules_dir: Optional[str] = None) -> Verdict:
    """Download a URL and analyze."""
    with tempfile.NamedTemporaryFile(delete=False, suffix="__laelaps_dl") as tf:
        r = requests.get(url, stream=True, timeout=60, allow_redirects=True,
                         headers={"User-Agent": "laelaps-analyzer/1.0"})
        for chunk in r.iter_content(chunk_size=65536):
            tf.write(chunk)
        tf_path = tf.name

    try:
        return analyze_file(tf_path, yara_rules_dir=yara_rules_dir)
    finally:
        try:
            os.unlink(tf_path)
        except Exception:
            pass


# ==============================================================================
# CLI RENDERING
# ==============================================================================

def _v1_render_terminal(verdict: Verdict) -> None:
    """Pretty-print verdict to terminal (rich if available, plain otherwise)."""
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
        rich_available = True
    except ImportError:
        rich_available = False

    if not rich_available:
        _render_plain(verdict)
        return

    console = Console()

    # Banner
    verdict_colors = {
        "malicious": "bold red",
        "suspicious": "bold yellow",
        "unknown": "bold blue",
        "clean": "bold green",
    }
    verdict_color = verdict_colors.get(verdict.verdict, "white")

    header_text = Text()
    header_text.append(f"LAELAPS MALWARE ANALYSIS\n\n", style="bold cyan")
    header_text.append(f"File:    ", style="dim")
    header_text.append(f"{verdict.filename}\n", style="bold")
    header_text.append(f"Size:    ", style="dim")
    header_text.append(f"{verdict.size_bytes:,} bytes\n")
    header_text.append(f"Type:    ", style="dim")
    header_text.append(f"{verdict.filetype}\n")
    header_text.append(f"SHA256:  ", style="dim")
    header_text.append(f"{verdict.hashes.get('sha256', 'n/a')}\n\n")
    header_text.append(f"VERDICT: ", style="dim")
    header_text.append(f"{verdict.verdict.upper()}", style=verdict_color)
    header_text.append(f"   ")
    header_text.append(f"Score: {verdict.score:.1f}/100", style="bold")
    header_text.append(f"   ")
    header_text.append(f"Analysis: {verdict.analysis_time_seconds:.1f}s", style="dim")

    console.print(Panel(header_text, border_style=verdict_color.replace("bold ", "")))

    # Reputation summary
    if verdict.reputation:
        rep_table = Table(title="Threat Intel Reputation", show_header=True, header_style="bold magenta")
        rep_table.add_column("Source")
        rep_table.add_column("Verdict")
        rep_table.add_column("Details")

        vt = verdict.reputation.get("virustotal", {})
        if vt.get("found"):
            det = f"{vt.get('malicious', 0)}/{vt.get('total_engines', 0)} engines"
            det += f" | labels: {vt.get('popular_labels', [])[:3]}"
            rep_table.add_row("VirusTotal", "🔴 Known" if vt.get("malicious", 0) > 0 else "⚪ Clean", det)
        elif vt.get("found") is False:
            rep_table.add_row("VirusTotal", "⚪ Not found", "First-seen or private")
        elif "error" in vt:
            rep_table.add_row("VirusTotal", "❓", vt["error"])

        mb = verdict.reputation.get("malwarebazaar", {})
        if mb.get("found"):
            rep_table.add_row("MalwareBazaar", "🔴 Known",
                              f"{mb.get('signature', '?')} | tags: {mb.get('tags', [])[:5]}")
        elif mb.get("found") is False:
            rep_table.add_row("MalwareBazaar", "⚪ Not found", "-")

        tf = verdict.reputation.get("threatfox", {})
        if tf.get("found"):
            rep_table.add_row("ThreatFox", "🔴 Known",
                              f"{tf.get('malware_family', '?')} ({tf.get('ioc_type', '?')})")

        console.print(rep_table)

    # Indicators grouped by severity
    by_severity = defaultdict(list)
    for ind in verdict.indicators:
        by_severity[ind.severity].append(ind)

    sev_order = ["critical", "high", "medium", "low", "info"]
    sev_style = {"critical": "red", "high": "yellow", "medium": "blue", "low": "cyan", "info": "dim"}

    for sev in sev_order:
        if sev not in by_severity:
            continue
        items = by_severity[sev]
        ind_table = Table(
            title=f"{sev.upper()} ({len(items)})",
            show_header=True,
            header_style=f"bold {sev_style[sev]}",
        )
        ind_table.add_column("Layer", style="dim", width=10)
        ind_table.add_column("Title", width=42)
        ind_table.add_column("Detail")
        ind_table.add_column("Conf", justify="right", width=5)

        for ind in items:
            det = ind.detail[:120] + ("..." if len(ind.detail) > 120 else "")
            ind_table.add_row(ind.layer, ind.title, det, f"{ind.confidence:.2f}")
        console.print(ind_table)

    # IOCs
    if verdict.ioc_extracted:
        console.print("\n[bold cyan]Extracted IOCs:[/bold cyan]")
        for kind, values in verdict.ioc_extracted.items():
            if values:
                console.print(f"  [dim]{kind}[/dim]: {values[:5]}")

    # MITRE
    if verdict.mitre_techniques:
        console.print(f"\n[bold cyan]MITRE ATT&CK Techniques:[/bold cyan] {', '.join(verdict.mitre_techniques)}")

    # Families
    if verdict.families:
        console.print(f"\n[bold cyan]Attributed Families:[/bold cyan] {', '.join(verdict.families)}")

    # LLM summary
    if verdict.llm_summary:
        console.print(Panel(verdict.llm_summary, title="AI Verdict Summary", border_style="cyan"))

    # Errors
    if verdict.errors:
        console.print(f"\n[dim]Analysis notes:[/dim]")
        for e in verdict.errors:
            console.print(f"  - {e}")


def _render_plain(verdict: Verdict) -> None:
    """Plain-text renderer fallback."""
    print("=" * 78)
    print(f"LAELAPS MALWARE ANALYSIS")
    print("=" * 78)
    print(f"File:    {verdict.filename}")
    print(f"Size:    {verdict.size_bytes:,} bytes")
    print(f"Type:    {verdict.filetype}")
    print(f"SHA256:  {verdict.hashes.get('sha256', 'n/a')}")
    print(f"MD5:     {verdict.hashes.get('md5', 'n/a')}")
    print(f"")
    print(f"VERDICT: {verdict.verdict.upper()}   Score: {verdict.score:.1f}/100")
    print("=" * 78)

    if verdict.reputation:
        print("\n--- REPUTATION ---")
        for src, res in verdict.reputation.items():
            if res.get("found"):
                print(f"  {src}: KNOWN MALICIOUS ({res})")
            elif res.get("found") is False:
                print(f"  {src}: not found")
            elif "error" in res:
                print(f"  {src}: error - {res['error']}")

    by_sev = defaultdict(list)
    for ind in verdict.indicators:
        by_sev[ind.severity].append(ind)

    for sev in ("critical", "high", "medium", "low", "info"):
        if sev not in by_sev:
            continue
        print(f"\n--- {sev.upper()} ({len(by_sev[sev])}) ---")
        for ind in by_sev[sev]:
            print(f"  [{ind.layer}] {ind.title}")
            print(f"     {ind.detail[:200]}")
            if ind.mitre_attack:
                print(f"     MITRE: {ind.mitre_attack}")

    if verdict.mitre_techniques:
        print(f"\nMITRE techniques: {', '.join(verdict.mitre_techniques)}")

    if verdict.families:
        print(f"Attributed families: {', '.join(verdict.families)}")

    if verdict.llm_summary:
        print(f"\n--- AI VERDICT SUMMARY ---")
        print(verdict.llm_summary)


# ==============================================================================
# STREAMLIT UI
# ==============================================================================

def launch_streamlit() -> None:
    """Launch Streamlit UI mode. Called by re-invoking self with 'streamlit run'."""
    script = os.path.abspath(__file__)
    env = os.environ.copy()
    env["LAELAPS_UI_MODE"] = "1"
    subprocess.run(
        [sys.executable, "-m", "streamlit", "run", script,
         "--server.headless=false", "--browser.gatherUsageStats=false"],
        env=env,
    )


def streamlit_app() -> None:
    """Streamlit interface - called when we're inside a streamlit run."""
    import streamlit as st

    st.set_page_config(page_title="Laelaps Malware Analyzer", page_icon="🐕", layout="wide")
    st.title("🐕 Laelaps - Malware Detection, Attribution & Threat-Intel")
    st.caption("Deep static analysis + family attribution + threat-report generation in one agent.")

    with st.sidebar:
        st.subheader("Configuration")
        vt_key = st.text_input("VirusTotal API Key (optional)", type="password",
                               value=os.environ.get("VT_API_KEY", ""))
        anth_key = st.text_input("Anthropic API Key (optional, for LLM verdict)",
                                 type="password", value=os.environ.get("ANTHROPIC_API_KEY", ""))
        offline = st.checkbox("Offline mode (skip all network calls)")
        no_llm = st.checkbox("Skip LLM verdict summary")
        yara_dir = st.text_input("Custom YARA rules directory (optional)")
        recursive = st.slider("Archive recursion depth", 0, 3, 1)

        if vt_key:
            os.environ["VT_API_KEY"] = vt_key
        if anth_key:
            os.environ["ANTHROPIC_API_KEY"] = anth_key
        if offline:
            os.environ["LAELAPS_OFFLINE"] = "1"

    tab1, tab2, tab3 = st.tabs(["📄 File Upload", "🔗 URL / Hash", "📚 About"])

    with tab1:
        uploaded = st.file_uploader("Upload a file to analyze",
                                    type=None, accept_multiple_files=False)
        if uploaded:
            with tempfile.NamedTemporaryFile(
                delete=False, suffix=f"__{uploaded.name}"
            ) as tf:
                tf.write(uploaded.read())
                tf_path = tf.name

            try:
                with st.spinner(f"Analyzing {uploaded.name}..."):
                    rep = analyze_file_v2(tf_path, use_llm=not no_llm,
                                          yara_rules_dir=yara_dir or None, recursive_depth=recursive)
                _streamlit_render_v2(rep, st)
            finally:
                try:
                    os.unlink(tf_path)
                except Exception:
                    pass

    with tab2:
        st.subheader("Scan a URL or Hash")
        input_val = st.text_input("A URL to scan, or a hash (MD5/SHA1/SHA256)")
        deep = st.checkbox("Deep mode: download & analyze the payload (sandbox only!)")
        if st.button("Analyze"):
            if not input_val:
                st.warning("Enter a URL or hash.")
            elif re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", input_val):
                with st.spinner("Querying threat intel..."):
                    st.subheader(f"Hash: {input_val}")
                    st.json(rep_hash(input_val))
            else:
                with st.spinner(f"Scanning {input_val}..."):
                    try:
                        _streamlit_render_url(scan_url(input_val, deep=deep), st)
                    except Exception as e:
                        st.error(f"URL scan failed: {e}")

    with tab3:
        st.markdown("""
### About Laelaps

**Laelaps** fuses a deep static-analysis engine with a threat-intel attribution engine
and writes an analyst-grade report for any file, URL, or hash.

**Deep static engine:**
- Multi-hash (MD5, SHA1, SHA256, SHA512, TLSH, ssdeep, imphash) + VirusTotal / MalwareBazaar / ThreatFox
- Format-aware parsing: PE, ELF, Mach-O, PDF, Office/OLE, APK/DEX, scripts
- Entropy & packer detection, suspicious API combos (injection trio, hollowing, keylogging)
- IOC extraction, YARA (built-in + custom), VBA/XLM macros, PDF JS, PowerShell decode
- Archive recursion (zip-slip / zip-bomb), image steganography
- CVE / exploit strings (Log4Shell, Follina, EternalBlue, PrintNightmare) → MITRE ATT&CK

**Attribution & threat-intel engine:**
- Family attribution for ~30 families (LummaC2, RedLine, Vidar, AsyncRAT, Cobalt Strike, LockBit, …)
- Loader / packer / wrapper detection (Electron, NSIS, Themida, VMProtect, .NET Reactor, …)
- Electron/ASAR + .NET/CLR analysis, brand-impersonation / typosquat detection
- C2 fingerprinting (Telegram, Discord webhook, dead-drops, gate.php)
- Capability profiling, credential/wallet target enumeration, persistence + Sigma correlation
- URL scanner (structure + reputation, optional deep fetch) and threat-report generator
- Optional LLM verdict summary (Claude or GPT)

**Configuration:**
Set `VT_API_KEY`, `MB_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` for full functionality.
Set `LAELAPS_OFFLINE=1` for air-gapped analysis.

⚠️ **Authorized analysis only.** Do not analyze samples you don't have legal authority to inspect.
""")


def _streamlit_render_v2(rep: "V2Report", st) -> None:
    """Render a full Laelaps threat report (V2Report) in Streamlit."""
    badge = {"malicious": "🔴", "suspicious": "🟡", "unknown": "🔵", "clean": "🟢"}[rep.verdict]
    st.markdown(f"## {badge} Verdict: **{rep.verdict.upper()}**  ·  Threat score **{rep.score:.1f}/100**")

    if rep.reference_only:
        st.info("Reference content, not operational malware - this reads as detection rules / "
                "threat-intel / analysis code, so the score is dampened. Verify manually.")
    else:
        st.markdown("> " + build_one_liner(rep.families, rep.capabilities, rep.loaders,
                                           rep.brand_impersonation, rep.c2))

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("File type", rep.filetype[:28])
    c2.metric("Size", f"{rep.size_bytes:,} B")
    c3.metric("Signals", len(rep.signals))
    c4.metric("Families", len(rep.families))

    with st.expander("Hashes", expanded=False):
        st.json(rep.hashes)

    if rep.loaders:
        st.markdown("**Packaging / loader:** " + ", ".join(rep.loaders))

    if rep.families:
        st.subheader("Family attribution")
        st.table([{"Family": f.family, "Category": f.category,
                   "Confidence": f"{int(f.confidence * 100)}%",
                   "Basis": "; ".join(f.matched_signals[:3])} for f in rep.families[:8]])

    if rep.capabilities:
        st.subheader("Capabilities")
        st.table([{"Capability": cap, "Confidence": f"{int(m['confidence'] * 100)}%",
                   "Evidence": ", ".join(m["evidence"][:4])}
                  for cap, m in sorted(rep.capabilities.items(), key=lambda kv: -kv[1]["confidence"])])

    if rep.targeted_assets:
        st.subheader("Targeted assets")
        for cat, items in rep.targeted_assets.items():
            st.markdown(f"- **{cat}:** {', '.join(items[:8])}")

    if rep.c2:
        st.subheader("C2 / exfiltration")
        st.table([{"Channel": c["channel"], "Severity": c["severity"], "Indicator": c["match"]}
                  for c in rep.c2])

    if rep.brand_impersonation:
        st.subheader("Brand-impersonation domains")
        for b in rep.brand_impersonation:
            st.markdown(f"- **{b['host']}** - {b['reasons']}")

    if rep.persistence:
        st.subheader("Persistence")
        for p in rep.persistence:
            st.markdown(f"- {p['technique']}  *(MITRE {p['mitre']})*")

    if rep.signals:
        st.subheader("Signals")
        by_sev = defaultdict(list)
        for s in rep.signals:
            by_sev[s.severity].append(s)
        for sev in ("critical", "high", "medium", "low", "info"):
            if sev not in by_sev:
                continue
            with st.expander(f"{sev.upper()} ({len(by_sev[sev])})",
                             expanded=(sev in ("critical", "high"))):
                for s in by_sev[sev]:
                    st.markdown(f"**[{s.engine}]** {s.title}")
                    st.caption(s.detail)
                    if s.mitre:
                        st.markdown(f"*MITRE: {', '.join(s.mitre)}*")
                    st.divider()

    if rep.iocs:
        with st.expander("Extracted IOCs", expanded=False):
            for kind, values in rep.iocs.items():
                if values:
                    st.markdown(f"**{kind}** ({len(values)})")
                    st.code("\n".join(values[:50]))

    if rep.mitre:
        st.subheader("MITRE ATT&CK Techniques")
        st.write(", ".join(rep.mitre))

    if rep.llm_summary:
        st.subheader("AI Analyst Summary")
        st.markdown(rep.llm_summary)

    with st.expander("Full Markdown threat report", expanded=False):
        st.markdown(rep.report_md)

    st.download_button(
        "Download full JSON report",
        data=json.dumps(rep.to_dict(), indent=2, default=str),
        file_name=f"laelaps_{rep.hashes.get('sha256', 'unknown')[:16]}.json",
        mime="application/json",
    )


def _streamlit_render_url(res: Dict[str, Any], st) -> None:
    """Render a URL scan result in Streamlit."""
    badge = {"malicious": "🔴", "suspicious": "🟡", "clean": "🟢", "unknown": "🔵"}[res["verdict"]]
    st.markdown(f"## {badge} URL verdict: **{res['verdict'].upper()}**  ·  score **{res['score']}/100**")
    st.caption(f"host: {res['host']}")
    if res["signals"]:
        st.table([{"Severity": s["severity"], "Finding": s["title"], "Detail": s["detail"][:100]}
                  for s in res["signals"]])
    reputation = {k: v for k, v in (res.get("reputation") or {}).items() if v}
    if reputation:
        st.subheader("Reputation")
        st.json(reputation)
    if res.get("deep_analysis"):
        d = res["deep_analysis"]
        st.subheader("Deep payload analysis")
        st.markdown(f"Downloaded payload verdict: **{d['verdict']}** ({d['score']}/100). "
                    f"Families: {[f['family'] for f in d.get('families', [])]}")


# ==============================================================================
# REST API MODE
# ==============================================================================

def launch_api(host: str = "127.0.0.1", port: int = 8765) -> None:
    """Launch FastAPI REST server."""
    try:
        from fastapi import FastAPI, File, UploadFile, HTTPException
        from fastapi.responses import JSONResponse
        import uvicorn
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q",
                              "--break-system-packages", "fastapi", "uvicorn[standard]",
                              "python-multipart"])
        from fastapi import FastAPI, File, UploadFile, HTTPException
        from fastapi.responses import JSONResponse
        import uvicorn

    app = FastAPI(title="Laelaps Malware Analyzer API", version="1.0")

    @app.post("/analyze/file")
    async def analyze_endpoint(file: UploadFile = File(...)):
        with tempfile.NamedTemporaryFile(delete=False, suffix=f"__{file.filename}") as tf:
            content = await file.read()
            tf.write(content)
            tf_path = tf.name
        try:
            rep = analyze_file_v2(tf_path)
            return JSONResponse(rep.to_dict())
        finally:
            try:
                os.unlink(tf_path)
            except Exception:
                pass

    @app.post("/analyze/hash/{hash_value}")
    async def hash_endpoint(hash_value: str):
        if not re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", hash_value):
            raise HTTPException(400, "Not a valid MD5/SHA1/SHA256 hash")
        return rep_hash(hash_value)

    @app.get("/scan/url")
    async def url_endpoint(url: str, deep: bool = False):
        return scan_url(url, deep=deep)

    @app.get("/health")
    async def health():
        return {"status": "ok", "version": "1.0"}

    print(f"Starting Laelaps API server on http://{host}:{port}")
    print(f"OpenAPI docs at http://{host}:{port}/docs")
    uvicorn.run(app, host=host, port=port)


# ============================================================================
# ATTRIBUTION & THREAT-INTEL ENGINE (family attribution, loaders, Electron,
# .NET, brand-impersonation, C2 fingerprinting, capability profiling, Sigma,
# URL scanner, threat-report generator, and the unified orchestrator + CLI)
# ============================================================================

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_WEIGHT = {"critical": 34, "high": 17, "medium": 7, "low": 2, "info": 0}


# ==============================================================================
# DATA MODELS
# ==============================================================================
@dataclass
class Signal:
    """One detection produced by a v2 engine."""
    engine: str
    severity: str            # critical | high | medium | low | info
    title: str
    detail: str
    confidence: float = 0.5  # 0..1
    mitre: List[str] = field(default_factory=list)
    evidence: str = ""


@dataclass
class FamilyMatch:
    family: str
    category: str            # infostealer | rat | loader | ransomware | banker | clipper | keylogger | framework
    confidence: float
    matched_signals: List[str]
    description: str
    distribution: str = ""


@dataclass
class V2Report:
    filepath: str
    filename: str
    size_bytes: int
    filetype: str
    hashes: Dict[str, str]
    verdict: str             # malicious | suspicious | clean | unknown
    score: float             # 0..100
    families: List[FamilyMatch] = field(default_factory=list)
    capabilities: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    signals: List[Signal] = field(default_factory=list)
    loaders: List[str] = field(default_factory=list)
    c2: List[Dict[str, str]] = field(default_factory=list)
    targeted_assets: Dict[str, List[str]] = field(default_factory=dict)
    brand_impersonation: List[Dict[str, str]] = field(default_factory=dict)
    persistence: List[Dict[str, str]] = field(default_factory=list)
    iocs: Dict[str, List[str]] = field(default_factory=dict)
    mitre: List[str] = field(default_factory=list)
    reputation: Dict[str, Any] = field(default_factory=dict)
    report_md: str = ""
    reference_only: bool = False
    llm_summary: Optional[str] = None
    analysis_time_seconds: float = 0.0
    timestamp: str = ""
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["families"] = [asdict(f) for f in self.families]
        d["signals"] = [asdict(s) for s in self.signals]
        return d


# ==============================================================================
# PRIMITIVES (self-sufficient; mirror v1 so we can run without it)
# ==============================================================================
def read_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def v2_compute_hashes(data: bytes) -> Dict[str, str]:
    h = {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    try:
        import tlsh
        t = tlsh.hash(data)
        if t and t != "TNULL":
            h["tlsh"] = t
    except Exception:
        pass
    return h


# shannon_entropy is provided by the deep-static engine above.


def v2_extract_strings(data: bytes, min_len: int = 4) -> List[str]:
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    out = [m.decode("ascii", "ignore") for m in ascii_re.findall(data)]
    out += [m.decode("utf-16-le", "ignore") for m in utf16_re.findall(data)]
    return out


MAGIC = {
    b"MZ": "PE (Windows executable)",
    b"\x7fELF": "ELF (Linux executable)",
    b"\xfe\xed\xfa\xce": "Mach-O",
    b"\xfe\xed\xfa\xcf": "Mach-O (64)",
    b"\xcf\xfa\xed\xfe": "Mach-O (64 LE)",
    b"\xca\xfe\xba\xbe": "Mach-O universal / Java class",
    b"PK\x03\x04": "ZIP / Office / JAR / APK / asar-container",
    b"Rar!": "RAR archive",
    b"7z\xbc\xaf\x27\x1c": "7-Zip archive",
    b"\x1f\x8b\x08": "gzip",
    b"%PDF": "PDF document",
    b"\xd0\xcf\x11\xe0": "OLE (legacy Office / MSI)",
    b"\x89PNG": "PNG image",
    b"\xff\xd8\xff": "JPEG image",
    b"dex\n": "DEX (Android)",
    b"#!": "shell script",
    b"\x04\x22M\x18": "asar (Electron archive, pickle)",
}


def v2_detect_filetype(data: bytes, path: str) -> str:
    head = data[:64]
    for sig, name in MAGIC.items():
        if head.startswith(sig):
            if sig == b"PK\x03\x04":
                blob = data[:200000]
                if b"AndroidManifest.xml" in blob:
                    return "APK (Android package)"
                if b"[Content_Types].xml" in data[:5000] or b"word/" in blob or b"xl/" in blob:
                    return "OOXML (Office Open XML)"
            if sig == b"MZ" and is_dotnet_pe(data):
                return "PE (.NET / CLR assembly)"
            return name
    ext = Path(path).suffix.lower()
    return {
        ".ps1": "PowerShell script", ".vbs": "VBScript", ".js": "JavaScript",
        ".hta": "HTML application", ".bat": "Batch script", ".cmd": "Batch script",
        ".sh": "Shell script", ".py": "Python script", ".jar": "Java archive",
        ".asar": "asar (Electron archive)", ".lnk": "Windows shortcut",
    }.get(ext, "Unknown / binary")


# lightweight IOC extraction (v2 self-sufficient version)
IOC_RE = {
    "urls": re.compile(r"https?://[^\s\"'<>\\|)}\]]{4,300}"),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"),
    "domains": re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"),
    "btc": re.compile(r"\b(?:bc1[a-z0-9]{20,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    "eth": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "xmr": re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
    "onion": re.compile(r"\b[a-z2-7]{16,56}\.onion\b"),
    "telegram": re.compile(r"(?:t\.me/|@)[A-Za-z0-9_]{4,64}"),
}
_LEGIT = ("microsoft.com", "windows.com", "google.com", "gstatic.com", "apple.com",
          "mozilla.org", "w3.org", "schemas.", "verisign.com", "digicert.com",
          "sectigo.com", "openxmlformats.org", "gnu.org")
_IMG_EXT = (".dll", ".exe", ".sys", ".png", ".jpg", ".gif", ".txt", ".log", ".xml",
            ".json", ".dat", ".tmp", ".css", ".js", ".ico", ".pak", ".node")
# final labels that are file-extensions / code identifiers, not real TLDs
_NONTLD = {"asar", "wallet", "sqlite", "bin", "dat", "exe", "dll", "sys", "node", "pak",
           "js", "json", "py", "sync", "tmp", "log", "ini", "xml", "db", "lnk", "sqlite3",
           "php", "join", "min", "map", "html", "htm", "aspx", "jsp", "cgi", "split", "exec"}


def _plausible_domain(d: str) -> bool:
    if re.search(r"[A-Z]", d):        # malware host strings are ~always lowercase;
        return False                  # internal capitals => code identifier (fs.readFileSync)
    tld = d.rsplit(".", 1)[-1].lower()
    return tld.isalpha() and (2 <= len(tld) <= 24) and tld not in _NONTLD


def v2_extract_iocs(strings: List[str]) -> Dict[str, List[str]]:
    text = "\n".join(strings)
    out: Dict[str, List[str]] = {}
    for name, rx in IOC_RE.items():
        vals = sorted(set(rx.findall(text)))
        if name == "domains":
            vals = [d for d in vals
                    if not any(l in d.lower() for l in _LEGIT)
                    and not d.lower().endswith(_IMG_EXT)
                    and _plausible_domain(d)
                    and 4 < len(d) < 100]
        if name == "ipv4":
            vals = [ip for ip in vals
                    if not ip.startswith(("0.", "127.", "10.", "192.168.", "172.16.", "255.", "169.254."))]
        if vals:
            out[name] = vals[:300]
    return out


def is_dotnet_pe(data: bytes) -> bool:
    """Detect a .NET/CLR assembly. Prefer pefile; fall back to byte signatures."""
    pe_mod = get_pefile()
    if pe_mod is not None and data[:2] == b"MZ":
        try:
            pe = pe_mod.PE(data=data, fast_load=True)
            pe.parse_data_directories(
                directories=[pe_mod.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]])
            dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY
            has = len(dd) > 14 and dd[14].VirtualAddress != 0 and dd[14].Size != 0
            pe.close()
            if has:
                return True
        except Exception:
            pass
    # signature fallback (works with no deps)
    if b"BSJB" in data and (b"mscoree.dll" in data or b"_CorExeMain" in data
                            or b"#Strings" in data or b"#~" in data):
        return True
    return False


def lev(a: str, b: str) -> int:
    """Levenshtein distance (small, pure-python)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]

# ==============================================================================
# A. MALWARE FAMILY SIGNATURE DATABASE
# ------------------------------------------------------------------------------
# Public, behavior/string-level detection signatures (the kind threat-intel teams
# publish). These identify KNOWN malware so a defender can attribute a sample.
# They provide no uplift for building malware - a stealer author already knows
# browser paths; the value here is purely recognition. Fuzzy on purpose: the
# attributor combines several weak signals into a confidence-weighted verdict.
# ==============================================================================
FAMILY_DB: List[Dict[str, Any]] = [
    {"name": "LummaC2", "aliases": ["Lumma", "LummaStealer"], "category": "infostealer",
     "desc": "C-based infostealer (MaaS). Grabs browser creds/cookies/autofill, crypto "
             "wallets and 2FA extensions; resolves C2 via dead-drops (Steam/Telegram). "
             "Heavily distributed through fake/cracked software installers and malvertising.",
     "strings": ["lummac2", "lid=", "soft_id=", "lumma"],
     "c2": [r"steamcommunity\.com/profiles/", r"api\.telegram\.org/bot"],
     "caps": ["Browser credential theft", "Cookie / session theft", "Crypto wallet theft",
              "Data exfiltration", "Discovery / recon"],
     "targets": ["Browsers (Chromium)", "Crypto wallets (desktop)", "Crypto wallet extensions",
                 "2FA / authenticators"],
     "mitre": ["T1555.003", "T1539", "T1005", "T1102"], "min_signals": 2,
     "distribution": "fake software installers (e.g. counterfeit VSCode/Chrome setups), cracks, malvertising"},

    {"name": "RedLine Stealer", "aliases": ["RedLine"], "category": "infostealer",
     "desc": ".NET infostealer. Steals browser data, crypto wallets, VPN/FTP creds, Discord/"
             "Telegram tokens; config is Base64/SOAP. Uses the Leaf.xNet HTTP library.",
     "strings": ["redline", "leaf.xnet", "redlinestealer", "scannedwallet", "browserextension"],
     "dotnet": True, "c2": [],
     "caps": ["Browser credential theft", "Cookie / session theft", "Crypto wallet theft",
              "Data exfiltration", "Discovery / recon"],
     "targets": ["Browsers (Chromium)", "Crypto wallets (desktop)", "VPN configs",
                 "Email / FTP clients", "Messaging apps"],
     "mitre": ["T1555.003", "T1552.001", "T1005"], "min_signals": 2,
     "distribution": "cracked software, malicious ads, phishing attachments"},

    {"name": "Vidar", "aliases": ["Vidar Stealer"], "category": "infostealer",
     "desc": "Arkei-derived infostealer; pulls C2 config from Telegram/Steam dead-drops, "
             "grabs browser data, wallets, 2FA and arbitrary documents.",
     "strings": ["vidar"], "c2": [r"steamcommunity\.com/profiles/", r"t\.me/"],
     "caps": ["Browser credential theft", "Cookie / session theft", "Crypto wallet theft",
              "Data exfiltration"],
     "targets": ["Browsers (Chromium)", "Crypto wallets (desktop)", "Messaging apps"],
     "mitre": ["T1555.003", "T1102.001"], "min_signals": 2,
     "distribution": "loaders, cracked software, malvertising"},

    {"name": "StealC", "aliases": ["Stealc"], "category": "infostealer",
     "desc": "Lightweight Vidar/Raccoon-lineage stealer with a PHP gate C2.",
     "strings": ["stealc"], "c2": [r"/[a-z0-9]{6,}\.php", r"/gate"],
     "caps": ["Browser credential theft", "Crypto wallet theft", "Data exfiltration"],
     "targets": ["Browsers (Chromium)", "Crypto wallets (desktop)"], "min_signals": 2,
     "mitre": ["T1555.003"], "distribution": "loaders, cracked software"},

    {"name": "Raccoon Stealer", "aliases": ["Raccoon", "RecordBreaker"], "category": "infostealer",
     "desc": "MaaS stealer; Telegram dead-drop resolver, browser + wallet theft.",
     "strings": ["raccoon", "recordbreaker"], "c2": [r"t\.me/", r"api\.telegram\.org"],
     "caps": ["Browser credential theft", "Crypto wallet theft", "Data exfiltration"],
     "targets": ["Browsers (Chromium)", "Crypto wallets (desktop)"], "min_signals": 2,
     "mitre": ["T1555.003"], "distribution": "malvertising, loaders"},

    {"name": "Rhadamanthys", "category": "infostealer",
     "desc": "Modular stealer with a custom loader; browser/wallet/messaging theft.",
     "strings": ["rhadamanthys"], "c2": [],
     "caps": ["Browser credential theft", "Crypto wallet theft", "Data exfiltration"],
     "targets": ["Browsers (Chromium)", "Crypto wallets (desktop)", "Messaging apps"],
     "min_signals": 1, "mitre": ["T1555.003"], "distribution": "malvertising, phishing"},

    {"name": "Meduza Stealer", "category": "infostealer",
     "desc": "Windows stealer targeting browsers, wallets, password managers.",
     "strings": ["meduza"], "c2": [],
     "caps": ["Browser credential theft", "Crypto wallet theft"],
     "targets": ["Browsers (Chromium)", "Crypto wallets (desktop)", "Password managers"],
     "min_signals": 1, "mitre": ["T1555"], "distribution": "underground MaaS"},

    {"name": "AgentTesla", "aliases": ["Agent Tesla"], "category": "keylogger",
     "desc": ".NET keylogger/stealer; SMTP/FTP/Telegram exfil, clipboard + screenshot + "
             "browser credential grab.",
     "strings": ["agenttesla", "agent tesla"], "dotnet": True,
     "c2": [r"api\.telegram\.org/bot", r"smtp", r"ftp://"],
     "caps": ["Keylogging", "Browser credential theft", "Screen capture",
              "Clipboard hijacking (clipper)", "Data exfiltration"],
     "targets": ["Browsers (Chromium)", "Email / FTP clients"], "min_signals": 2,
     "mitre": ["T1056.001", "T1113", "T1552.001"], "distribution": "phishing attachments"},

    {"name": "Snake Keylogger", "aliases": ["404 Keylogger"], "category": "keylogger",
     "desc": ".NET keylogger; keystrokes, clipboard, screenshots, browser creds; "
             "SMTP/Telegram/FTP exfil.",
     "strings": ["snake keylogger", "404 keylogger", "snakekeylogger"], "dotnet": True,
     "c2": [r"api\.telegram\.org/bot", r"smtp"],
     "caps": ["Keylogging", "Clipboard hijacking (clipper)", "Screen capture",
              "Browser credential theft", "Data exfiltration"],
     "targets": ["Browsers (Chromium)", "Email / FTP clients"], "min_signals": 2,
     "mitre": ["T1056.001"], "distribution": "phishing attachments"},

    {"name": "FormBook / XLoader", "aliases": ["FormBook", "XLoader"], "category": "infostealer",
     "desc": "Form-grabber + stealer + keylogger with HTTP C2 (XLoader is the cross-platform "
             "successor).",
     "strings": ["formbook", "xloader"], "c2": [],
     "caps": ["Browser credential theft", "Keylogging", "Data exfiltration", "Discovery / recon"],
     "targets": ["Browsers (Chromium)"], "min_signals": 1,
     "mitre": ["T1056.001", "T1185"], "distribution": "phishing"},

    {"name": "AsyncRAT", "aliases": ["Async RAT", "AsyncClient"], "category": "rat",
     "desc": ".NET remote-access trojan; remote shell, keylog, screen, file ops, plugin loading. "
             "C2 host often fetched from a paste service.",
     "strings": ["asyncrat", "asyncclient", "async rat"], "dotnet": True, "c2": [],
     "caps": ["Remote access / RAT", "Keylogging", "Screen capture", "Command execution",
              "Persistence", "Data exfiltration"],
     "targets": [], "min_signals": 1, "mitre": ["T1219", "T1056.001", "T1113"],
     "distribution": "loaders, phishing, cracked software"},

    {"name": "Quasar RAT", "aliases": ["Quasar", "QuasarRAT"], "category": "rat",
     "desc": "Open-source .NET RAT (frequently abused); remote desktop, keylog, creds.",
     "strings": ["quasar", "quasarrat", "quasar.common", "quasar.client"], "dotnet": True, "c2": [],
     "caps": ["Remote access / RAT", "Keylogging", "Browser credential theft", "Command execution"],
     "targets": ["Browsers (Chromium)"], "min_signals": 1, "mitre": ["T1219"],
     "distribution": "phishing, loaders"},

    {"name": "njRAT", "aliases": ["Bladabindi", "njq8"], "category": "rat",
     "desc": ".NET RAT; keylog, remote shell, webcam, USB spreading.",
     "strings": ["njrat", "njq8", "bladabindi"], "dotnet": True, "c2": [],
     "caps": ["Remote access / RAT", "Keylogging", "Command execution", "Persistence"],
     "targets": [], "min_signals": 1, "mitre": ["T1219"], "distribution": "USB, phishing, cracks"},

    {"name": "DCRat", "aliases": ["Dark Crystal RAT"], "category": "rat",
     "desc": "Modular .NET RAT with a plugin architecture; stealer + surveillance plugins.",
     "strings": ["dcrat", "dark crystal"], "dotnet": True, "c2": [],
     "caps": ["Remote access / RAT", "Keylogging", "Browser credential theft", "Screen capture"],
     "targets": ["Browsers (Chromium)"], "min_signals": 1, "mitre": ["T1219"],
     "distribution": "phishing, cracked software"},

    {"name": "Remcos", "aliases": ["Remcos RAT"], "category": "rat",
     "desc": "Commercial RAT (Breaking-Security) abused as malware; full remote control.",
     "strings": ["remcos", "breaking-security", "rmc-"], "c2": [],
     "caps": ["Remote access / RAT", "Keylogging", "Screen capture", "Command execution"],
     "targets": [], "min_signals": 1, "mitre": ["T1219"], "distribution": "phishing attachments"},

    {"name": "NanoCore", "aliases": ["Nano Core"], "category": "rat",
     "desc": ".NET RAT; plugins for keylog, surveillance, credential theft.",
     "strings": ["nanocore", "nano core", "nanotechnology"], "dotnet": True, "c2": [],
     "caps": ["Remote access / RAT", "Keylogging", "Screen capture", "Command execution"],
     "targets": [], "min_signals": 1, "mitre": ["T1219"], "distribution": "phishing"},

    {"name": "Warzone / Ave Maria", "aliases": ["Warzone RAT", "AveMaria"], "category": "rat",
     "desc": "RAT with hidden-VNC (hVNC), credential theft, UAC bypass.",
     "strings": ["warzone", "ave_maria", "avemaria", "ave maria"], "c2": [],
     "caps": ["Remote access / RAT", "Browser credential theft", "Command execution",
              "Privilege escalation"],
     "targets": ["Browsers (Chromium)"], "min_signals": 1, "mitre": ["T1219", "T1548.002"],
     "distribution": "phishing"},

    {"name": "Cobalt Strike Beacon", "aliases": ["Cobalt Strike", "CobaltStrike"],
     "category": "framework",
     "desc": "Commercial post-exploitation framework, ubiquitously abused. Beacon implant for "
             "C2, lateral movement, injection. Named-pipe & malleable-HTTP C2.",
     "strings": ["beacon.dll", "reflectiveloader", "%s (admin)", "\\\\.\\pipe\\msse-",
                 "\\\\.\\pipe\\status_", "spawnto"], "c2": [r"\\\\\.\\pipe\\msse-"],
     "caps": ["Remote access / RAT", "Command execution", "Credential dumping (LSASS)",
              "Privilege escalation"],
     "targets": [], "min_signals": 2, "mitre": ["T1219", "T1055", "T1090"],
     "distribution": "post-exploitation (red-team tool abused by threat actors)"},

    {"name": "Meterpreter", "aliases": ["Metasploit"], "category": "framework",
     "desc": "Metasploit implant; in-memory command execution, pivoting, credential access.",
     "strings": ["meterpreter", "metsrv", "stdapi", "priv_passwd_get_sam_hashes"], "c2": [],
     "caps": ["Remote access / RAT", "Command execution", "Credential dumping (LSASS)"],
     "targets": [], "min_signals": 2, "mitre": ["T1219", "T1003"],
     "distribution": "exploitation frameworks"},

    {"name": "Amadey", "category": "loader",
     "desc": "Loader/bot; fingerprints host, pulls tasks & additional payloads, drops stealers.",
     "strings": ["amadey"], "c2": [r"/index\.php"],
     "caps": ["Downloader / loader", "Discovery / recon", "Persistence", "Data exfiltration"],
     "targets": [], "min_signals": 1, "mitre": ["T1105", "T1082"],
     "distribution": "exploit kits, SmokeLoader chains"},

    {"name": "SmokeLoader", "aliases": ["Smoke Loader", "Dofoil"], "category": "loader",
     "desc": "Modular loader/backdoor; heavy anti-analysis, downloads follow-on malware.",
     "strings": ["smokeloader", "smoke loader"], "c2": [],
     "caps": ["Downloader / loader", "Anti-analysis / sandbox evasion", "Persistence"],
     "targets": [], "min_signals": 1, "mitre": ["T1105", "T1497"],
     "distribution": "spam, cracked software"},

    {"name": "LockBit", "category": "ransomware",
     "desc": "RaaS ransomware; fast local + network encryption, self-spreading, recovery wiping.",
     "strings": ["lockbit", "restore-my-files", ".lockbit", "lockbit_ransomware"], "c2": [],
     "caps": ["Ransomware / destruction", "Discovery / recon", "Defense evasion (AV tamper)"],
     "targets": [], "min_signals": 1, "mitre": ["T1486", "T1490"], "distribution": "RaaS affiliates"},

    {"name": "Conti", "category": "ransomware",
     "desc": "Ransomware (Ryuk lineage); multithreaded encryption, shadow-copy deletion.",
     "strings": ["conti", "conti_log", "readme.txt.conti"], "c2": [],
     "caps": ["Ransomware / destruction", "Defense evasion (AV tamper)"], "targets": [],
     "min_signals": 1, "mitre": ["T1486", "T1490"], "distribution": "RaaS affiliates"},

    {"name": "BlackCat / ALPHV", "aliases": ["BlackCat", "ALPHV"], "category": "ransomware",
     "desc": "Rust ransomware; cross-platform, highly configurable, triple extortion.",
     "strings": ["blackcat", "alphv", "recover-", "-files.txt"], "c2": [],
     "caps": ["Ransomware / destruction", "Discovery / recon"], "targets": [], "min_signals": 1,
     "mitre": ["T1486"], "distribution": "RaaS affiliates"},

    {"name": "Emotet", "category": "loader",
     "desc": "Modular loader/banker; email-thread hijacking spreader, drops other malware.",
     "strings": ["emotet"], "c2": [],
     "caps": ["Downloader / loader", "Data exfiltration", "Persistence"], "targets": [],
     "min_signals": 1, "mitre": ["T1105", "T1566"], "distribution": "malicious spam (malspam)"},
]

# capability -> detection needles (lowercased regex). Higher-level rollup for reports.
CAPABILITY_SIGS: Dict[str, List[str]] = {
    "Browser credential theft": [r"login data", r"logins\.json", r"signons", r"web data",
                                 r"\bkey4\.db\b", r"\bkey3\.db\b", r"password", r"autofill"],
    "Cookie / session theft": [r"\bcookies\b", r"cookies\.sqlite", r"network\\cookies",
                               r"sessionstore", r"\bsession(s)?\b", r"cookie stealer"],
    "Crypto wallet theft": [r"wallet\.dat", r"\bexodus\b", r"\belectrum\b", r"\bmetamask\b",
                            r"\bphantom\b", r"\bledger\b", r"\btrezor\b", r"\batomic\b",
                            r"\bcoinomi\b", r"keystore", r"\bkeplr\b", r"\bguarda\b"],
    "Clipboard hijacking (clipper)": [r"setclipboarddata", r"getclipboarddata", r"clipboard",
                                      r"addclipboardformatlistener", r"\bclipper\b"],
    "Keylogging": [r"getasynckeystate", r"setwindowshookex", r"getkeyboardstate", r"\bkeylog",
                   r"wh_keyboard", r"registerrawinputdevices"],
    "Screen capture": [r"bitblt", r"\bgetdc\b", r"createcompatiblebitmap", r"screenshot",
                       r"screen capture", r"gdiplus"],
    "Remote access / RAT": [r"\bhvnc\b", r"hidden vnc", r"remote desktop", r"\bvnc\b",
                            r"reverse shell", r"remote control", r"anydesk", r"teamviewer",
                            r"\bsocks5?\b proxy", r"remote shell"],
    "Command execution": [r"cmd\.exe", r"powershell", r"\bwscript\b", r"createprocess",
                          r"shellexecute", r"/bin/sh", r"child_process", r"winexec"],
    "Persistence": [r"currentversion\\run", r"runonce", r"schtasks", r"\bstartup\b",
                    r"winlogon", r"sc create", r"createservice"],
    "Anti-analysis / sandbox evasion": [r"isdebuggerpresent", r"vboxservice", r"\bvmware\b",
                                        r"sbiedll", r"\bwireshark\b", r"checkremotedebugger",
                                        r"\bsandbox\b", r"\bvirtualbox\b", r"\bqemu\b",
                                        r"cuckoo", r"anti[_ ]?vm"],
    "Defense evasion (AV tamper)": [r"add-mppreference", r"exclusionpath", r"\bdefender\b",
                                    r"\bamsi\b", r"amsibypass", r"disable.{0,12}(defender|antivirus)",
                                    r"netsh.{0,10}firewall", r"etw"],
    "Data exfiltration": [r"api\.telegram\.org", r"/api/webhooks/", r"ftp://", r"\bsmtp\b",
                          r"sendmail", r"httpsendrequest", r"webclient", r"\bexfil", r"\bupload"],
    "Discovery / recon": [r"getcomputername", r"getusername", r"systeminfo", r"getlocaleinfo",
                          r"ipify", r"ifconfig\.me", r"fingerprint", r"machineguid", r"getadaptersinfo"],
    "Downloader / loader": [r"downloadfile", r"downloadstring", r"urldownloadtofile", r"certutil",
                            r"bitsadmin", r"\bloader\b", r"\bdropper\b", r"\bpayload\b"],
    "Ransomware / destruction": [r"your files have been encrypted", r"\bransom", r"\.locky\b",
                                 r"vssadmin.{0,10}delete", r"bcdedit", r"wbadmin.{0,10}delete",
                                 r"readme.{0,20}decrypt", r"how.{0,3}to.{0,3}decrypt"],
    "Credential dumping (LSASS)": [r"\blsass\b", r"minidumpwritedump", r"sekurlsa", r"mimikatz",
                                   r"comsvcs\.dll"],
    "Privilege escalation": [r"uac bypass", r"fodhelper", r"eventvwr", r"seimpersonate",
                             r"\bjuicypotato\b", r"bypassuac"],
}

# credential/wallet target categories -> artifact strings the sample would reference.
# (Public artifact locations, listed as DETECTION needles - not an exfil how-to.)
CRED_TARGETS: Dict[str, List[str]] = {
    "Browsers (Chromium)": ["login data", "web data", "\\user data\\", "local state",
                            "cookies", "network\\cookies", "\\google\\chrome", "\\microsoft\\edge",
                            "\\brave", "\\opera", "\\chromium"],
    "Browsers (Gecko/Firefox)": ["logins.json", "key4.db", "key3.db", "cookies.sqlite",
                                 "places.sqlite", "signons.sqlite", "\\mozilla\\firefox"],
    "Crypto wallets (desktop)": ["wallet.dat", "exodus", "electrum", "atomic", "coinomi",
                                 "ledger live", "guarda", "jaxx", "\\bitcoin\\wallets", "keystore"],
    "Crypto wallet extensions": ["metamask", "nkbihfbeogaeaoehlefnkodbefgpgknn", "phantom",
                                 "tronlink", "binance chain", "ronin", "keplr",
                                 "ejbalbakoplchlghecdalmeeeajnimhm"],
    "Messaging apps": ["\\telegram desktop\\tdata", "discord\\local storage", "discord token",
                       "\\signal", "\\element", "pidgin\\accounts.xml", "\\skype"],
    "Email / FTP clients": ["thunderbird", "filezilla\\recentservers.xml",
                            "filezilla\\sitemanager.xml", "winscp.ini", "coreftp", "\\outlook"],
    "VPN configs": ["openvpn", "protonvpn", "nordvpn", "\\wireguard\\", ".ovpn", "windscribe"],
    "Password managers": ["keepass", ".kdbx", "1password", "bitwarden", "nordpass", "dashlane"],
    "Gaming accounts": ["steam\\ssfn", "\\.minecraft\\", "battle.net", "ubisoft game launcher",
                        "\\ea desktop", "\\epic"],
    "2FA / authenticators": ["\\authy", "winauth", "authenticator", "\\2fa"],
}

# ==============================================================================
# H. BEHAVIORAL CAPABILITY PROFILING
# ==============================================================================
def profile_capabilities(corpus_lc: str) -> Dict[str, Dict[str, Any]]:
    caps: Dict[str, Dict[str, Any]] = {}
    for cap, needles in CAPABILITY_SIGS.items():
        ev = []
        for n in needles:
            m = re.search(n, corpus_lc)
            if m:
                ev.append(m.group(0)[:40])
        if ev:
            # confidence scales with breadth of evidence
            conf = min(0.95, 0.4 + 0.12 * len(ev))
            caps[cap] = {"present": True, "evidence": sorted(set(ev))[:8], "confidence": round(conf, 2)}
    return caps


# ==============================================================================
# G. CREDENTIAL / WALLET TARGET ENUMERATION
# ==============================================================================
def enumerate_targets(corpus_lc: str) -> Dict[str, List[str]]:
    hits: Dict[str, List[str]] = {}
    for cat, needles in CRED_TARGETS.items():
        found = [n for n in needles if n in corpus_lc]
        if found:
            hits[cat] = found
    return hits


# ==============================================================================
# A. FAMILY ATTRIBUTION ENGINE
# ==============================================================================
def attribute_families(corpus_lc: str, corpus_raw: str, iocs: Dict[str, List[str]],
                       caps: Dict[str, Dict], cred_hits: Dict[str, List[str]],
                       is_dotnet: bool, is_electron: bool) -> List[FamilyMatch]:
    present_caps = set(caps.keys())
    present_targets = set(cred_hits.keys())
    results: List[FamilyMatch] = []

    for fam in FAMILY_DB:
        matched: List[str] = []
        conf = 0.0
        name_hit = False

        for s in fam.get("strings", []):
            if s in corpus_lc:
                matched.append(f"string marker: '{s}'")
                # a family-name-ish token is strong; a generic param weaker
                strong = s in {fam["name"].lower()} or s in [a.lower() for a in fam.get("aliases", [])] \
                    or len(s) >= 7
                conf += 0.45 if strong else 0.2
                if strong:
                    name_hit = True

        for pat in fam.get("c2", []):
            if re.search(pat, corpus_raw, re.I):
                matched.append(f"C2 pattern: /{pat}/")
                conf += 0.2

        fam_caps = set(fam.get("caps", []))
        if fam_caps:
            overlap = present_caps & fam_caps
            if overlap:
                ratio = len(overlap) / len(fam_caps)
                conf += 0.25 * ratio
                if ratio >= 0.5:
                    matched.append(f"capability overlap: {sorted(overlap)}")

        fam_tgts = set(fam.get("targets", []))
        if fam_tgts:
            t_overlap = present_targets & fam_tgts
            if t_overlap:
                conf += 0.2 * (len(t_overlap) / len(fam_tgts))
                matched.append(f"targets: {sorted(t_overlap)}")

        if fam.get("dotnet") and is_dotnet:
            conf += 0.1
            matched.append("runtime: .NET/CLR assembly")

        # distinct signal *types* actually matched
        sig_types = sum([
            any(m.startswith("string") for m in matched),
            any(m.startswith("C2") for m in matched),
            any(m.startswith("capability") for m in matched),
            any(m.startswith("targets") for m in matched),
        ])

        conf = min(0.97, conf)
        if name_hit or (conf >= 0.45 and sig_types >= fam.get("min_signals", 2)):
            results.append(FamilyMatch(
                family=fam["name"], category=fam["category"], confidence=round(conf, 2),
                matched_signals=matched, description=fam["desc"],
                distribution=fam.get("distribution", "")))

    # ---- special-case attributions ------------------------------------------
    # Cryptocurrency clipper: clipboard capability + a wallet-address IOC present
    if "Clipboard hijacking (clipper)" in caps and (iocs.get("btc") or iocs.get("eth") or iocs.get("xmr")):
        results.append(FamilyMatch(
            family="Cryptocurrency Clipper (generic)", category="clipper", confidence=0.7,
            matched_signals=["clipboard-monitoring capability", "hardcoded wallet address(es) in binary"],
            description="Clipboard hijacker that swaps copied crypto addresses for the attacker's wallet.",
            distribution="bundled with cracked software / other stealers"))

    # Electron-wrapped stealer: Electron loader + >=2 credential target categories
    if is_electron and len(cred_hits) >= 2:
        already = any(f.family == "LummaC2" for f in results)
        note = " (payload also attributed to a named family above)" if already else ""
        results.append(FamilyMatch(
            family="Electron-wrapped Infostealer (custom loader)", category="infostealer",
            confidence=0.72,
            matched_signals=["Electron/asar packaging", f"references {len(cred_hits)} credential/wallet stores"],
            description="A trojanized/counterfeit Electron desktop app whose bundled JavaScript "
                        "harvests browser and wallet secrets" + note + ".",
            distribution="counterfeit app installers on brand-impersonation domains"))

    # de-dup by family name, keep highest confidence
    best: Dict[str, FamilyMatch] = {}
    for r in results:
        if r.family not in best or r.confidence > best[r.family].confidence:
            best[r.family] = r
    return sorted(best.values(), key=lambda x: x.confidence, reverse=True)


# ==============================================================================
# B. LOADER / PACKER / WRAPPER DETECTION
# ==============================================================================
LOADER_SIGS: Dict[str, Dict[str, Any]] = {
    "Electron": {"markers": ["app.asar", "electron.asar", "node_modules", "chrome_100_percent.pak",
                             "v8_context_snapshot", "electron", "resources\\app"], "min": 2,
                 "note": "Electron/Chromium desktop app - bundled JS can carry the real payload"},
    "NSIS installer": {"markers": ["nullsoft", "nsis", "nsisdl", "; nsis"], "min": 1,
                       "note": "Nullsoft installer - commonly wraps droppers"},
    "Inno Setup": {"markers": ["inno setup", "jr.inno.setup", "innocallback"], "min": 1,
                   "note": "Inno Setup installer"},
    "InstallShield/MSI": {"markers": ["windows installer", "msi.dll", "installshield"], "min": 1,
                          "note": "MSI/InstallShield package"},
    "SFX self-extractor": {"markers": [";!@install@!utf-8!", "winrar sfx", "sfxrar", "7zsfx"], "min": 1,
                           "note": "self-extracting archive carrying a payload"},
    "Themida/WinLicense": {"markers": [".themida", "themida", "winlicense", ".winlice"], "min": 1,
                           "note": "Themida/WinLicense protector (anti-analysis)"},
    "VMProtect": {"markers": [".vmp0", ".vmp1", "vmprotect"], "min": 1,
                  "note": "VMProtect virtualization (anti-analysis)"},
    "Enigma Protector": {"markers": ["enigma", ".enigma"], "min": 1, "note": "Enigma protector"},
    ".NET Reactor": {"markers": [".net reactor", "reactor 6", "eziriz"], "min": 1,
                     "note": ".NET Reactor obfuscator/protector"},
    "ConfuserEx": {"markers": ["confusedby", "confuserex", "confuser.core"], "min": 1,
                   "note": "ConfuserEx .NET obfuscator"},
    "PyInstaller": {"markers": ["pyi-", "pyinstaller", "_meipass", "python3"], "min": 2,
                    "note": "PyInstaller-bundled Python"},
    "AutoIt": {"markers": ["autoit", "au3!", ">>>autoit script<<<"], "min": 1,
               "note": "compiled AutoIt (frequently used by droppers)"},
    "UPX packer": {"markers": ["upx!", "upx0", "upx1"], "min": 2, "note": "UPX packing"},
    "Go binary": {"markers": ["go build id", "go1.", "runtime.gopanic"], "min": 2, "note": "Go-compiled"},
    "Rust binary": {"markers": ["rustc", "cargo\\registry", "core::panicking"], "min": 2, "note": "Rust-compiled"},
}


def detect_loaders(corpus_lc: str, data: bytes) -> Tuple[List[str], List[Signal]]:
    found: List[str] = []
    sigs: List[Signal] = []
    for name, spec in LOADER_SIGS.items():
        hits = [m for m in spec["markers"] if m in corpus_lc]
        if len(hits) >= spec["min"]:
            found.append(name)
            sev = "high" if name in ("Themida/WinLicense", "VMProtect", "SFX self-extractor",
                                     "Electron") else "medium"
            sigs.append(Signal(
                engine="loader", severity=sev, title=f"Packaging/loader: {name}",
                detail=f"{spec['note']} (markers: {hits[:4]})", confidence=0.7,
                evidence=", ".join(hits[:4])))
    # crude high-entropy blob check -> generic packing signal
    if len(data) > 4096:
        ent = shannon_entropy(data)
        if ent > 7.5 and not found:
            sigs.append(Signal(engine="loader", severity="medium",
                               title="High whole-file entropy (packed/encrypted)",
                               detail=f"Shannon entropy {ent:.2f}/8.0 with no recognized packer - custom packer likely.",
                               confidence=0.6, mitre=["T1027.002"]))
    return found, sigs


# ==============================================================================
# C. ELECTRON / ASAR ANALYSIS
# ==============================================================================
def _find_asar_header(blob: bytes) -> Optional[Dict[str, Any]]:
    """Best-effort asar header parse via brace-matching the {"files":...} object."""
    idx = blob.find(b'{"files"')
    if idx == -1:
        return None
    depth, end = 0, None
    limit = min(len(blob), idx + 8_000_000)
    for i in range(idx, limit):
        ch = blob[i]
        if ch == 0x7b:      # {
            depth += 1
        elif ch == 0x7d:    # }
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end is None:
        return None
    try:
        return json.loads(blob[idx:end].decode("utf-8", "ignore"))
    except Exception:
        return None


def _walk_asar(node: Dict[str, Any], prefix: str = "") -> List[str]:
    names: List[str] = []
    for k, v in (node.get("files", node) or {}).items():
        path = f"{prefix}/{k}" if prefix else k
        if isinstance(v, dict) and "files" in v:
            names += _walk_asar(v, path)
        else:
            names.append(path)
    return names


def analyze_electron(data: bytes, corpus_lc: str) -> Tuple[bool, List[Signal], Dict[str, Any]]:
    sigs: List[Signal] = []
    info: Dict[str, Any] = {}
    is_electron = ("app.asar" in corpus_lc or "electron.asar" in corpus_lc
                   or ("electron" in corpus_lc and "node_modules" in corpus_lc)
                   or data[:4] == b"\x04\x22M\x18")
    if not is_electron:
        return False, sigs, info

    sigs.append(Signal(engine="electron", severity="medium",
                       title="Electron application detected",
                       detail="Chromium/Node desktop app. The bundled JavaScript (in app.asar) can "
                              "read local browser profiles and wallet data directly via Node's fs.",
                       confidence=0.6))

    header = _find_asar_header(data)
    if header:
        files = _walk_asar(header)
        info["asar_files"] = files[:200]
        sigs.append(Signal(engine="electron", severity="info",
                           title=f"asar archive parsed - {len(files)} bundled file(s)",
                           detail="Bundled entries: " + ", ".join(files[:12]),
                           confidence=0.4, evidence=", ".join(files[:12])))
        sus = [f for f in files if re.search(r"steal|grab|inject|hook|clip|wallet|cred|token|keylog", f, re.I)]
        if sus:
            sigs.append(Signal(engine="electron", severity="high",
                               title="Suspiciously named files inside asar",
                               detail=f"Bundled JS entries hint at theft: {sus[:8]}",
                               confidence=0.75, evidence=", ".join(sus[:8])))

    # scan readable JS-ish strings within the whole blob for stealer behavior
    js_needles = {
        "fs read of browser profiles": r"(readfilesync|readfile).{0,80}(user data|login data|logins\.json|cookies)",
        "child_process spawn": r"child_process|execsync|spawnsync|require\(['\"]child_process",
        "http exfil from JS": r"(https?://[^\s\"']+).{0,40}(upload|/api/|webhook|bot[0-9])",
        "wallet extension access from JS": r"(nkbihfbeogaeaoehlefnkodbefgpgknn|metamask|phantom)",
    }
    for label, pat in js_needles.items():
        if re.search(pat, corpus_lc):
            sigs.append(Signal(engine="electron", severity="high",
                               title=f"Electron JS behavior: {label}",
                               detail="Bundled JavaScript exhibits data-theft behavior consistent with a trojanized app.",
                               confidence=0.7, mitre=["T1555.003"]))
    return True, sigs, info


# ==============================================================================
# D. .NET / CLR ANALYSIS
# ==============================================================================
def analyze_dotnet(data: bytes, corpus_lc: str) -> Tuple[bool, List[Signal]]:
    sigs: List[Signal] = []
    is_net = is_dotnet_pe(data)
    if not is_net:
        return False, sigs
    sigs.append(Signal(engine="dotnet", severity="info", title=".NET/CLR managed assembly",
                       detail="Managed .NET binary. ~60% of modern commodity stealers/RATs are .NET; "
                              "decompile with ILSpy/dnSpyEx for source-level review.",
                       confidence=0.5))
    obf = {"confusedby": "ConfuserEx", ".net reactor": ".NET Reactor", "eziriz": ".NET Reactor",
           "eazfuscator": "Eazfuscator.NET", "dotfuscator": "Dotfuscator",
           "smartassembly": "SmartAssembly", "babelobfuscator": "Babel", "agile.net": "Agile.NET"}
    for k, v in obf.items():
        if k in corpus_lc:
            sigs.append(Signal(engine="dotnet", severity="medium", title=f".NET obfuscator: {v}",
                               detail="Managed-code obfuscation - common on malicious .NET binaries.",
                               confidence=0.7, mitre=["T1027"]))
    libs = {"leaf.xnet": "Leaf.xNet HTTP library (strong RedLine indicator)",
            "newtonsoft.json": "Newtonsoft.Json (config serialization, common in .NET stealers)",
            "system.net.webclient": "WebClient (download/exfil primitive)",
            "gzipstream": "GZip (embedded/compressed payload handling)"}
    for k, v in libs.items():
        if k in corpus_lc:
            sigs.append(Signal(engine="dotnet", severity="low", title=f".NET library: {v}",
                               detail="Library usage typical of .NET commodity malware.", confidence=0.4))
    return True, sigs

# ==============================================================================
# E. BRAND-IMPERSONATION / TYPOSQUAT DETECTION
# ==============================================================================
# full brand tokens (typo-checked) + short/generic tokens that only fire when
# paired with an action word (avoids false positives like "encode.com")
BRANDS_FULL = {"microsoft", "windows", "office", "office365", "onedrive", "vscode",
               "visualstudio", "github", "google", "chrome", "gmail", "youtube", "discord",
               "telegram", "whatsapp", "signal", "zoom", "steam", "steamcommunity", "epicgames",
               "nvidia", "geforce", "amd", "adobe", "photoshop", "acrobat", "spotify", "netflix",
               "paypal", "coinbase", "binance", "kraken", "metamask", "ledger", "trezor",
               "cloudflare", "dropbox", "notion", "slack", "anydesk", "teamviewer", "wireguard",
               "protonvpn", "nordvpn", "malwarebytes", "kaspersky", "norton", "mcafee", "openai",
               "chatgpt", "anthropic", "claude", "figma", "canva", "roblox", "minecraft"}
BRANDS_PAIRED = {"code": "Visual Studio Code", "teams": "Microsoft Teams", "meet": "Google Meet",
                 "wallet": "crypto wallet", "vault": "password vault", "authenticator": "2FA app"}
OFFICIAL = {"vscode": "code.visualstudio.com", "code": "code.visualstudio.com",
            "github": "github.com", "discord": "discord.com", "telegram": "telegram.org",
            "steam": "steampowered.com", "steamcommunity": "steamcommunity.com",
            "chrome": "google.com", "metamask": "metamask.io", "zoom": "zoom.us",
            "anydesk": "anydesk.com", "teamviewer": "teamviewer.com"}
ACTION_WORDS = {"setup", "install", "installer", "download", "downloads", "get", "update",
                "updater", "secure", "login", "signin", "verify", "account", "official", "free",
                "crack", "cracked", "activator", "keygen", "patch", "portable", "win", "app", "latest"}
SUS_TLD = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".click", ".download",
           ".stream", ".men", ".loan", ".party", ".rest", ".sbs", ".shop", ".live", ".online",
           ".site", ".fun", ".cyou", ".icu", ".life", ".buzz", ".ru", ".su"}


def _host_of(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"^[a-z]+://", "", s)
    s = s.split("/")[0].split("?")[0].split("@")[-1].split(":")[0]
    return s


def detect_brand_impersonation(candidates: List[str]) -> List[Dict[str, str]]:
    seen, out = set(), []
    for cand in candidates:
        host = _host_of(cand)
        if not host or "." not in host or host in seen:
            continue
        seen.add(host)
        tokens = re.split(r"[.\-_]", host)
        tld = "." + host.rsplit(".", 1)[-1]
        reasons = []

        if host.startswith("xn--") or ".xn--" in host or "xn--" in host:
            reasons.append("punycode/homoglyph domain (xn--)")

        # exact official domain? skip brand logic
        is_official = any(host == od or host.endswith("." + od) for od in set(OFFICIAL.values()))

        if not is_official:
            # full-brand token present
            for b in BRANDS_FULL:
                if b in tokens:
                    reasons.append(f"contains brand token '{b}' but is not the official domain")
                    break
            # typosquat: a token within edit-distance 1 of a brand
            for t in tokens:
                if len(t) >= 5:
                    for b in BRANDS_FULL:
                        if abs(len(t) - len(b)) <= 1 and t != b and lev(t, b) == 1:
                            reasons.append(f"typosquat of '{b}' (token '{t}')")
                            break
            # paired short/generic brand token + action word
            has_action = any(t in ACTION_WORDS for t in tokens)
            for t in tokens:
                if t in BRANDS_PAIRED and has_action:
                    reasons.append(f"impersonates {BRANDS_PAIRED[t]} ('{t}' + install/setup keyword)")
                    break

        if tld in SUS_TLD and (reasons or any(t in ACTION_WORDS for t in tokens)):
            reasons.append(f"abused TLD '{tld}'")

        if reasons:
            out.append({"host": host, "reasons": "; ".join(sorted(set(reasons)))})
    return out


# ==============================================================================
# F. C2 PROTOCOL FINGERPRINTING
# ==============================================================================
C2_SIGS: List[Tuple[str, str, str, List[str]]] = [
    (r"api\.telegram\.org/bot[0-9]{6,}:[A-Za-z0-9_\-]{20,}",
     "Telegram Bot API channel (bot token embedded)", "critical", ["T1102.002", "T1567"]),
    (r"api\.telegram\.org/bot", "Telegram Bot API exfil endpoint", "high", ["T1102.002"]),
    (r"(?:discord(?:app)?\.com|discord\.gg)/api/webhooks/",
     "Discord webhook exfiltration", "critical", ["T1567.004"]),
    (r"steamcommunity\.com/profiles/",
     "Steam-profile dead-drop C2 resolver (Vidar/Lumma-style)", "high", ["T1102.001"]),
    (r"(?:pastebin\.com/raw/|gist\.githubusercontent\.com|raw\.githubusercontent\.com)",
     "Paste-site dead-drop config/loader", "high", ["T1102.001", "T1105"]),
    (r"\bt\.me/[A-Za-z0-9_]{4,}", "Telegram channel dead-drop", "medium", ["T1102.001"]),
    (r"/(?:gate|panel|c2|loader|pinger|gate\.php|api/gate|report)\b",
     "Stealer/botnet C2 gate endpoint", "high", ["T1071.001"]),
    (r"\\\\\.\\pipe\\(?:msse-|status_|postex_)",
     "Named-pipe C2 (Cobalt Strike Beacon-style)", "critical", ["T1090"]),
    (r"(?:ipify\.org|api\.ip\.sb|ifconfig\.me|icanhazip\.com|checkip\.amazonaws)",
     "External-IP discovery (victim geolocation/recon)", "medium", ["T1016"]),
    (r"user-agent:\s*(?:mozilla/[0-9. ]+)?\(?(?:tesla|stealer|bot)\)?",
     "Hardcoded stealer/bot User-Agent", "medium", ["T1071.001"]),
]


def fingerprint_c2(corpus_raw: str, iocs: Dict[str, List[str]]) -> List[Dict[str, str]]:
    out = []
    for pat, label, sev, mitre in C2_SIGS:
        m = re.search(pat, corpus_raw, re.I)
        if m:
            out.append({"channel": label, "severity": sev, "match": m.group(0)[:120],
                        "mitre": ",".join(mitre)})
    # raw IP-literal C2 candidates
    for ip in iocs.get("ipv4", [])[:5]:
        out.append({"channel": "hardcoded IP endpoint (candidate C2)", "severity": "medium",
                    "match": ip, "mitre": "T1071"})
    # de-dup by channel label
    ded = {}
    for c in out:
        ded.setdefault(c["channel"], c)
    return list(ded.values())


# ==============================================================================
# I. PERSISTENCE / AUTORUN SCANNER
# ==============================================================================
PERSIST_SIGS: List[Tuple[str, str, str, List[str]]] = [
    (r"currentversion\\run(?:once)?", "Registry Run/RunOnce key", "high", ["T1547.001"]),
    (r"schtasks(?:\.exe)?\s*/create|register-scheduledtask", "Scheduled task creation", "high", ["T1053.005"]),
    (r"\bsc\s+create\b|createservicew?", "Windows service install", "medium", ["T1543.003"]),
    (r"\\start menu\\programs\\startup", "Startup-folder drop", "high", ["T1547.001"]),
    (r"winlogon\\(?:shell|userinit)", "Winlogon Shell/Userinit hijack", "high", ["T1547.004"]),
    (r"image file execution options", "IFEO debugger hijack", "high", ["T1546.012"]),
    (r"__eventfilter|commandlineeventconsumer|activescripteventconsumer",
     "WMI event-subscription persistence", "high", ["T1546.003"]),
    (r"add-mppreference.{0,40}exclusion", "Windows Defender exclusion added", "high", ["T1562.001"]),
    (r"netsh\s+(?:firewall|advfirewall)", "Firewall rule modification", "medium", ["T1562.004"]),
    (r"vssadmin.{0,12}delete|wbadmin.{0,12}delete|bcdedit.{0,20}(?:no|disable)",
     "Backup/recovery tampering (ransomware precursor)", "critical", ["T1490"]),
    (r"\bhkcu\\software\\classes\\.{0,30}\\shell\\open\\command", "COM/shell-open hijack", "high", ["T1546.015"]),
]


def scan_persistence(corpus_lc: str) -> List[Dict[str, str]]:
    out = []
    for pat, label, sev, mitre in PERSIST_SIGS:
        if re.search(pat, corpus_lc):
            out.append({"technique": label, "severity": sev, "mitre": ",".join(mitre)})
    return out


# ==============================================================================
# J. SIGMA-STYLE BEHAVIORAL CORRELATION RULES
# ==============================================================================
def sigma_rules(caps: Dict[str, Dict], cred_hits: Dict[str, List[str]],
                c2: List[Dict], loaders: List[str], persistence: List[Dict],
                is_electron: bool, is_dotnet: bool) -> List[Signal]:
    out: List[Signal] = []
    capset = set(caps.keys())
    c2_present = len(c2) > 0

    def add(sev, title, detail, conf, mitre=None):
        out.append(Signal(engine="sigma", severity=sev, title=title, detail=detail,
                          confidence=conf, mitre=mitre or []))

    if len(cred_hits) >= 3 and c2_present:
        add("critical", "Infostealer chain: multi-store collection + exfil",
            f"References {len(cred_hits)} credential/wallet stores AND has an exfil channel "
            f"({c2[0]['channel']}). Classic infostealer collect-and-exfiltrate behavior.", 0.9,
            ["T1005", "T1567"])
    if "Crypto wallet theft" in capset and "Clipboard hijacking (clipper)" in capset:
        add("high", "Crypto clipper + wallet theft combo",
            "Monitors the clipboard and touches wallet artifacts - swaps addresses and drains wallets.", 0.8,
            ["T1115"])
    if "Remote access / RAT" in capset and persistence:
        add("high", "RAT with persistence",
            "Remote-control capability plus an autorun mechanism - a resident backdoor.", 0.8, ["T1219"])
    if is_electron and len(cred_hits) >= 2:
        add("high", "Electron-wrapped stealer (trojanized desktop app)",
            "An Electron app that reaches into browser/wallet stores - a counterfeit or backdoored "
            "application rather than a legitimate one.", 0.8, ["T1555.003"])
    if "Keylogging" in capset and "Data exfiltration" in capset:
        add("high", "Keylogger with exfil",
            "Captures keystrokes and ships them out - credential/keystroke theft.", 0.75, ["T1056.001"])
    if "Ransomware / destruction" in capset and any(
            "recovery" in p["technique"].lower() or "backup" in p["technique"].lower() for p in persistence):
        add("critical", "Ransomware deployment pattern",
            "Encryption/ransom indicators plus backup/shadow-copy destruction.", 0.9, ["T1486", "T1490"])
    if "Credential dumping (LSASS)" in capset:
        add("critical", "LSASS credential dumping",
            "Targets LSASS memory for OS credential extraction (Mimikatz-class).", 0.85, ["T1003.001"])
    if "Defense evasion (AV tamper)" in capset and c2_present:
        add("high", "AV/EDR tampering before C2",
            "Disables defenses (Defender exclusion / AMSI / ETW) and then calls out.", 0.75, ["T1562.001"])
    return out


# ==============================================================================
# K. FAMILY YARA PACK (used only if yara-python is installed)
# ==============================================================================
FAMILY_YARA = r"""
rule Lumma_Stealer { strings: $a="LummaC2" nocase $b="soft_id=" $c="lid=" condition: $a or ($b and $c) }
rule RedLine_Stealer { strings: $a="RedLine" nocase $b="Leaf.xNet" nocase $c="ScannedWallet" nocase condition: 2 of them }
rule Vidar_Stealer { strings: $a="Vidar" nocase $b="steamcommunity.com/profiles/" condition: all of them }
rule StealC { strings: $a="StealC" nocase $b=/\/[a-z0-9]{6,}\.php/ condition: $a and $b }
rule Raccoon_Stealer { strings: $a="Raccoon" nocase $b="RecordBreaker" nocase condition: any of them }
rule AgentTesla { strings: $a="AgentTesla" nocase $b="api.telegram.org/bot" $c="GetAsyncKeyState" condition: $a or ($b and $c) }
rule Snake_Keylogger { strings: $a="Snake Keylogger" nocase $b="404 Keylogger" nocase condition: any of them }
rule FormBook_XLoader { strings: $a="FormBook" nocase $b="XLoader" nocase condition: any of them }
rule AsyncRAT { strings: $a="AsyncRAT" nocase $b="AsyncClient" nocase condition: any of them }
rule QuasarRAT { strings: $a="Quasar" nocase $b="Quasar.Common" nocase condition: any of them }
rule njRAT { strings: $a="njRAT" nocase $b="njq8" nocase $c="Bladabindi" nocase condition: any of them }
rule DCRat { strings: $a="DCRat" nocase $b="Dark Crystal" nocase condition: any of them }
rule Remcos { strings: $a="Remcos" nocase $b="Breaking-Security" nocase condition: any of them }
rule NanoCore { strings: $a="NanoCore" nocase $b="NanoCore Client" nocase condition: any of them }
rule Warzone_AveMaria { strings: $a="Warzone" nocase $b="Ave_Maria" nocase $c="AveMaria" nocase condition: any of them }
rule CobaltStrike_Beacon { strings: $a="ReflectiveLoader" $b="beacon.dll" nocase $c="%s (admin)" condition: 2 of them }
rule Meterpreter { strings: $a="metsrv" $b="meterpreter" nocase $c="stdapi" condition: 2 of them }
rule LockBit { strings: $a="LockBit" nocase $b="Restore-My-Files" nocase condition: any of them }
rule Conti { strings: $a="conti" nocase $b="CONTI_LOG" condition: any of them }
rule BlackCat_ALPHV { strings: $a="ALPHV" nocase $b="BlackCat" nocase condition: any of them }
rule Amadey { strings: $a="Amadey" nocase condition: $a }
rule Electron_Stealer_Generic { strings: $a="app.asar" $b="Login Data" $c="wallet.dat" nocase condition: $a and ($b or $c) }
rule Crypto_Clipper_Generic { strings: $a="SetClipboardData" $b="AddClipboardFormatListener" $c=/\b(bc1|0x)[a-zA-Z0-9]{20,}/ condition: ($a or $b) and $c }
rule Telegram_Exfil_Generic { strings: $a=/api\.telegram\.org\/bot[0-9]{6,}:[A-Za-z0-9_-]{20,}/ condition: $a }
rule Discord_Webhook_Exfil { strings: $a=/discord(app)?\.com\/api\/webhooks\// condition: $a }
"""


def run_family_yara(data: bytes) -> List[Signal]:
    y = get_yara()
    if y is None:
        return []
    try:
        rules = y.compile(source=FAMILY_YARA)
        matches = rules.match(data=data, timeout=30)
    except Exception:
        return []
    out = []
    for m in matches:
        out.append(Signal(engine="yara-family", severity="high",
                          title=f"YARA family rule: {m.rule}",
                          detail="Attribution rule matched: " + m.rule.replace("_", " "),
                          confidence=0.85))
    return out

# ==============================================================================
# REPUTATION LOOKUPS (file hash + URL). All optional / offline-safe.
# ==============================================================================
def _online() -> bool:
    return requests is not None and not os.environ.get("LAELAPS_OFFLINE")


def rep_urlhaus_url(url: str) -> Dict[str, Any]:
    if not _online():
        return {}
    try:
        headers = {}
        k = os.environ.get("ABUSECH_API_KEY")
        if k:
            headers["Auth-Key"] = k
        r = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url},
                          headers=headers, timeout=15)
        if r.status_code == 200:
            j = r.json()
            if j.get("query_status") == "ok":
                payloads = j.get("payloads") or []
                fams = sorted({p.get("signature") for p in payloads if p.get("signature")})
                return {"found": True, "threat": j.get("threat"), "status": j.get("url_status"),
                        "tags": j.get("tags"), "families": fams,
                        "reference": j.get("urlhaus_reference")}
            return {"found": False}
        if r.status_code in (401, 403):
            return {"error": "URLhaus requires ABUSECH_API_KEY"}
    except Exception as e:
        return {"error": str(e)}
    return {}


def rep_vt_url(url: str) -> Dict[str, Any]:
    key = os.environ.get("VT_API_KEY")
    if not (_online() and key):
        return {}
    try:
        uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{uid}",
                         headers={"x-apikey": key}, timeout=15)
        if r.status_code == 200:
            a = r.json().get("data", {}).get("attributes", {})
            s = a.get("last_analysis_stats", {})
            return {"found": True, "malicious": s.get("malicious", 0),
                    "suspicious": s.get("suspicious", 0),
                    "total": sum(s.values()) if s else 0,
                    "categories": list((a.get("categories") or {}).values())[:5]}
        if r.status_code == 404:
            return {"found": False}
    except Exception as e:
        return {"error": str(e)}
    return {}


def rep_urlscan(host: str) -> Dict[str, Any]:
    if not _online():
        return {}
    try:
        r = requests.get("https://urlscan.io/api/v1/search/",
                         params={"q": f"page.domain:{host}"}, timeout=15)
        if r.status_code == 200:
            res = r.json().get("results", [])
            if res:
                verdicts = [x.get("verdicts", {}).get("overall", {}).get("malicious")
                            for x in res[:10]]
                return {"found": True, "results": len(res),
                        "malicious_hits": sum(1 for v in verdicts if v),
                        "latest": res[0].get("task", {}).get("url")}
            return {"found": False}
    except Exception as e:
        return {"error": str(e)}
    return {}


def rep_hash(sha256: str) -> Dict[str, Any]:
    """Delegate to v1 if present; else do a couple of direct lookups."""
    try:
        return {"virustotal": check_virustotal(sha256),
                "malwarebazaar": check_malwarebazaar(sha256),
                "threatfox": check_threatfox(sha256)}
    except Exception:
        pass
    rep = {}
    if _online():
        try:
            k = os.environ.get("MB_API_KEY", "")
            r = requests.post("https://mb-api.abuse.ch/api/v1/",
                              data={"query": "get_info", "hash": sha256},
                              headers={"Auth-Key": k} if k else {}, timeout=15)
            if r.status_code == 200 and r.json().get("query_status") == "ok":
                s = r.json()["data"][0]
                rep["malwarebazaar"] = {"found": True, "signature": s.get("signature"),
                                        "tags": s.get("tags")}
        except Exception:
            pass
    return rep


# ==============================================================================
# L. URL / LINK SCANNER
# ==============================================================================
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
                  "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "bl.ink", "s.id"}
PAYLOAD_EXT = re.compile(r"\.(exe|scr|msi|bat|cmd|ps1|vbs|vbe|js|jse|jar|hta|apk|iso|img|lnk|"
                         r"dll|com|pif|wsf|zip|rar|7z)(?:$|\?)", re.I)


def scan_url(url: str, deep: bool = False) -> Dict[str, Any]:
    from urllib.parse import urlparse
    signals: List[Signal] = []
    raw = url if "://" in url else "http://" + url
    p = urlparse(raw)
    host = (p.hostname or "").lower()
    netloc = p.netloc.lower()
    path = p.path or ""
    query = p.query or ""

    def add(sev, title, detail, conf=0.6, mitre=None):
        signals.append(Signal(engine="url", severity=sev, title=title, detail=detail,
                              confidence=conf, mitre=mitre or []))

    # ---- structural analysis (no network) -----------------------------------
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        add("high", "IP-literal host", "URL uses a raw IP instead of a domain - common for "
            "throwaway malware hosting.", 0.7, ["T1071"])
    if "xn--" in host:
        add("high", "Punycode/homoglyph host", "Internationalized domain - can visually spoof a brand.",
            0.7)
    if "@" in netloc:
        add("high", "Credentials-in-URL trick", "'@' in the authority hides the true host from a "
            "casual reader (everything before '@' is ignored by the browser).", 0.75)
    if host in URL_SHORTENERS or any(host == s or host.endswith("." + s) for s in URL_SHORTENERS):
        add("medium", "URL shortener", "Destination is hidden behind a shortener - expand before "
            "trusting.", 0.55)
    if host.count(".") >= 4:
        add("low", "Excessive subdomains", "Deeply-nested subdomains often mimic a brand in the "
            "left-most labels.", 0.4)
    m = PAYLOAD_EXT.search(path + ("?" + query if query else ""))
    if m:
        add("high", f"Direct executable/archive download ({m.group(1)})",
            "Link points straight at a runnable/packaged payload.", 0.7, ["T1105", "T1204.002"])
    if re.match(r"^(?:data|javascript):", raw, re.I):
        add("high", "data:/javascript: URI", "Inline-code URI scheme - used for drive-by execution.",
            0.7, ["T1059.007"])
    tld = "." + host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUS_TLD:
        add("medium", f"Abused TLD '{tld}'", "TLD frequently used for malicious infrastructure.", 0.5)
    if len(path) > 8:
        seg = re.sub(r"[^A-Za-z0-9]", "", path)
        if seg and shannon_entropy(seg.encode()) > 4.2 and len(seg) > 16:
            add("low", "High-entropy URL path", "Random-looking path - possible auto-generated "
                "payload/campaign URL.", 0.4)

    # brand impersonation on the host
    brand = detect_brand_impersonation([host])
    for b in brand:
        add("high", "Brand-impersonation domain",
            f"{b['host']}: {b['reasons']}", 0.75, ["T1656"])

    # correlation: brand-impersonation host serving a direct payload = fake-installer delivery
    if brand and m:
        add("critical", "Fake software-installer delivery pattern",
            "A brand-impersonation host serving a direct executable/archive is the classic "
            "counterfeit-installer / malvertising pattern (fake app that drops a stealer/RAT).",
            0.8, ["T1204.002", "T1656"])

    # ---- reputation (network) -----------------------------------------------
    reputation = {}
    if _online():
        reputation["urlhaus"] = rep_urlhaus_url(raw)
        reputation["virustotal"] = rep_vt_url(raw)
        reputation["urlscan"] = rep_urlscan(host)
        uh = reputation.get("urlhaus", {})
        if uh.get("found"):
            fams = uh.get("families") or []
            add("critical", "URLhaus: known malware-distribution URL",
                f"threat={uh.get('threat')}, status={uh.get('status')}, "
                f"payload families={fams or 'n/a'}, tags={uh.get('tags')}", 0.95, ["T1105"])
        vt = reputation.get("virustotal", {})
        if vt.get("found") and vt.get("malicious", 0) > 0:
            add("high" if vt["malicious"] < 5 else "critical", "VirusTotal URL detections",
                f"{vt['malicious']}/{vt.get('total', 0)} engines flag this URL.", 0.85)
        us = reputation.get("urlscan", {})
        if us.get("found") and us.get("malicious_hits", 0) > 0:
            add("medium", "urlscan.io prior malicious scans",
                f"{us['malicious_hits']} malicious verdict(s) in scan history for {host}.", 0.6)
    else:
        signals.append(Signal(engine="url", severity="info", title="Offline - reputation skipped",
                              detail="Set keys / unset LAELAPS_OFFLINE for URLhaus/VT/urlscan lookups.",
                              confidence=0.2))

    # ---- deep mode: download + full file analysis ---------------------------
    deep_report = None
    if deep and _online():
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix="__url_payload") as tf:
                rr = requests.get(raw, stream=True, timeout=60, allow_redirects=True,
                                  headers={"User-Agent": "laelaps/2.0"})
                for chunk in rr.iter_content(65536):
                    tf.write(chunk)
                tf_path = tf.name
            deep_report = analyze_file_v2(tf_path, use_llm=False)
        except Exception as e:
            signals.append(Signal(engine="url", severity="info", title="Deep fetch failed",
                                  detail=str(e), confidence=0.2))
        finally:
            try:
                os.unlink(tf_path)
            except Exception:
                pass

    score, verdict = score_signals(signals,
                                   bonus=40 if any(s.severity == "critical" for s in signals) else 0)
    return {"url": raw, "host": host, "verdict": verdict, "score": score,
            "signals": [asdict(s) for s in sorted(signals, key=lambda x: SEV_RANK[x.severity])],
            "reputation": reputation, "deep_analysis": deep_report.to_dict() if deep_report else None}


# ==============================================================================
# SCORING
# ==============================================================================
def _verdict_for(score: float) -> str:
    if score >= 60:
        return "malicious"
    if score >= 28:
        return "suspicious"
    if score >= 8:
        return "unknown"
    return "clean"


def score_signals(signals: List[Signal], bonus: float = 0.0) -> Tuple[float, str]:
    raw = sum(SEV_WEIGHT.get(s.severity, 0) * s.confidence for s in signals) + bonus
    score = round(min(100.0, raw), 1)
    return score, _verdict_for(score)


def looks_like_analysis_content(corpus_lc: str, filetype: str, data: bytes) -> Tuple[bool, str]:
    """Distinguish a file that *describes/detects* malware (this tool, a threat report, a
    detection ruleset) from operational malware. Signature scanners cannot tell 'uses these
    paths' from 'lists these paths'; this dampens the former. Gated OFF for compiled binaries
    and archives (a real PE/.NET/APK payload is judged on its merits)."""
    ft = filetype.lower()
    if any(k in ft for k in ("pe (", ".net", "elf", "mach-o", "dex", "ole")):
        return False, ""
    if any(k in ft for k in ("zip", "ooxml", "apk", "jar", "rar", "7-zip", "asar", "gzip")):
        return False, ""
    reasons: List[str] = []
    yara_rules = bool(re.search(r"\brule\s+\w+\s*\{", corpus_lc)) and "condition:" in corpus_lc
    if yara_rules:
        reasons.append("contains YARA rule definitions")
    mitre_ids = len(set(re.findall(r"t1\d{3}", corpus_lc)))
    if mitre_ids >= 5:
        reasons.append(f"{mitre_ids} distinct MITRE ATT&CK IDs tabulated")
    vocab = sum(1 for w in ("detection", "signature", "threat intel", "threat-intel",
                            "malware analys", "false positive", "indicator of compromise",
                            "att&ck", "yara", "sigma", "defensive")
                if w in corpus_lc)
    if vocab >= 3:
        reasons.append("dense threat-intel / detection vocabulary")
    # strong = a ruleset (YARA) OR a threat-intel writeup (many technique IDs + vocab).
    # Ordinary malicious scripts (.ps1/.js/.py stealers) have none of these.
    strong = yara_rules or (mitre_ids >= 5 and vocab >= 3)
    return (strong, "; ".join(reasons)) if strong else (False, "")

# ==============================================================================
# M. THREAT-REPORT GENERATOR (analyst-grade Markdown)
# ==============================================================================
def _humanize_caps(caps: Dict[str, Dict]) -> str:
    order = ["Browser credential theft", "Cookie / session theft", "Crypto wallet theft",
             "Keylogging", "Clipboard hijacking (clipper)", "Screen capture",
             "Remote access / RAT", "Data exfiltration"]
    present = [c for c in order if c in caps] + [c for c in caps if c not in order]
    phrases = {
        "Browser credential theft": "steals saved browser credentials",
        "Cookie / session theft": "harvests cookies and session tokens",
        "Crypto wallet theft": "steals cryptocurrency wallet data",
        "Keylogging": "logs keystrokes", "Screen capture": "captures the screen",
        "Clipboard hijacking (clipper)": "hijacks the clipboard",
        "Remote access / RAT": "gives the attacker hands-on remote access",
        "Data exfiltration": "exfiltrates the collected data",
    }
    return ", ".join(phrases.get(c, c.lower()) for c in present[:6])


def build_one_liner(fam: List[FamilyMatch], caps: Dict, loaders: List[str],
                    brand: List[Dict], c2: List[Dict]) -> str:
    named = next((f for f in fam if f.category in ("infostealer", "rat", "ransomware", "keylogger",
                                                   "banker", "clipper", "framework")), None)
    lead = named.family if named else (fam[0].family if fam else "Unclassified malware")
    wrap = ""
    if "Electron" in loaders:
        wrap = " wrapped in a custom Electron loader"
    elif loaders:
        wrap = f" packaged with {loaders[0]}"
    behav = _humanize_caps(caps)
    exfil = ""
    ch = [c["channel"] for c in c2 if "exfil" in c["channel"].lower() or "webhook" in c["channel"].lower()
          or "telegram" in c["channel"].lower() or "dead-drop" in c["channel"].lower()]
    if ch:
        exfil = f", exfiltrating via {ch[0].lower()}"
    dist = ""
    if brand:
        hosts = ", ".join(b["host"] for b in brand[:2])
        dist = f"; distributed through brand-impersonation domain(s) such as {hosts}"
    elif named and named.distribution:
        dist = f"; typically distributed via {named.distribution}"
    return f"The payload is **{lead}**{wrap}. It {behav}{exfil}{dist}."


def generate_report(r: "V2Report") -> str:
    L = []
    L.append(f"# Threat Analysis Report - {r.filename}")
    L.append(f"*Generated {r.timestamp} · Laelaps static + attribution engine*\n")
    badge = {"malicious": "🔴 MALICIOUS", "suspicious": "🟡 SUSPICIOUS",
             "clean": "🟢 CLEAN", "unknown": "🔵 UNKNOWN"}[r.verdict]
    L.append(f"## Verdict: {badge}  ·  Threat score {r.score}/100\n")
    if r.reference_only:
        L.append("> ⚠️ **Reference content, not operational malware.** This file reads as detection "
                 "rules / threat-intel / analysis code. The families and indicators below are "
                 "*referenced* (string literals / YARA rules), not executed; the score has been "
                 "dampened accordingly. If you expected an actual malware sample here, treat this as a "
                 "red flag and inspect manually.\n")
    else:
        L.append("> " + build_one_liner(r.families, r.capabilities, r.loaders,
                                         r.brand_impersonation, r.c2) + "\n")

    L.append("## 1. File Identification")
    L.append(f"- **File:** `{r.filename}`  ({r.size_bytes:,} bytes)")
    L.append(f"- **Type:** {r.filetype}")
    L.append(f"- **SHA-256:** `{r.hashes.get('sha256','?')}`")
    L.append(f"- **MD5:** `{r.hashes.get('md5','?')}`")
    if r.loaders:
        L.append(f"- **Packaging / loader:** {', '.join(r.loaders)}")
    L.append("")

    L.append("## 2. Classification & Attribution")
    if r.families:
        L.append("| Family | Category | Confidence | Basis |")
        L.append("|---|---|---|---|")
        for f in r.families[:8]:
            basis = "; ".join(f.matched_signals[:3])
            L.append(f"| **{f.family}** | {f.category} | {int(f.confidence*100)}% | {basis} |")
        L.append("")
        top = r.families[0]
        L.append(f"**Lead attribution - {top.family}:** {top.description}")
        if top.distribution:
            L.append(f"\n*Distribution:* {top.distribution}")
    else:
        L.append("No known family matched with sufficient confidence. Behavior-based verdict only.")
    L.append("")

    L.append("## 3. Capabilities Observed")
    if r.capabilities:
        L.append("| Capability | Confidence | Evidence |")
        L.append("|---|---|---|")
        for cap, meta in sorted(r.capabilities.items(), key=lambda kv: -kv[1]["confidence"]):
            ev = ", ".join(meta["evidence"][:4])
            L.append(f"| {cap} | {int(meta['confidence']*100)}% | `{ev}` |")
    else:
        L.append("No high-level capabilities inferred from static content.")
    L.append("")

    if r.targeted_assets:
        L.append("## 4. Targeted Assets (secrets the sample references)")
        for cat, items in r.targeted_assets.items():
            L.append(f"- **{cat}:** {', '.join(items[:8])}")
        L.append("")

    if r.c2:
        L.append("## 5. Command-and-Control / Exfiltration Infrastructure")
        L.append("| Channel | Severity | Indicator |")
        L.append("|---|---|---|")
        for c in r.c2:
            L.append(f"| {c['channel']} | {c['severity']} | `{c['match']}` |")
        L.append("")

    if r.brand_impersonation:
        L.append("## 6. Distribution - Brand-Impersonation Domains")
        for b in r.brand_impersonation:
            L.append(f"- **{b['host']}** - {b['reasons']}")
        L.append("")

    if r.persistence:
        L.append("## 7. Persistence & Autorun")
        for p in r.persistence:
            L.append(f"- {p['technique']}  *(MITRE {p['mitre']})*")
        L.append("")

    if r.iocs:
        L.append("## 8. Extracted IOCs")
        for k, vals in r.iocs.items():
            if vals:
                L.append(f"- **{k}** ({len(vals)}): " + ", ".join(f"`{v}`" for v in vals[:8]))
        L.append("")

    if r.mitre:
        L.append("## 9. MITRE ATT&CK Techniques")
        L.append(", ".join(f"`{t}`" for t in r.mitre))
        L.append("")

    L.append("## 10. Threat-Intel Reputation")
    if r.reputation:
        for src, res in r.reputation.items():
            if isinstance(res, dict) and res.get("found"):
                L.append(f"- **{src}:** KNOWN - {json.dumps({k: v for k, v in res.items() if k != 'found'})}")
            elif isinstance(res, dict) and res.get("found") is False:
                L.append(f"- **{src}:** not found (first-seen / private)")
            elif isinstance(res, dict) and res.get("error"):
                L.append(f"- **{src}:** {res['error']}")
    else:
        L.append("- Not run (offline mode or no API keys). Set `VT_API_KEY` / `MB_API_KEY` / "
                 "`ABUSECH_API_KEY` and unset `LAELAPS_OFFLINE` for VirusTotal / MalwareBazaar / "
                 "ThreatFox hash reputation.")
    L.append("")

    L.append("## 11. Recommended Actions")
    if r.verdict in ("malicious", "suspicious"):
        L.append("- **Contain:** isolate the host; block the C2/exfil indicators above at proxy/DNS/firewall.")
        L.append("- **Rotate:** treat all browser-stored passwords, session cookies, wallet seeds and "
                 "2FA seeds on the host as compromised - force password resets and re-issue MFA.")
        L.append("- **Hunt:** sweep for the persistence entries and IOCs across the fleet.")
        L.append("- **Confirm dynamically:** detonate in a sandbox (CAPE / ANY.RUN) for live C2 + behavior.")
    else:
        L.append("- No malicious indicators; monitor as usual. Re-scan if provenance is uncertain.")
    L.append("")
    L.append("## 12. Caveats")
    L.append("- Static + reputation analysis only - no dynamic execution, memory or network behavior.")
    L.append("- Family attribution is confidence-weighted from public signatures; corroborate a "
             "high-impact verdict with a second source (VT/sandbox) before acting.")
    L.append("- Absence of a signal is not proof of safety (packing/obfuscation can hide behavior).")
    if r.notes:
        L.append("\n*Engine notes:* " + "; ".join(r.notes))
    return "\n".join(L)


# ==============================================================================
# ORCHESTRATOR
# ==============================================================================
def analyze_file_v2(filepath: str, use_llm: bool = True, yara_rules_dir: Optional[str] = None, recursive_depth: int = 1) -> V2Report:
    start = time.time()
    filepath = os.path.abspath(filepath)
    data = read_bytes(filepath)
    strings = v2_extract_strings(data)
    corpus_raw = "\n".join(strings)
    corpus_lc = corpus_raw.lower()
    iocs = v2_extract_iocs(strings)

    rep = V2Report(filepath=filepath, filename=os.path.basename(filepath), size_bytes=len(data),
                   filetype=v2_detect_filetype(data, filepath), hashes=v2_compute_hashes(data),
                   verdict="unknown", score=0.0,
                   timestamp=datetime.now(timezone.utc).isoformat())
    if not data:
        rep.notes.append("file is empty")
        return rep

    signals: List[Signal] = []

    # engines
    loaders, loader_sigs = detect_loaders(corpus_lc, data)
    signals += loader_sigs
    rep.loaders = loaders

    is_electron, elc_sigs, elc_info = analyze_electron(data, corpus_lc)
    signals += elc_sigs

    is_dotnet, net_sigs = analyze_dotnet(data, corpus_lc)
    signals += net_sigs

    caps = profile_capabilities(corpus_lc)
    rep.capabilities = caps

    cred_hits = enumerate_targets(corpus_lc)
    rep.targeted_assets = cred_hits
    if len(cred_hits) >= 3:
        signals.append(Signal(engine="targets", severity="high",
                              title=f"References {len(cred_hits)} distinct credential/wallet stores",
                              detail="Touching many secret stores at once is a hallmark of infostealers: "
                                     + ", ".join(cred_hits.keys()), confidence=0.8,
                              mitre=["T1555", "T1005"]))

    c2 = fingerprint_c2(corpus_raw, iocs)
    rep.c2 = c2
    for c in c2:
        signals.append(Signal(engine="c2", severity=c["severity"], title=f"C2/exfil: {c['channel']}",
                              detail=f"Indicator: {c['match']}", confidence=0.7,
                              mitre=c["mitre"].split(",") if c["mitre"] else []))

    brand = detect_brand_impersonation(iocs.get("domains", []) + iocs.get("urls", []))
    rep.brand_impersonation = brand
    for b in brand:
        signals.append(Signal(engine="brand", severity="high", title="Brand-impersonation domain",
                              detail=f"{b['host']} - {b['reasons']}", confidence=0.7, mitre=["T1656"]))

    persistence = scan_persistence(corpus_lc)
    rep.persistence = persistence
    for p in persistence:
        signals.append(Signal(engine="persist", severity=p["severity"],
                              title=f"Persistence: {p['technique']}", detail=f"MITRE {p['mitre']}",
                              confidence=0.65, mitre=p["mitre"].split(",")))

    signals += sigma_rules(caps, cred_hits, c2, loaders, persistence, is_electron, is_dotnet)
    signals += run_family_yara(data)

    families = attribute_families(corpus_lc, corpus_raw, iocs, caps, cred_hits, is_dotnet, is_electron)
    rep.families = families
    for f in families[:6]:
        sev = "critical" if f.confidence >= 0.8 else "high"
        signals.append(Signal(engine="attribution", severity=sev,
                              title=f"Family attribution: {f.family} ({int(f.confidence*100)}%)",
                              detail=f.description, confidence=f.confidence))

    # fold in the deep-static engine (PE/ELF/Office/PDF/script/archive/steg/YARA/reputation)
    try:
        deep = analyze_file(filepath, yara_rules_dir=yara_rules_dir,
                            recursive_depth=recursive_depth)
        rep.notes.append(f"deep-static engine: {deep.verdict} ({deep.score:.0f}/100), "
                         f"{len(deep.indicators)} indicators")
        for ind in deep.indicators:
            if ind.severity in ("critical", "high"):
                signals.append(Signal(engine="deep:" + ind.layer, severity=ind.severity,
                                      title=ind.title, detail=ind.detail[:300],
                                      confidence=ind.confidence, mitre=ind.mitre_attack))
        for k, v in (deep.reputation or {}).items():
            rep.reputation[k] = v
    except Exception as e:
        rep.notes.append(f"deep-static engine error: {e}")

    # hash reputation (v2 path)
    if not rep.reputation and _online():
        rep.reputation = rep_hash(rep.hashes["sha256"])

    # finalize
    rep.iocs = iocs
    rep.signals = sorted(signals, key=lambda s: (SEV_RANK[s.severity], -s.confidence))
    rep.mitre = sorted({t for s in signals for t in s.mitre if t})
    # attribution bonus: a confident named family should push the score up
    bonus = 0.0
    if families and families[0].confidence >= 0.7:
        bonus += 25
    rep.score, rep.verdict = score_signals(signals, bonus=bonus)

    # reference-vs-operational triage: dampen files that *describe/detect* malware
    # (detection rulesets, threat reports, this tool itself) rather than *being* malware.
    ref_only, ref_reasons = looks_like_analysis_content(corpus_lc, rep.filetype, data)
    if ref_only:
        rep.reference_only = True
        rep.notes.append("triaged as security-analysis/detection content - score dampened")
        rep.signals.insert(0, Signal(
            engine="triage", severity="info",
            title="Reference content, not operational malware (score dampened)",
            detail="This file reads as detection rules / threat-intel / analysis code (" +
                   ref_reasons + "). The indicators below are REFERENCED (string literals / YARA "
                   "rules), not executed. A signature scanner cannot fully separate a sample from a "
                   "writeup about it - verify manually before trusting this dampening.",
            confidence=0.5))
        rep.score = min(rep.score, 22.0)
        rep.verdict = _verdict_for(rep.score)

    # optional LLM enrichment (only if v1 provides it and a key is set)
    if use_llm and not os.environ.get("LAELAPS_OFFLINE"):
        try:
            fake = Verdict(filepath=rep.filepath, filename=rep.filename, size_bytes=rep.size_bytes,
                              filetype=rep.filetype, hashes=rep.hashes, verdict=rep.verdict,
                              score=rep.score,
                              indicators=[Indicator(layer=s.engine, category="malicious",
                                                       severity=s.severity, title=s.title,
                                                       detail=s.detail, confidence=s.confidence,
                                                       mitre_attack=s.mitre) for s in rep.signals[:20]],
                              families=[f.family for f in families],
                              mitre_techniques=rep.mitre, reputation=rep.reputation)
            rep.llm_summary = llm_verdict(fake)
        except Exception:
            pass

    rep.report_md = generate_report(rep)
    rep.analysis_time_seconds = round(time.time() - start, 2)
    return rep


# ==============================================================================
# TERMINAL RENDERING + CLI
# ==============================================================================
def render_terminal(rep: V2Report) -> None:
    print(rep.report_md)
    if rep.llm_summary:
        print("\n" + "=" * 78 + "\nAI ANALYST SUMMARY\n" + "=" * 78)
        print(rep.llm_summary)
    print(f"\n[analysis completed in {rep.analysis_time_seconds}s · "
          f"{len(rep.signals)} signals · engine coverage: attribution, loader, electron, "
          f"dotnet, c2, brand, targets, persistence, sigma, "
          f"yara={'on' if get_yara() else 'off (pip install yara-python)'}]")


def render_url(res: Dict[str, Any]) -> None:
    badge = {"malicious": "🔴 MALICIOUS", "suspicious": "🟡 SUSPICIOUS",
             "clean": "🟢 LIKELY CLEAN", "unknown": "🔵 UNCERTAIN"}[res["verdict"]]
    print(f"# URL Scan - {res['url']}")
    print(f"## Verdict: {badge}  ·  score {res['score']}/100  ·  host `{res['host']}`\n")
    if res["signals"]:
        print("| Severity | Finding | Detail |")
        print("|---|---|---|")
        for s in res["signals"]:
            print(f"| {s['severity']} | {s['title']} | {s['detail'][:90]} |")
    rep = res.get("reputation") or {}
    shown = {k: v for k, v in rep.items() if v}
    if shown:
        print("\n### Reputation")
        for k, v in shown.items():
            print(f"- **{k}:** {json.dumps(v)}")
    if res.get("deep_analysis"):
        d = res["deep_analysis"]
        print(f"\n### Deep payload analysis\nDownloaded payload verdict: "
              f"**{d['verdict']}** ({d['score']}/100). Families: "
              f"{[f['family'] for f in d.get('families', [])]}")
    print("\n*URL structure analysis is heuristic; a 'clean' structural result does not guarantee "
          "safety. Enable network reputation (URLhaus/VT/urlscan) and use --deep in a sandbox to confirm.*")


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="laelaps",
        description="Laelaps - one-stop malware detection, attribution & threat-intel engine (defensive).",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("target", nargs="?", help="file path OR md5/sha1/sha256 hash")
    ap.add_argument("--url", help="scan a link (structure + reputation)")
    ap.add_argument("--deep", action="store_true",
                    help="with --url: download and analyze the payload (sandbox only!)")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--report", action="store_true", help="print only the Markdown threat report")
    ap.add_argument("--offline", action="store_true", help="skip all network lookups")
    ap.add_argument("--no-llm", action="store_true", help="skip the optional LLM summary")
    ap.add_argument("--yara-rules", help="directory of extra YARA rules for the deep engine")
    ap.add_argument("--recursive", type=int, default=1,
                    help="archive recursion depth for the deep engine (default 1)")
    ap.add_argument("--api", action="store_true", help="launch the REST API server instead of scanning")
    ap.add_argument("--api-host", default="127.0.0.1")
    ap.add_argument("--api-port", type=int, default=8765)
    ap.add_argument("--ui", action="store_true", help="launch the Streamlit web UI")
    args = ap.parse_args()

    # Streamlit self-invocation (launch_streamlit re-execs us with this set)
    if os.environ.get("LAELAPS_UI_MODE"):
        streamlit_app()
        return 0

    if args.offline:
        os.environ["LAELAPS_OFFLINE"] = "1"
    if args.no_llm:
        os.environ.pop("ANTHROPIC_API_KEY", None)
        os.environ.pop("OPENAI_API_KEY", None)

    if args.api:
        launch_api(args.api_host, args.api_port)
        return 0

    if args.ui:
        print("Launching Laelaps web UI...")
        launch_streamlit()
        return 0

    if args.url:
        res = scan_url(args.url, deep=args.deep)
        if args.json:
            print(json.dumps(res, indent=2, default=str))
        else:
            render_url(res)
        return 0 if res["verdict"] in ("clean", "unknown") else 1

    if not args.target:
        ap.print_help()
        return 0

    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", args.target):
        print(json.dumps(rep_hash(args.target), indent=2, default=str))
        return 0

    if not os.path.isfile(args.target):
        print(f"error: '{args.target}' is not a file or a valid hash", file=sys.stderr)
        return 2

    rep = analyze_file_v2(args.target, use_llm=not args.no_llm,
                          yara_rules_dir=args.yara_rules, recursive_depth=args.recursive)
    if args.json:
        print(json.dumps(rep.to_dict(), indent=2, default=str))
    elif args.report:
        print(rep.report_md)
    else:
        render_terminal(rep)
    return {"malicious": 1, "suspicious": 1, "unknown": 0, "clean": 0}[rep.verdict]


if __name__ == "__main__":
    sys.exit(main())
