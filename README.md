# 🐕 Laelaps - One-Stop Malware Detection, Attribution & Threat-Intel Engine

> *Laelaps: the hound of Greek myth fated to always catch what it hunts.*

A single-file, **defensive** malware analyzer. Point it at a **file**, a **URL**, or a
**hash** and it fuses a deep static-analysis engine with a threat-intel attribution
engine to tell you:

- **What** it is - infostealer, RAT, loader, ransomware, banker, clipper, keylogger
- **Which** known family - LummaC2, RedLine, Vidar, StealC, AsyncRAT, Remcos, Cobalt Strike, LockBit, …
- **What** it steals and **how** it exfiltrates - browser creds, cookies, wallets, 2FA; Telegram/Discord/dead-drop C2
- **How** it's distributed - brand-impersonation domains, fake installers, loaders

…then writes an **analyst-grade threat report**. It only inspects and reports - it
performs no malicious action. Same category as YARA, `oletools`, VirusTotal tooling,
or a SOC triage script.

```
> The payload is LummaC2 wrapped in a custom Electron loader. It steals saved
> browser credentials, harvests cookies and session tokens, steals cryptocurrency
> wallet data, and exfiltrates via a Telegram Bot API channel; distributed through
> brand-impersonation domains such as setup-code.com and code-setup.com.
```

## Quick start

```bash
python laelaps.py suspicious.exe               # full analysis + threat report
python laelaps.py suspicious.exe --report      # just the Markdown report
python laelaps.py suspicious.exe --json        # machine-readable
python laelaps.py --url https://setup-code.com/VSCode-Setup.exe   # scan a link
python laelaps.py --url https://x.tld/p.exe --deep                # download + analyze (sandbox!)
python laelaps.py <md5|sha1|sha256>            # reputation-only hash lookup
python laelaps.py ./FitGirl-Repack/            # scan a whole download folder (see below)
python laelaps.py huge-game-data.bin           # oversized file: fast head+tail sampled scan
python laelaps.py <target> --offline           # never touch the network
python laelaps.py sample.exe --attack-layer layer.json  # + write a MITRE ATT&CK Navigator layer
python laelaps.py --api                        # REST API server (OpenAPI docs at /docs)
python laelaps.py --ui                         # Streamlit web UI
```

Exit code is non-zero for `malicious`/`suspicious` verdicts (CI/pipeline friendly).

## Scan a whole download before you install it

Large downloads - a hundreds-of-GB game repack from a torrent, a bundle of installers -
are exactly where a trojaned `setup.exe`, a fake crack, or a dropper hides. Laelaps scans
the whole thing **before it hits your system**, without reading every byte:

```bash
python laelaps.py ./Some.Game.Repack/                     # scan the folder
python laelaps.py ./Some.Game.Repack/ --json              # machine-readable summary
python laelaps.py ./Some.Game.Repack/ --stop-on-malicious # fast go/no-go
python laelaps.py big-game-data.bin --full-hash           # sampled scan + a real SHA-256
```

How it stays fast on huge inputs:

- **Risky files first.** Executables, scripts and installers (`.exe`, `.dll`, `.msi`,
  `.bat`, `.ps1`, `.lnk`, ...) are analyzed in full and scanned before anything else, so a
  bad verdict surfaces early.
- **Huge blobs are sampled, not read whole.** Any file at/above `--max-scan-size`
  (default 64 MB) is scanned by reading only its first 8 MB + last 2 MB - enough to catch a
  trojaned installer, an appended-executable overlay, or dropper strings, without ever
  loading a 500 GB blob into memory.
- **Parallel.** Files are scanned concurrently (`--workers`, default auto).
- **One verdict, named offender.** The tree collapses to a single verdict plus a table of
  the flagged files (which one, what family, why), so you know exactly what not to run.

Flags: `--max-scan-size MB`, `--workers N`, `--max-files N`, `--stop-on-malicious`,
`--full-hash`. Directory scans run static-only (offline) per file for speed; re-scan a
single flagged file on its own for network reputation.

> Static analysis is not a guarantee: a clean result means nothing obviously malicious was
> found in the executable/script surface, and compressed game data is sampled, not fully
> parsed. Treat a flagged installer as unsafe and confirm in a sandbox.

## Detection layers

Laelaps runs **two engines in one namespace** over every sample.

### Deep static engine (file-format aware)

| # | Layer | What it catches |
|---|-------|-----------------|
| 1 | Multi-hash + reputation | MD5/SHA1/SHA256/SHA512, TLSH, ssdeep, imphash → VirusTotal · MalwareBazaar · ThreatFox |
| 2 | YARA | Built-in pack (injection, hollowing, ransom notes, Mimikatz, Log4Shell, Follina, Cobalt Strike, Meterpreter, …) + custom rules dir |
| 3 | Format parsing | PE, ELF, Mach-O, PDF, Office/OLE, DEX/APK, scripts, LNK shortcuts |
| 4 | Entropy & packers | Whole-file + sliding-window entropy, packer-section names, W+X sections |
| 5 | IOC extraction | URLs, IPs, domains, BTC/ETH/XMR wallets, `.onion`, mutexes, base64 blobs, encoded PowerShell, shellcode |
| 6 | API heuristics | Injection trio (`VirtualAllocEx`+`WriteProcessMemory`+`CreateRemoteThread`), process hollowing, keylogger APIs |
| 7 | Macro / script | VBA + XLM 4.0 macros, PDF JavaScript/Launch, PowerShell decode (base64/`-enc`), VBS/JS/Bash/Batch |
| 8 | Archives | Recursive expansion, Zip Slip, zip-bomb, password-protected refusal |
| 9 | Steganography | Trailing data after JPEG/PNG end markers, LSB stats |
| 10 | CVE / exploit strings | Log4Shell, Follina (MSDT), EternalBlue (MS17-010), PrintNightmare, Equation Editor, JBIG2 |
| 11 | MITRE ATT&CK | Every indicator carries technique IDs, aggregated per report; export a Navigator layer with `--attack-layer FILE` |
| 12 | LLM verdict | Optional senior-analyst summary (Claude / GPT) |

### Attribution & threat-intel engine

| Layer | What it does |
|-------|--------------|
| Family attribution | Confidence-weighted signatures for ~30 families + generic clipper / Electron-stealer heuristics |
| Loader / packer / wrapper | Electron, NSIS, Inno, MSI, SFX, Themida, VMProtect, .NET Reactor, ConfuserEx, PyInstaller, AutoIt, UPX, Go, Rust |
| Electron / ASAR | Detects Electron, parses `app.asar`, flags theft behavior in bundled JS |
| .NET / CLR | Managed-assembly + obfuscator + malicious-library detection |
| Brand-impersonation | Homoglyph/punycode, token, and Levenshtein checks (`setup-code.com` → fake VS Code) |
| C2 fingerprinting | Telegram bot (token-embedded), Discord webhook, Steam/paste dead-drops, `gate.php`, Cobalt Strike named pipes |
| Credential/wallet targets | Which browser, wallet, messaging, VPN, password-manager, gaming, and 2FA stores the sample references |
| Capability profiling | 17 buckets: browser theft, cookie/session, wallet, clipper, keylog, screen, RAT, exec, persistence, evasion, AV-tamper, exfil, recon, loader, ransomware, LSASS, privesc |
| Persistence scanner | Run keys, scheduled tasks, services, startup, Winlogon, IFEO, WMI, Defender-exclusion, firewall, backup tampering |
| Sigma-style correlation | Multi-signal chains (collect+exfil, clipper+wallet, RAT+persistence, keylog+exfil, ransomware, LSASS, AV-tamper→C2) |
| Family YARA pack | 25 attribution rules (used if `yara-python` is installed) |
| URL scanner | Structure heuristics + URLhaus / VirusTotal / urlscan reputation, optional `--deep` download-and-analyze |
| Threat-report generator | Verdict, one-line brief, attribution table, capability matrix, targeted assets, C2 infra, distribution, persistence, IOCs, ATT&CK, actions, caveats |

## Install

Laelaps runs with the standard library + `requests` alone, and **degrades gracefully**
when optional analyzers are missing (it will attempt to auto-install them on first use).
For full coverage:

```bash
pip install -r requirements.txt --break-system-packages
# or the essentials:
pip install pefile yara-python python-tlsh oletools requests --break-system-packages
```

Optional API keys (all optional, more = better coverage):

| Env var | Enables |
|---------|---------|
| `VT_API_KEY` | VirusTotal (70+ AV engines) |
| `MB_API_KEY` / `ABUSECH_API_KEY` | MalwareBazaar / URLhaus |
| `URLSCAN_API_KEY` | urlscan.io URL reputation |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | LLM verdict summary |
| `LAELAPS_YARA_RULES_DIR` | Extra YARA ruleset directory |
| `LAELAPS_OFFLINE=1` | Disable **all** network calls (air-gapped) |

## Verdict scale

`clean` (<8) · `unknown` (8-27) · `suspicious` (28-59) · `malicious` (≥60) - score 0-100.

## Tests

All tests are hermetic and fully offline. Every sample is **inert** - EICAR-style
recognition tokens with no working payload, entrypoint, or live infrastructure.

```bash
python3 tests/smoke_test.py     # 34 checks: one sample per detection domain end-to-end
python3 tests/corpus_test.py    # 21 malware families attributed with correct category + UI wiring
python3 tests/bulk_test.py      # 18 checks: repack folder scan + large-file sampled scan
python3 tests/lnk_test.py       # 14 checks: weaponized shortcut detection + ATT&CK layer
```

- **`tests/smoke_test.py`** - one crafted sample per detection domain (YARA/hash, reputation
  wiring, format parsing, entropy/packers, IOC extraction, behavioral heuristics, script
  decode, CVE triggers, and the LummaC2/Electron attribution showcase), plus the URL scanner,
  score calibration (a clean file stays clean; Laelaps' own source is dampened as "reference
  content"), and CLI exit codes.
- **`tests/corpus_test.py`** - attribution breadth across 21 families (LummaC2, RedLine, Vidar,
  StealC, Raccoon, AgentTesla, Snake, AsyncRAT, Quasar, njRAT, Remcos, NanoCore, DCRat, Cobalt
  Strike, Meterpreter, Amadey, SmokeLoader, Emotet, LockBit, Conti, BlackCat), and a headless
  render of the Streamlit report so the UI wiring is verified without a browser.
- **`tests/bulk_test.py`** - a synthetic game repack (trojaned installer + benign readme +
  a big data blob with an executable overlay): asserts the installer is flagged, the readme
  stays clean, the huge blob is sampled rather than read whole, and the tree collapses to one
  malicious verdict; plus the large-file sampled path and CLI exit codes.
- **`tests/lnk_test.py`** - inert Windows shortcuts (shell-link structure only): asserts a
  shortcut launching an encoded PowerShell downloader is flagged, one with a trailing overlay
  is flagged, a plain notepad shortcut stays clean, and the ATT&CK Navigator layer export is
  well-formed.

## Important limitations (read these)

- **Static + reputation only.** No dynamic execution, memory, or live-network behavior.
  Packing/obfuscation can hide indicators - *absence of a signal is not proof of safety*.
  Confirm high-impact verdicts dynamically (CAPE / ANY.RUN / a real sandbox).
- **Attribution is probabilistic**, built from public signatures. Corroborate with a
  second source before acting on it.
- **Reference-vs-operational triage:** files that *describe/detect* malware (threat
  reports, detection rulesets, Laelaps' own source) are auto-dampened and labeled
  "reference content" so they don't false-positive. This is a heuristic, not a guarantee.
- **Handle real samples safely:** analyze in a disposable VM/container with no egress;
  never run `--deep` against a live payload outside a sandbox.

> ⚠️ **Authorized analysis only.** Analyze only files you have legal authority to inspect.
