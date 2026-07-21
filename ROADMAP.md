# Laelaps Enhancement & Upgrade Roadmap

*A landscape report for a solo defensive malware-analysis builder.*

Laelaps today is a static + reputation + attribution engine. This roadmap sequences the
upgrades that turn it into a full analysis framework, ranked by return on investment for a
solo builder, with every tool checked for maintenance status and licensing.

## Already in Laelaps

Shipped since this roadmap was written (do not re-scope these):

- **Large-download / repack scanning** - scan a whole directory tree or an oversized single
  file (e.g. a hundreds-of-GB game repack pulled from a torrent) without reading every byte:
  the executable/script/installer surface is analyzed in full and scanned first, huge data
  blobs are sampled (first 8 MB + last 2 MB), files are scanned in parallel, and the tree
  collapses to one aggregate verdict that names the offending file. Includes
  embedded-executable-overlay detection for droppers hidden inside data blobs.
- **PE clustering pivots (partial)** - imphash and rich-header hash are surfaced in the
  report. Still to add from Phase 1: authentihash, telfhash (ELF), icon dhash, and TLSH/HAC-T
  clustering.
- **LNK (Windows shortcut) analysis** (Section 9) - a pure-Python shell-link parser extracts
  the shortcut's target and arguments, flags interpreter/LOLBin launches, encoded-PowerShell
  and in-shortcut downloaders, and payloads smuggled in a trailing overlay.
- **ATT&CK Navigator layer export** (Section 10) - `--attack-layer FILE` writes the aggregated
  MITRE techniques as a Navigator layer JSON for coverage visualization.
- **Archive-aware repack scanning** (Section 9) - `.zip`/`.jar`/`.7z` bundles are expanded and
  each member scanned in place (named `archive::member`), nested archives are followed, and
  password-protected / Zip-Slip archives are flagged even when their contents cannot be read.
  This closes the real repack gap: FitGirl-style repacks ship the installer inside a `.7z`.
- **LOLBAS / GTFOBins living-off-the-land layer** (Section 9) - context-aware detection of abused
  signed binaries (certutil download, regsvr32 squiblydoo, mshta, msbuild/installutil AWL-bypass,
  bitsadmin, wmic, nc/bash/curl-pipe-shell) mapped to ATT&CK, applied corpus-wide so it catches
  LOLBin commands embedded in a PE, macro, LNK or document, not only in files parsed as scripts.

## TL;DR

- The single highest-uplift upgrade is adding a capability/behavior layer plus modern
  hashing/similarity that Laelaps does not yet have: integrate Mandiant CAPA (code-level
  capability detection mapped to ATT&CK + MBC) and FLOSS (deobfuscated string extraction),
  migrate YARA to YARA-X (the Rust rewrite that is now the official successor; classic YARA is
  in maintenance mode), and add TLSH-based clustering plus imphash/richhash/telfhash/icon-dhash
  pivots. These are all open-source, Python-friendly, and directly extend the existing static
  engine.
- The biggest architectural gap is dynamic analysis. Rather than build a sandbox, wire Laelaps
  into CAPEv2 (the maintained open-source config-and-payload-extraction sandbox) and/or the
  free Hatching/Recorded Future Triage API, and add lightweight emulation (Speakeasy for
  shellcode, Qiling/Dumpulator for config/string decryption) for cases that do not warrant a
  full VM.
- To become a "framework," model Laelaps on Assemblyline 4 / Strelka (plugin-analyzer +
  task-queue + REST + dashboard) or plug directly into them as a service; adopt STIX 2.1/MISP
  output and CAPA-style MBC mapping as interchange standards. Sequence the work in three
  phases: Phase 1 = static capability + hashing + config extraction + YARA-X (fast, high ROI);
  Phase 2 = dynamic/sandbox + memory + network fingerprinting; Phase 3 = platform architecture,
  ML, and threat-intel orchestration.

## Key Findings

1. **YARA-X is the new standard.** VirusTotal shipped YARA-X 1.0.0 stable in June 2025; classic
   YARA is now maintenance-only. YARA/YARA-X creator Victor Alvarez wrote in the VirusTotal
   post "YARA is dead, long live YARA-X" (May 2024): "YARA is still being maintained... do not
   expect new large features or modules. All efforts to enhance YARA, including the addition of
   new modules, will now focus on YARA-X." It is ~99% rule-compatible, faster on heavy
   regex/loops, memory-safe (Rust), has official Python bindings (`pip install yara-x`), and
   compiles to WASM. Migrate now for new detection logic.
2. **CAPA + MBC is the modern capability-mapping approach**, a category Laelaps lacks. CAPA
   identifies what a program can do at the code level (not byte patterns), mapping to MITRE
   ATT&CK and the Malware Behavior Catalog (MBC). This is the biggest single detection-capability
   uplift available, and it is a Python tool you can invoke directly.
3. **Dynamic analysis is the largest true gap.** CAPEv2 (kevoreilly) is the maintained
   open-source sandbox successor to the abandoned Cuckoo; it auto-unpacks and extracts configs
   for 70+ families and exposes a REST API. Classic Cuckoo is dead; Cuckoo3 (CERT-EE) and
   DRAKVUF Sandbox (CERT.pl, agentless/hypervisor-level) are the other live options.
4. **Emulation gives much of dynamic value without a VM.** Speakeasy (Mandiant) for
   shellcode/Windows emulation, Qiling (cross-platform, Unicorn-based), and Dumpulator (emulate
   minidumps, great for config extraction/unpacking) are all Python-scriptable and integrate as
   libraries.
5. **Config extraction is a force-multiplier for the existing family attribution.** malduck +
   mwcfg (CERT.pl ecosystem), MWCP (DoD), CAPE's extractors, and SentinelOne's
   CobaltStrikeParser / Didier Stevens' 1768.py turn "this looks like family X" into "here are
   its actual C2 servers, keys, and campaign IDs." For scale context, Google Threat Intelligence
   (Mandiant) reported in October 2024 that its configuration-extraction team "currently supports
   400+ malware families and is constantly expanding this support," a useful benchmark.
6. **Modern hashing/similarity beyond the current TLSH.** Add imphash and rich-header hash (both
   in `pefile`), authentihash, telfhash (ELF/IoT), icon dhash (perceptual hashing, directly
   strengthens the brand-impersonation feature), and use TLSH distances with HAC-T clustering to
   build a retrohunt corpus. TLSH is preferred over ssdeep for clustering because it is a true
   distance metric supporting O(N log N) clustering.
7. **Platform frameworks to model or adopt:** Assemblyline 4 (CSE Canada, plugin services, 50+
   analyzers, REST API, Kubernetes/Docker scale), Strelka (Target, real-time container-based
   file scanning with YARA), IntelOwl (analyzer orchestration), and Karton + MWDB (CERT.pl
   distributed pipeline). For a solo builder, the realistic path is a FastAPI REST wrapper +
   task queue + web dashboard, borrowing the plugin/service pattern.

## Details

### 1. Dynamic / Behavioral Analysis & Sandboxing (Phase 2)

Laelaps is static-only; this is the single most impactful capability class to add. Two
integration strategies: (a) call an external sandbox API, or (b) run lightweight emulation
in-process.

**Full sandboxes (open-source):**

- **CAPEv2** (kevoreilly/CAPEv2, GPL), the recommended open-source sandbox. Derived from Cuckoo,
  its name means "Config And Payload Extraction." It performs automated unpacking, config
  extraction for 70+ families (Emotet, Cobalt Strike, etc.), YARA-based classification of
  unpacked payloads, network (PCAP) capture, and a stealth debugger with dynamic anti-evasion
  bypasses. Exposes an `apiv2` REST API (token auth) returning behavioral telemetry, signatures,
  configs, and process dumps. Self-host on Ubuntu + Windows 10/11 guest under KVM/QEMU, or use
  the free public instance at capesandbox.com. Integration: submit sample via REST, poll for
  report JSON, merge extracted config + behavioral signatures into the report.
- **Cuckoo3** (CERT-EE), Python-3 rewrite of Cuckoo. Newer, smaller community than CAPE.
- **DRAKVUF Sandbox** (CERT.pl), agentless, hypervisor-level (Xen VMI) monitoring, so malware
  cannot detect an in-guest agent. Requires Xen-compatible hardware and more setup. Best when
  evasion-resistance is paramount; CAPE has the larger ecosystem and stronger config extraction.
- **Classic Cuckoo Sandbox is abandoned**, do not build on it.

**Commercial sandbox APIs (note free tiers):**

- **Hatching / Recorded Future Triage** (tria.ge), best free option for a solo builder. Free
  Researcher account yields an API key; REST API returns verdict scores (0-10), family tags,
  full behavioral report JSON, extracted malware configs for a growing family list, PCAP, and
  dumped files. Caveat: public-cloud submissions are public. Commercial private-cloud tiers start
  at 500 analyses/day. Now branded Recorded Future: Sandbox.
- **ANY.RUN API**, interactive sandbox; returns ATT&CK TTP mapping, IOCs, process graphs, and
  reports in JSON/MISP/STIX/HTML. Free Community plan is non-commercial with limited API; REST
  API/SDK and MISP/STIX export reserved for paid Hunter/Enterprise tiers.
- **Joe Sandbox**, free Cloud Basic gives 15 analyses/month (5/day) with limited output and
  public submissions; RESTful API with reports in XML/JSON/HTML/PDF and MAEC/MISP/OpenIOC export;
  2,580+ behavior signatures, MITRE mapping, config extraction.
- **VMRay**, enterprise, hypervisor-based/agentless, no real free tier; API-first with verdicts,
  VMRay Threat Identifiers (behavior patterns scored 1-5), ATT&CK mapping, and continuously
  updated config extractors. Least solo-friendly.
- **Intezer Analyze**, genetic/code-reuse analysis (identifies malware by shared code "genes");
  free community tier + Python SDK (`pip install intezer-sdk`); returns verdict, family
  classification, code reuse, IOCs, capabilities, related samples.

**Emulation frameworks (lightweight, in-process, high ROI, no VM):**

- **Speakeasy** (Mandiant), emulates Windows user/kernel-mode malware and shellcode on top of
  Unicorn; ideal for triaging shellcode and getting API-call traces at scale. Python.
- **Qiling**, higher-level cross-platform (Windows/Linux/macOS/BSD/UEFI; x86/ARM/MIPS) emulation
  framework on Unicorn, with loaders, dynamic linkers, and syscall/IO handlers. Great for
  string/config decryption and controlled execution of snippets. CERT.pl's karton-unpacker uses
  Qiling to unpack UPX and others.
- **Dumpulator**, emulates minidump files; because full process memory is present, it is fast for
  config extraction and unpacking (only syscalls need emulation).
- **Unicorn Engine**, the low-level CPU emulator underneath the above; use directly to decrypt
  strings/deobfuscate control flow. Supports 10 architectures as of 2025.
- **Zelos**, another Python binary emulation framework in the same class.

**Recommendation:** Phase 2 = add Speakeasy (shellcode) + Qiling/Dumpulator (config decryption)
as libraries first (no infra), then wire the Triage free API, then optionally self-host CAPEv2.

### 2. Advanced Static Analysis & Capability Detection (Phase 1, highest ROI)

- **Mandiant CAPA** (Apache-2.0), identifies capabilities in PE/ELF/.NET/shellcode via rules
  describing code-level features (APIs, strings, constants, byte patterns) within functions/basic
  blocks, and maps them to ATT&CK, MBC, and MAEC. Unlike YARA (byte patterns), CAPA describes
  behavioral capability. This is the flagship addition; it upgrades MITRE mapping from
  string-heuristic to code-level and adds MBC. Invoke as a Python library or subprocess; ingest
  the JSON.
- **YARA-X**, migrate the generic rules + 25-rule family pack. Keep classic YARA only for any
  rule using deprecated features; author all new rules in YARA-X. `pip install yara-x`.
- **FLOSS** (Mandiant, formerly FLARE Obfuscated String Solver), automatically extracts static,
  stack, tight, and decoded/obfuscated strings via emulation (vivisect). Direct upgrade to the
  ASCII/UTF-16 string extraction. Now has Go/Rust language-aware extraction and a new
  "QuantumStrand" contextual string tool. Consider adding StringSifter (Mandiant ML string
  ranker) on top, as Assemblyline/FAME/IntelOwl do.
- **Detect-It-Easy (DiE)**, the de-facto packer/compiler/linker detector with a large signature
  database; complements the existing packer heuristics with a maintained signature set (has a
  CLI/`diec`).
- **LIEF**, robust cross-platform PE/ELF/Mach-O parsing and modification library; more capable
  than format-specific parsers and useful for feature extraction. (Note: EMBER moved from LIEF to
  `pefile` for its v3 features, so use both where appropriate.)
- **Headless disassembler automation:** Ghidra headless / pyghidra (now shipped with Ghidra),
  radare2/rizin with r2pipe/rzpipe (open, scriptable, free), and Binary Ninja API (commercial,
  excellent API). Use these to script function-level analysis, xrefs, and to feed CAPA (CAPA can
  use its own vivisect/Binary Ninja/IDA backends). For a solo builder, rizin + r2pipe or pyghidra
  is the free path.
- **MBC mapping**, adopt alongside ATT&CK; CAPA emits both, so integrating CAPA gets you MBC for
  free.

### 3. Machine Learning & Similarity / Clustering (Phase 3 + selective Phase 1)

**Fuzzy hashing / similarity (add in Phase 1, cheap, high value):**

- **TLSH** (already integrated), use distances + HAC-T hierarchical clustering for O(N log N)
  family grouping; TLSH is preferred over ssdeep for clustering because it is a true distance
  metric and is harder to evade. Adopted by MalwareBazaar, MISP, STIX 2.1. `python-tlsh`.
- **imphash**, MD5 of PE import table; `pefile.get_imphash()`. Links samples built with the same
  toolkit. Limitations: PE-only, collides on generic/low-import tables (filter to >= 10 imports),
  near-useless for .NET (use TypeRefHash), and forgeable.
- **Rich header hash**, `pefile.get_rich_header_hash()` (since pefile 2021.9.3); links samples
  from the same build environment. Can be very broad, filter goodware.
- **authentihash**, PE hash excluding Authenticode fields; matches identical code across different
  signatures.
- **telfhash** (Trend Micro), symbol hash for ELF, the imphash analog for Linux/IoT malware;
  supported on VirusTotal since 2020; depends on TLSH. `pip install telfhash`.
- **icon dhash / perceptual hashing**, extract PE/APK icons and compute dhash (via
  `imagehash`/`dhash`), cluster by Hamming distance. This directly strengthens the existing
  brand-impersonation/typosquat feature by catching fake installers reusing brand icons.
- **LZJD** (`pyLZJD`) and sdhash, alternative similarity digests; LZJD is fast and strong on large
  files but results are dataset-dependent.
- **vhash/behash**, VirusTotal's proprietary structural and behavioral hashes; pivot via the VT
  API rather than compute locally.

**ML classification (Phase 3):**

- **EMBER**, the de-facto PE feature standard. EMBER2024 (Joyce et al., presented at ACM
  SIGKDD/KDD-2025, Toronto, Aug 3-7 2025) expanded to exactly 3,238,315 files (50,500/week over 64
  weeks, Sep 24 2023 to Dec 14 2024) across Win32/Win64/.NET/APK/ELF/PDF, with feature v3 (2,568
  dimensions) and a challenge set of 6,315 malicious files that initially evaded all VirusTotal AV
  engines. The oft-cited strong baseline (ROC-AUC ~0.996 and ~94% TPR at 1% FPR, or ~99% TPR
  reported in some runs) comes from the original EMBER2018 LightGBM baseline (Anderson & Roth,
  2018, arXiv:1804.04637), not EMBER2024, whose headline finding is that classifiers degrade
  sharply on the evasive challenge set. Train a LightGBM GBDT model for a fast malicious/benign
  score; `pip install ember` + `lightgbm`.
- **MalConv**, featureless raw-byte CNN baseline; heavier, marginally lower AUC than LightGBM.
- **Graph-neural-network / transformer approaches** exist but are research-grade; not worth solo
  effort yet.

**Binary diffing / function similarity:**

- **BinDiff** (Google, open-source since 2024), graph-based function matching across
  IDA/Ghidra/Binary Ninja exports; the most-used diffing tool.
- **Diaphora**, most feature-rich open-source IDA diffing plugin; SQLite-backed, scriptable,
  tool-agnostic.
- **ghidriff**, Ghidra-based, fully free/headless diffing engine (good for automation).
- **FunctionSimSearch, machoc/machoke**, function-level fuzzy hashing for clustering.

### 4. Config Extraction & Automated Unpacking / Deobfuscation (Phase 1-2)

- **malduck** (CERT.pl), Python malware-analysis Swiss army knife: modular config-extraction
  engine, crypto (AES/ChaCha/Serpent/etc.), compression (aPLib/LZNT1), and memory-model objects
  over PE/ELF/dumps. The framework to build extractors on.
- **mwcfg + mwcfg-modules**, ready-made malduck extractor modules and a CLI/server.
- **MWCP** (DoD/DC3) and **RATDecoders** (kevthehermit), additional extractor ecosystems.
- **CAPE config extractors**, reusable even outside the sandbox.
- **Cobalt Strike:** SentinelOne CobaltStrikeParser and Didier Stevens 1768.py parse beacon
  configs, high value given Cobalt Strike is in the family list.
- **configextractor-py** (CSE Canada), unifies many parser frameworks (malduck, MWCP, etc.)
  behind one interface; used by Assemblyline.
- **Unpacking/deobfuscation:** unipacker (generic PE unpacker), de4dot / de4dot-cex (.NET),
  ILSpy/dnSpyEx automation; box-js and malware-jail (JavaScript, box-js was the strongest in one
  comparative study, though DOM-heavy samples still fail); PowerDecode and PowerShellProfiler
  (PowerShell); oletools/olevba, ViperMonkey (VBA emulation), XLMMacroDeobfuscator (Excel 4.0
  macros); scdbg and Speakeasy for shellcode.

### 5. Network / Traffic & Infrastructure Analysis (Phase 2)

- **TLS fingerprinting:** JA4+ (FoxIO) is the current best-in-class, superseding JA3. Per the
  VirusTotal blog "Unveiling Hidden Connections: JA4 Client Fingerprinting on VirusTotal" (Oct 18,
  2024), "JA4, developed by FoxIO, represents a significant advancement over the older JA3... JA4
  was specifically designed to be resilient to this [TLS extension] randomization," and it is
  queryable via the `behavior_network` search modifier. Keep JARM (active server fingerprinting,
  good for Cobalt Strike C2) and JA3/JA3S for legacy corpus matching, and add HASSH for SSH. Note
  licensing: the JA4 TLS-client fingerprint is BSD-3, but the rest of JA4+ (JA4S/H/L/X/SSH) is
  under the FoxIO License 1.1 (free for internal use, not for monetization).
- **PCAP analysis & IDS:** Suricata (also runs inside CAPE), Zeek, Snort. Auto-generate
  Suricata/Snort rules from extracted IOCs and configs.
- **Infrastructure pivoting/enrichment:** Shodan, Censys, VirusTotal graph, passive DNS, abuse.ch
  feeds (URLhaus/ThreatFox/MalwareBazaar, several already used), GreyNoise (internet-noise
  filtering), Spamhaus. Add these as enrichment analyzers keyed off extracted IPs/domains.

### 6. Threat Intelligence Integration & Standards (Phase 3)

- **STIX 2.1 / TAXII**, the interchange standard; emit IOCs/reports as STIX 2.1 bundles (use the
  `stix2` Python lib) and optionally serve a TAXII 2.1 collection. This is the single most
  important standards upgrade for interoperability.
- **MISP**, integrate via PyMISP: push events/attributes, consume feeds, apply warninglists (to
  suppress false-positive IOCs like public DNS), and retrohunt. MISP is the most widely adopted
  sharing platform.
- **OpenCTI**, STIX 2.1-native knowledge graph; richer TTP modeling. Sync with MISP via
  connectors.
- **AlienVault OTX**, free pulses for enrichment.
- **Other standards to emit/consume:** MBC (via CAPA), MAEC (malware attribute encoding), OpenIOC,
  CACAO (playbooks). Export MITRE ATT&CK Navigator layers (JSON) from technique mappings, easy,
  high-impact reporting upgrade.

### 7. Memory Forensics (Phase 2-3)

- **Volatility 3**, the standard (Volatility 2 is legacy); plugins `malfind` (RWX/injected code),
  `ptemalfind`, `dlllist`, `yarascan`, `dumpfiles`, `hashdump`, `netscan`. Detects
  injection/hollowing and lets you dump unpacked payloads for the static engine to re-analyze.
  `pip install volatility3`.
- **MemProcFS**, mounts a memory image as a filesystem; its `findevil` forensic mode (Windows
  10+) flags injected code and integrates YARA scanning (e.g., with the 1,000+ Elastic rules).
  Very analyst-friendly.
- **Integration:** accept a memory dump as input, run malfind + in-memory YARA/CAPA, extract and
  recursively analyze injected/unpacked regions.

### 8. Frameworks to Build On / Architecture Upgrade (cross-cutting; Phase 1 planning to Phase 3 execution)

Options, ranked by solo-builder realism:

- **Model Laelaps's architecture on Strelka** (Target), real-time, container-based file scanning
  at scale; a coordinator + workers + YARA/backend scanners, each file type routed to scanners
  that can recursively re-submit extracted children. This decomposition (router, per-type
  scanners, recursive extraction, YARA/metadata) is exactly how to refactor Laelaps's monolithic
  CLI into services. It has 50+ scanners and a simple UI.
- **Assemblyline 4** (CSE Canada, MIT), the go-to open platform: plugin "services," 50+ analyzers,
  scoring, REST API, web UI, Docker/Kubernetes scaling, recursive deobfuscation. You can (a)
  contribute Laelaps as an Assemblyline service, or (b) adopt its service/scoring architecture. It
  already wraps CAPA, FLOSS, config extractors, etc.
- **IntelOwl**, threat-intel orchestration with many analyzers behind one REST API/Python client;
  good model for the enrichment layer.
- **Karton + MWDB** (CERT.pl), distributed, Redis/S3-backed microservice pipeline (router,
  classifier, analyzers, mwdb-reporter) with MWDB as the sample/config repository. The reference
  architecture for a scalable extraction pipeline; Karton-playground lets you prototype.
- **Viper, Yeti, FAME**, modular analysis/binary-management frameworks; FAME is explicitly
  "modular analysis" and a good conceptual match.
- **TheHive + Cortex**, case management + observable analyzers/responders; integrate Laelaps as a
  Cortex analyzer so SOC analysts can run it one-click on an observable.
- **SOAR/automation:** Shuffle (open-source), n8n, Tines, orchestrate Laelaps + sandbox +
  enrichment into playbooks.

**Concrete solo path:** wrap Laelaps's analyzers as independent callables, add a FastAPI REST
service, add a task queue (Celery/RQ + Redis) for batch/bulk scanning, add a lightweight web
dashboard, and adopt a plugin/analyzer registration pattern so new format analyzers and enrichment
modules are drop-in. This is the "become a framework" upgrade.

### 9. File-Format & Platform Coverage Expansion (Phase 1-2, incremental)

- **LNK files**, high priority; LNK is a dominant initial-access vector post-macro-blocking
  (Qakbot, IcedID, Emotet, etc.). Use LnkParse3 (Python, parses malformed files) or Lifer; extract
  target/args/icon/overlay and metadata (machine ID, MAC, droid GUIDs) for campaign tracking; flag
  zeroed headers and overlays as suspicious (as Velociraptor 0.73 does).
- **OneNote (.one)**, extract embedded files/scripts (bat/vbs/ps1) and the fake-lure images; a
  2023-2024 delivery vector. (Assemblyline built dedicated OneNote services after the 2023
  campaign wave.)
- **ISO/IMG/VHD, MSIX/AppX, InstallShield, Docker/OCI images**, container-based delivery bypasses
  MOTW; add parsers to unwrap and recurse.
- **Mobile:** deeper Android via androguard 4.x (note: original author no longer maintains it, the
  `ng` branch/community continues it), MobSF (static+dynamic), Quark-Engine (obfuscation-neglect
  behavior scoring, now radare2/rizin-backed); iOS IPA static analysis via MobSF.
- **macOS:** deep Mach-O analysis (LIEF), code-signature/entitlements/notarization checks.
- **Living-off-the-land:** map observed commands to LOLBAS (Windows) and GTFOBins (Unix),
  high-value, low-effort detection enrichment.
- **Script droppers:** deeper Python (pyinstxtractor/decompyle), Go, Nim, Rust dropper analysis
  (FLOSS now has Go/Rust string support).

### 10. Reporting, Detection-Engineering & Visualization (Phase 1-3)

- **Auto-generate detection artifacts:** yarGen / yaraGenerator / YARA-X for YARA rules from
  samples (yarGen strips goodware strings; v0.24 adds an `--ai` option); Sigma rules for host/log
  detection; Suricata/Snort rules from network IOCs; ClamAV signatures. Emitting these turns
  Laelaps from an analyzer into a detection-engineering tool.
- **Attack-chain / process-tree visualization**, render process trees and capability/ATT&CK graphs
  (Graphviz/d3) from CAPA + sandbox output.
- **MITRE ATT&CK Navigator layer export**, JSON layers from technique mappings (quick win).
- **IOC standardization:** iocextract and msticpy (Microsoft) for robust, defanged IOC extraction
  and enrichment, upgrades the existing IOC regexes.
- **Richer HTML/PDF output**, templated HTML (Jinja2) + WeasyPrint/wkhtmltopdf for analyst-grade
  PDF reports alongside the Markdown.

## Recommendations

### Phase 1 - Static capability & similarity uplift (weeks, no new infra; highest ROI)

1. Migrate YARA to YARA-X (`pip install yara-x`); author all new family rules in YARA-X.
2. Integrate CAPA (capabilities + ATT&CK + MBC) and FLOSS (obfuscated strings), the two biggest
   single upgrades; add StringSifter ranking.
3. Add hashing pivots: imphash + rich-header hash (`pefile`), authentihash, telfhash (ELF), icon
   dhash (strengthens brand-impersonation); implement TLSH/HAC-T clustering to start a retrohunt
   corpus.
4. Add config extractors via malduck/mwcfg + CobaltStrikeParser/1768.py.
5. Add LNK (LnkParse3) and OneNote parsers; add LOLBAS/GTFOBins mapping.
6. Add DiE for packer/compiler detection; iocextract/msticpy for IOC standardization; ATT&CK
   Navigator layer + Sigma/YARA-X rule auto-generation.

*Benchmark to advance:* once static verdicts stabilize and you can cluster the sample corpus, move
to Phase 2.

### Phase 2 - Dynamic, memory, network (needs a VM/API)

1. Add emulation first (Speakeasy for shellcode, Qiling/Dumpulator for config decryption), no
   infra.
2. Wire the Triage free API (or ANY.RUN/Joe free tiers); then optionally self-host CAPEv2.
3. Add Volatility 3 + MemProcFS memory analysis (malfind + in-memory YARA/CAPA; recurse dumped
   payloads).
4. Add JA4+/JARM/HASSH fingerprinting, PCAP parsing, and Suricata rule generation from IOCs; add
   Shodan/Censys/GreyNoise/abuse.ch enrichment.

*Benchmark:* if you are processing enough samples that manual runs bottleneck, move to Phase 3.

### Phase 3 - Framework architecture, ML, TI orchestration

1. Refactor into a plugin/analyzer + FastAPI REST + task-queue + dashboard architecture (model on
   Strelka/Assemblyline); add batch/bulk scanning.
2. Emit STIX 2.1 bundles, integrate MISP (PyMISP + warninglists) and optionally OpenCTI; expose
   Laelaps as a Cortex analyzer.
3. Train an EMBER2024 + LightGBM classifier for a fast ML malicious score; add
   BinDiff/Diaphora/ghidriff for function-level similarity.
4. Consider contributing Laelaps as an Assemblyline service or plugging into Karton/MWDB for scale.

### What would change these recommendations

If the primary use is triaging Linux/IoT samples, prioritize telfhash + ELF emulation (Qiling)
over PE-centric work. If it is document/initial-access malware, prioritize
LNK/OneNote/oletools/ViperMonkey. If you need shareable intel output for a team, pull STIX
2.1/MISP forward into Phase 1. If throughput becomes the constraint, pull the framework refactor
(Phase 3) earlier.

## Caveats

- **Licensing:** Most tools here are permissive open-source (Apache/MIT/BSD/GPL), but note: JA4+
  beyond the base TLS-client fingerprint is FoxIO License 1.1 (no monetization); Binary
  Ninja/IDA/VMRay/Joe Sandbox Pro are commercial; CAPEv2 is GPL (copyleft, matters if you
  redistribute). Verify each before shipping a product.
- **Maintenance status flagged:** classic YARA = maintenance-only (use YARA-X); classic Cuckoo and
  CAPEv1 = abandoned (use CAPEv2/Cuckoo3); androguard original author stepped back (community `ng`
  branch continues); ssdeep = superseded by TLSH for clustering (not dead); imphash = reliability
  limits documented (collisions, .NET, forgeable).
- **Public-cloud sandboxes expose your samples** (Triage/ANY.RUN Community/Joe Basic make
  submissions public), do not submit sensitive or attributable samples; self-host CAPE for those.
- **Dynamic analysis is dangerous**, run sandboxes on isolated, no-internet (or
  controlled-internet) networks with strict segmentation, as Assemblyline hardening guidance
  stresses.
- **ML models drift and evade:** EMBER2024's own challenge set of 6,315 samples that evaded all
  VirusTotal engines shows classifiers degrade sharply on evasive malware; treat any ML score as
  one signal, never a verdict. Note that the strong ~0.996 AUC figure is the 2018 baseline, not a
  guarantee on today's evasive samples.
- **Some figures are third-party estimates** (e.g., Joe Sandbox Pro ~$499/mo, Intezer ~$2,400
  start), confirm current pricing with vendors.
- **Independent evaluations of similarity hashes** (TLSH, LZJD) are dataset-dependent; validate on
  your own corpus before trusting for attribution.
