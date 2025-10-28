# Malware Analysis Tools Reference

## References & Documentation

### Official Documentation
- **REMnux Tool Discovery**: [https://docs.remnux.org/discover-the-tools/examine+static+properties](https://docs.remnux.org/discover-the-tools/examine+static+properties)
  - Comprehensive guide to all REMnux tools organized by analysis category

### Quick Reference Guides
- **REMnux Malware Analysis Tips (PDF)**: [https://zeltser.com/media/docs/remnux-malware-analysis-tips.pdf](https://zeltser.com/media/docs/remnux-malware-analysis-tips.pdf)
  - Cheat sheet by Lenny Zeltser with practical analysis workflows and command examples

---

## Static Analysis (Files, Binaries, Strings, PE/ELF Metadata)

### Basic File Analysis
- **`file`** - Determine file type and format
- **`strings`** - Extract printable strings from binaries
- **`binwalk`** - Firmware analysis and extraction tool
- **`xxd`** - Hexadecimal dump utility
- **`hexdump`** - Another hexadecimal viewer

### Binary Analysis (Linux/ELF)
- **`readelf`** - Display information about ELF files
- **`objdump`** - Display information from object files
- **`nm`** - List symbols from object files
- **`strip`** - Remove symbols from object files

### PE Analysis (Windows)
- **`pefile`** (Python) - Python library for PE file analysis
- **`peframe`** - PE static analysis framework
- **`pehash`** - Generate hashes for PE files
- **`peframe`** - PE malware analysis framework
- **`Detect-It-Easy` (DiE)** - File type detection and analysis
- **`CFF Explorer`** - PE editor and analysis tool (via Wine)

### Advanced Static Analysis
- **`rabin2`/`radare2`** - Binary analysis framework
- **`flare-floss`** - Extract obfuscated strings from malware
- **`yara`/`yara-python`** - Pattern matching engine

---

## Disassembly / Decompilation / Reverse Engineering

### Primary Disassemblers
- **`Ghidra`** - NSA's free reverse engineering suite with decompiler
- **`Radare2` (`r2`)** - Command-line reverse engineering framework
- **`Cutter`** - GUI frontend for Radare2

### Assembly/Disassembly Libraries
- **`capstone`** - Disassembly framework
- **`keystone`** - Assembly framework

### Debugging Tools
- **`edb-debugger`** - Evan's Debugger for Linux
- **`gdb`** - GNU Debugger
- **`ndisasm`** - Netwide Disassembler

---

## Dynamic Analysis / Sandboxes / Network Simulation

### Network Simulation
- **`fakenet-ng`/`flare-fakenet-ng`** - Simulate network services for malware analysis
- **`INetSim`** - Internet services simulation suite

### Sandboxes
- **`Cuckoo`** - Automated malware analysis sandbox
- **Docker images** - Containerized analysis environments

### System Monitoring
- **`sysinternals` helpers** - Process monitors and system utilities (via Wine)
- **Process monitors** - Various system activity monitoring tools

---

## Memory Forensics & Live Memory Analysis

### Memory Analysis Frameworks
- **`Volatility` (v2/v3)** - Advanced memory forensics framework
- **`rekall`** - Memory analysis framework (sometimes included)

### Memory Acquisition
- **LiME** - Linux Memory Extractor
- **Memory acquisition scripts** - Various helper tools for memory capture

---

## Network / PCAP / Traffic Analysis

### Network Analysis
- **`Wireshark`** - Network protocol analyzer with GUI
- **`tcpdump`** - Command-line packet analyzer

### Intrusion Detection
- **`Suricata`** - Network threat detection engine
- **`Snort`** - Network intrusion detection system
- **`Bro/Zeek`** - Network analysis framework

### Additional Network Tools
- **`ssdeep`** - Fuzzy hashing for similarity detection
- **`ndpi`** - Deep packet inspection library

---

## Document & Office Malware Analysis

### OLE/Office Analysis
- **`oledump.py`** - Analyze OLE files (Office documents)
- **`olevba`** - Extract and analyze VBA macros
- **`oletools`** - Suite of tools for OLE analysis
- **`mraptor`** - Detect malicious macros
- **`evilclippy`** - Advanced macro analysis

### PDF Analysis
- **`pdfid.py`** - Identify suspicious PDF elements
- **`pdf-parser.py`** - Parse and analyze PDF files
- **`peepdf`** - Interactive PDF analysis tool

---

## Windows-specific / PE Analysis

### File Type Detection
- **`peid`** - Detect packers, cryptors, and compilers
- **`trid`** - File type identification
- **`diec`** - Detect It Easy - packer/compiler detection

### PE-Specific Tools
- **`peframe`** - PE malware analysis framework
- **`flare-floss`** - Extract obfuscated strings from PE files

---

## YARA, IOCs, Automation & Threat Intelligence

### YARA Tools
- **`yara`** - Pattern matching engine
- **`yarGen`** - Generate YARA rules automatically
- **`yara-python`** - Python bindings for YARA

### Threat Intelligence
- **`virustotal-search.py`** - Query VirusTotal API
- **`vt` wrappers** - VirusTotal command-line tools
- **`ioc_writer`** - Generate IOC files
- **Community scripts** - Automated queries to VT/OTX/etc.

---

## Scripts & Utility Collection

### REMnux Helpers
- **`remnux-installer` scripts** - Installation and setup utilities
- **`remnux` meta packages** - Package management
- **`myip`** - Display IP address information
- **`texteditor.py`** - Text editing utilities
- **`sortcanon.py`** - Canonicalization and sorting

### General Utilities
- **`7z`/`7zz`** - Archive extraction and creation
- **`ExifTool`** - Metadata extraction and editing
- **`trid`** - File type identification
- **`scalpel`** - File carving tool
- **`bulk_extractor`** - Digital forensics tool

---

## Android / Mobile Analysis

### Android Static Analysis
- **`dex2jar`** - Convert DEX files to JAR
- **`apktool`** - Reverse engineer Android APK files
- **`jadx`** - DEX to Java decompiler
- **`dexdump`** - DEX file parser

### Additional Mobile Tools
- **Smali tooling** - Android assembly language tools
- **DEX analyzers** - Various DEX analysis utilities

---

## Web / JavaScript / Script Analysis

### JavaScript Analysis
- **`jsbeautifier`** - JavaScript code formatter
- **`node` utilities** - Node.js-based analysis tools
- **`yaff`** - JavaScript analysis framework

### Script Analysis
- **`yara` + JS rulesets** - JavaScript-specific YARA rules
- **Script scanners** - Various JavaScript malware detection tools

---

## Forensics / File Carving / Metadata

### File Carving
- **`bulk_extractor`** - Extract information from digital evidence
- **`scalpel`** - Fast file carver
- **`foremost`** - File carving and recovery tool

### Metadata Analysis
- **`ExifTool`** - Read/write metadata in files
- **`zipdump.py`** - Analyze ZIP file contents

### Search Tools
- **`ripgrep`** - Fast text search tool
- **`grep`** - Text pattern matching

---

## Containers & Docker Images

### Containerized Analysis
- **REMnux Docker images** - Containerized versions of analysis tools
- **Reproducible labs** - Consistent analysis environments
- **Isolated execution** - Safe malware analysis in containers

### Benefits
- **No full distro installation** - Run specific tools without full REMnux
- **Reproducible analysis** - Consistent environments across systems
- **Easy deployment** - Quick setup for analysis tasks

---

## Tool Categories Summary

| Category | Primary Use Case | Key Tools |
|----------|-----------------|-----------|
| **Static Analysis** | File examination without execution | `file`, `strings`, `ghidra`, `radare2` |
| **Dynamic Analysis** | Runtime behavior analysis | `cuckoo`, `fakenet-ng`, `volatility` |
| **Network Analysis** | Traffic and communication analysis | `wireshark`, `suricata`, `tcpdump` |
| **Document Analysis** | Office/PDF malware detection | `oletools`, `pdfid`, `olevba` |
| **Mobile Analysis** | Android/mobile app analysis | `apktool`, `jadx`, `dex2jar` |
| **Threat Intelligence** | IOC generation and lookup | `yara`, `virustotal-search`, `yargen` |

---

## Getting Started Recommendations

### Beginner Tools
1. **`file`** and **`strings`** - Basic file analysis
2. **`Ghidra`** - User-friendly reverse engineering
3. **`Wireshark`** - Network traffic analysis
4. **`oletools`** - Document malware analysis

### Intermediate Tools
1. **`Radare2/Cutter`** - Advanced disassembly
2. **`Volatility`** - Memory forensics
3. **`YARA`** - Pattern matching and rule creation
4. **`Cuckoo`** - Automated sandbox analysis

### Advanced Tools
1. **Custom scripts** - Automated analysis workflows
2. **`fakenet-ng`** - Network service simulation
3. **`bulk_extractor`** - Large-scale forensics
4. **Docker containers** - Scalable analysis infrastructure