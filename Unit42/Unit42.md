# Unit42 Sherlock Analysis Report

* **Date of Analysis:** September 11, 2025
* **Analyst:** Belhamici Abderrahmane
* **Source:** [HackTheBox Sherlock — *Unit42*](https://app.hackthebox.com/sherlocks/Unit42)
* **Dataset:** Windows Event Log file

---

## Overview
This analysis focuses on a UltraVNC campaign where attackers utilized a backdoored version of UltraVNC to maintain access to Windows systems. The investigation uses Sysmon logs to identify and analyze malicious activities during the initial access stage of the campaign.


## Investigation Details
- **File Analyzed**: `Microsoft-Windows-Sysmon-Operational.evtx`
- **Analysis Tool**: Splunk
- **Splunk index**: htb-unit42
- **Timeline**: February 14, 2024, 03:41:45 - 03:43:26
- **Duration**: ~1 minute 41 seconds

---

## Sysmon Event IDs Reference

| Event ID | Event Type | Description |
|----------|------------|-------------|
| **1** | Process Creation | Logs process creation with command line, hashes, process path, parent process |
| **2** | File Creation Time Changed | Logs when process changes creation time of files (time stomping) |
| **3** | Network Connection | Logs network connections initiated or received by processes |
| **5** | Process Terminated | Logs when processes terminate/end |
| **11** | File Created | Logs file creation and overwrite events |
| **22** | DNS Query | Logs DNS queries made by processes |

---

## Task Analysis Summary

### Task 1: Event Log Count
- **Question**: How many Event logs are there with Event ID 11?
- **Answer**: 56 events
- **Event ID Used**: 11
- **Event Definition**: File creation events - logged whenever a file is created or overwritten on the system
- **Significance**: High volume of file creation events indicates potential malware dropping multiple files

### Task 2: Malicious Process Identification
- **Question**: What is the malicious process that infected the victim's system?
- **Answer**: `C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe`
- **Event ID Used**: 1
- **Event Definition**: Process creation events - logged whenever a new process is created, including command line arguments, process path, parent process, and file hashes
- **Analysis Value**: Allows analysts to see all programs executed on the system and identify malicious processes

#### Malware Analysis Details
| Attribute | Value |
|-----------|-------|
| **Creation Time** | 2024-02-14 03:41:26.459 |
| **SHA256 Hash** | `0CB44C4F8273750FA40497FCA81E850F73927E70B13C8F80CDCFEE9D1478E6F3` |
| **VirusTotal Detection** | 47/70 security vendors flagged as malicious |
| **Threat Classification** | trojan.winvnc/ultravnc |

#### Known File Variants
- Fattura 2 2024
- Fattura 2 2024.exe
- Preventivo24.01.11.exe
- Preventivo24.01.11.exe.bak
- verdesicilia.exe

#### Timeline History
- **Creation Time**: 2023-12-20 11:17:56 UTC
- **First Seen In The Wild**: 2024-01-23 14:48:08 UTC
- **First Submission**: 2024-01-22 10:30:24 UTC
- **Last Analysis**: 2025-08-27 07:58:13 UTC

#### Detection Rules

**YARA Rules**
- `Disclosed_0day_POCs_payload_MSI` - Detects POC code from disclosed 0day hacktool set
- `Windows_API_Function` - Detects Windows API functionality in executables
- `Adobe_XMP_Identifier` - Identifies Adobe XMP metadata

**High-Risk Sigma Rules**
- System File Execution Location Anomaly
- Potential MsiExec Masquerading
- Files With System Process Name In Unsuspected Locations

**Medium/Low-Risk Sigma Rules**
- WMIC Loading Scripting Libraries
- Potential DLL Sideloading Of DBGHELP.DLL
- New Firewall Rule Added Via Netsh.EXE
- Use of UltraVNC Remote Access Software
- Process Reconnaissance Via Wmic.EXE
- CurrentVersion NT Autorun Keys Modification
- System Information Discovery Via Wmic.EXE
- Modification of IE Registry Settings
- CMD Shell Output Redirect

**Sandbox Detection Results**
- **Zenbox**: MALWARE TROJAN EVADER
- **Dr.Web vxCube**: MALWARE
- **Yomi Hunter**: MALWARE

### Task 3: Distribution Method
- **Question**: Which Cloud drive was used to distribute the malware?
- **Answer**: DropBox
- **Event ID Used**: 22
- **Event Definition**: DNS query events - logged when a process makes DNS queries to resolve domain names
- **Evidence**: DNS Query to `uc2f030016253ec53f4953980a4e.dl.dropboxusercontent.com`
- **Timestamp**: 2024-02-14 03:41:26.000

### Task 4: Time Stomping Defense Evasion
- **Question**: What was the timestamp changed to for the PDF file?
- **Answer**: 2024-01-14 08:10:06.029
- **Event ID Used**: 2
- **Event Definition**: File creation time changed events - logged when a process changes the creation time of a file (time stomping technique)
- **Purpose**: Defense evasion technique to make malicious files appear older and blend in with legitimate files

#### Time Stomping Details
| Attribute | Value |
|-----------|-------|
| **Event Code** | 2 |
| **File Path** | `C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\TempFolder\~.pdf` |
| **Real Creation Time** | 2024-02-14 03:41:58.404 |
| **Modified Timestamp** | 2024-01-14 08:10:06.029 |

### Task 5: Dropped File Location
- **Question**: Where was "once.cmd" created on disk?
- **Answer**: `C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\once.cmd`
- **Event ID Used**: 11
- **Event Definition**: File creation events - logged when files are created or overwritten on the filesystem
- **Creation Time**: 2024-02-14 03:41:58.404
- **Analysis Value**: Tracks all files dropped by malware for forensic reconstruction

### Task 6: Internet Connectivity Check
- **Question**: What domain name did it try to connect to?
- **Answer**: `www.example.com`
- **Event ID Used**: 22
- **Event Definition**: DNS query events - captures DNS resolution requests made by processes
- **Purpose**: Dummy domain used to check internet connection status before C2 communication
- **Timestamp**: 2024-02-14 03:41:56.955

### Task 7: Command & Control Communication
- **Question**: Which IP address did the malicious process try to reach out to?
- **Answer**: 93.184.216.34
- **Event ID Used**: 3
- **Event Definition**: Network connection events - logged when a process makes or accepts network connections
- **Source IP**: 172.17.79.132
- **Analysis Value**: Identifies external C2 communication attempts and network-based IOCs

### Task 8: Process Termination
- **Question**: When did the process terminate itself?
- **Answer**: 2024-02-14 03:41:58.795
- **Event ID Used**: 5
- **Event Definition**: Process termination events - logged when a process ends/terminates
- **Context**: The malicious process terminated after successfully infecting the PC with backdoored UltraVNC
- **Analysis Value**: Helps establish the timeline and duration of malicious process execution

---

## Key Findings

### Attack Timeline
1. **03:41:26** - Initial malicious executable execution and DropBox DNS query
2. **03:41:56** - Internet connectivity check to www.example.com
3. **03:41:58** - File dropping and time stomping activities
4. **03:41:58** - Malicious process self-termination

### TTPs (Tactics, Techniques, and Procedures)
- **Initial Access**: Malicious executable disguised as invoice/document
- **Defense Evasion**: Time stomping to blend files with legitimate timestamps
- **Persistence**: UltraVNC backdoor installation
- **Command & Control**: Network communication to external IP
- **Discovery**: Internet connectivity verification

### IOCs (Indicators of Compromise)
- **File Hash**: `0CB44C4F8273750FA40497FCA81E850F73927E70B13C8F80CDCFEE9D1478E6F3`
- **Domain**: `uc2f030016253ec53f4953980a4e.dl.dropboxusercontent.com`
- **IP Address**: `93.184.216.34`
- **File Path**: `C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe`

---

## Conclusion
This analysis reveals a sophisticated attack campaign utilizing social engineering (fake invoice documents) combined with defense evasion techniques (time stomping) to deploy a backdoored UltraVNC client for persistent remote access. The attack demonstrates a well-orchestrated approach with cloud-based distribution, connectivity verification, and careful timestamp manipulation to avoid detection.