# 🔍 Malware Analysis Report — Malicious Document Exploit

* **Date of Analysis:** 30 August 2025
* **Analyst:** Belhamici Abderrahmane
* **Source:** [LetsDefend — *Malicious Doc Challenge*](https://app.letsdefend.io/challenge/malicious-doic)
* **Sample:** factura.doc
* **SHA256 Hash:** `5a31c77293af2920d7020d5d0236691adcea2c57c2716658ce118a5cba9d4913`

---

## 1. Executive Summary

This report details the analysis of a malicious Microsoft Office document (`factura.doc`) that exploits **CVE-2017-11882**, a critical vulnerability in Microsoft Office Equation Editor. The document serves as an initial attack vector, downloading and executing additional malware payloads on the victim's system through exploitation of the legacy Microsoft Office component.

The attack demonstrates a sophisticated multi-stage infection chain utilizing a 17-year-old vulnerability that remains actively exploited by threat actors worldwide.

---

## 2. Sample Overview

* **File Name:** `factura.doc`
* **File Type:** Microsoft Office Document
* **SHA256 Hash:** `5a31c77293af2920d7020d5d0236691adcea2c57c2716658ce118a5cba9d4913`
* **Primary Vulnerability:** CVE-2017-11882
* **Delivery Method:** Likely phishing email attachment
* **Target Platform:** Microsoft Office (Windows)

---

## 3. Vulnerability Analysis

### 3.1 CVE-2017-11882 Technical Details

* **Vulnerability Type:** Stack Buffer Overflow in Microsoft Office Equation Editor
* **Affected Component:** EQNEDT32.EXE (Microsoft Equation Editor)
* **Component Age:** Compiled on November 9, 2000, over 17 years ago
* **CVSS Score:** 7.8 (High)
* **Attack Vector:** Exploited when processing specially crafted equation data (formulas data). Equation data is imported in Excel documents as an embedded OLE object
* **Impact:** Remote Code Execution with user privileges

### 3.2 Exploitation Mechanism

**Attack Flow:**
1. **Document Opening:** User opens malicious `factura.doc` file
2. **OLE Object Processing:** Excel program uses COM (Component Object Model) to process embedded equation object
3. **Buffer Overflow Trigger:** Specially crafted equation data triggers stack overflow in EQNEDT32.EXE
4. **Code Execution:** Malicious shellcode executes with user privileges
5. **Payload Download:** Acts as the initial stager that will download the loader (which will then download final payload) or the final payload directly

### 3.3 Persistence and Prevalence

* **Active Exploitation:** In 2020, during the Covid-19 pandemic, CVE-2017-11882 was actively used in malicious mailouts that exploited the topic of disrupted deliveries due to the medical restrictions. And now, in 2023, this vulnerability apparently still serves malefactors' purposes!
* **Delivery Methods:** Typically hidden within Microsoft Office files like xls, doc or rtf. These files are delivered through spam mails
* **Evasion Techniques:** Often employs anti-analysis techniques to prevent automated detection

---

## 4. Malware Analysis Results

### 4.1 Challenge Analysis Findings

Based on the LetsDefend challenge analysis:

**Exploit Type:** Remote Code Execution (RCE) via Microsoft Office Equation Editor
**CVE Identifier:** CVE-2017-11882
**Downloaded Malware:** `jan2.exe`
**C2 Communication:** `185.36.74.48:80` (HTTP communication)
**Dropped Executable:** `aro.exe`

### 4.2 Infection Chain

1. **Initial Vector:** Malicious Office document (factura.doc)
2. **Vulnerability Exploitation:** CVE-2017-11882 buffer overflow in Equation Editor
3. **Code Execution:** Shellcode execution within Office process
4. **Payload Download:** Secondary malware (`jan2.exe`) downloaded from `185.36.74.48:80`
5. **Persistence:** Executable (`aro.exe`) dropped to disk for continued access
6. **C2 Communication:** HTTP communication established with `185.36.74.48` on port 80

---

## 5. Dynamic Analysis Results

### 5.1 Shellcode Analysis (SCDBG Output)

**API Call Sequence:**
1. **GetProcAddress** - Resolves `ExpandEnvironmentStringsW` function
2. **ExpandEnvironmentStringsW** - Expands `%APPDATA%\aro.exe` to full path (destination buffer: 12fbd8, size: 104 bytes)
3. **LoadLibraryW** - Loads `UrlMon` library for internet functionality
4. **GetProcAddress** - Resolves `URLDownloadToFileW` function
5. **URLDownloadToFileW** - Downloads `http://seed-bc.com/juop4/plwr/mklo/rbn/jan2.exe` to `%APPDATA%\aro.exe`
6. **LoadLibraryW** - Loads `shell32` library
7. **GetProcAddress** - Resolves `ShellExecuteW` function
8. **ShellExecuteW** - Executes the downloaded file

**Technical Execution Details:**
* **Step Count:** 46,996 execution steps
* **Primary Memory:** Reading 0x1000 bytes from 0x401000
* **Memory Changes:** Detected at step 3059
* **Unpacked Data:** Dumped to `FACT~PFW.unpack`

### 5.2 Malware Download Chain

**Download URL Structure:**
* **Primary URL:** `http://seed-bc.com/juop4/plwr/mklo/rbn/jan2.exe`
* **Domain:** `seed-bc.com`
* **Path Structure:** `/juop4/plwr/mklo/rbn/` (obfuscated directory structure)
* **Payload:** `jan2.exe`
* **Local Storage:** `%APPDATA%\aro.exe` (renamed after download)

### 5.3 Technical Analysis

* **File Format:** Microsoft Office Document (.doc)
* **Embedded Objects:** Malicious OLE equation object
* **Exploit Payload:** Embedded shellcode targeting EQNEDT32.EXE
* **Anti-Analysis:** Potential evasion techniques to avoid sandboxing

### 5.2 Exploitation Timeline

**Pre-Exploitation:**
* Document delivered via phishing email
* User opens document (social engineering success)

**Exploitation Phase:**
* Equation Editor processes malicious OLE object
* Stack buffer overflow triggered in EQNEDT32.EXE
* Shellcode execution achieved with the following sequence:
  - Environment string expansion for `%APPDATA%\aro.exe`
  - Dynamic library loading (UrlMon, shell32)
  - Function resolution (URLDownloadToFileW, ShellExecuteW)
  - File download from `seed-bc.com`
  - Local execution of downloaded payload

**Post-Exploitation:**
* Remote payload (`jan2.exe`) download from `185.36.74.48:80` via HTTP
* File renamed and saved as `aro.exe` in user's AppData directory
* Automatic execution of dropped file using ShellExecuteW
* Establishment of persistent access through `aro.exe`

---

## 6. Indicators of Compromise (IOCs)

| Indicator | Type | Description |
|-----------|------|-------------|
| `factura.doc` | Filename | Malicious Office document |
| `5a31c77293af2920d7020d5d0236691adcea2c57c2716658ce118a5cba9d4913` | SHA256 | File hash |
| CVE-2017-11882 | CVE | Exploited vulnerability |
| `185.36.74.48:80` | Network | Command and control communication (HTTP) |
| `jan2.exe` | Filename | Downloaded secondary payload |
| `aro.exe` | Filename | Dropped executable on disk (%APPDATA%) |
| `seed-bc.com` | Domain | Malware hosting domain |
| `http://seed-bc.com/juop4/plwr/mklo/rbn/jan2.exe` | URL | Full download URL |
| `EQNEDT32.EXE` | Process | Vulnerable Microsoft Equation Editor component |

*Note: Additional IOCs from VirusTotal analysis and challenge results needed*

---

## 7. Attack Attribution and Context

### 7.1 Threat Landscape

* **Vulnerability Age:** 17+ years old component still actively exploited
* **Exploitation Trends:** Spammer groups actively exploiting CVE-2017-11882 to infect systems with information stealers Pony/FAREIT and FormBook
* **Campaign Patterns:** Excel document with an embedded file name that is randomized, which exploits CVE-2017-11882 to deliver and execute malware on a victim's device

### 7.2 Common Payloads

Based on research, CVE-2017-11882 exploits commonly deliver:
* **Information Stealers:** Pony/FAREIT, FormBook, RedLine
* **Remote Access Tools (RATs):** Various backdoor families
* **Banking Trojans:** Credential harvesting malware
* **Ransomware:** In some campaign variants

---

## 8. Impact Assessment

### 8.1 Immediate Impact

* **System Compromise:** Full user-level access to victim system
* **Code Execution:** Arbitrary code execution capabilities
* **Data Access:** Potential access to user files and credentials
* **Network Access:** Possible lateral movement within network

### 8.2 Potential Consequences

* **Data Theft:** Personal and corporate information exfiltration
* **Credential Compromise:** Banking and authentication data theft
* **System Persistence:** Long-term backdoor access
* **Network Propagation:** Potential spread to other systems

---

## 9. Recommendations

### 9.1 Immediate Actions

* **System Isolation:** Isolate affected systems from network immediately
* **File Removal:** Remove `factura.doc`, `jan2.exe`, and `aro.exe` from system
* **Process Termination:** Kill any running instances of malicious processes
* **Network Blocking:** Block communication to `185.36.74.48:80`
* **Credential Reset:** Change all passwords on potentially affected accounts
* **Full System Scan:** Comprehensive malware scan and cleanup

### 9.2 Long-term Security Measures

* **Office Security:** Update to modern Microsoft Office versions with security patches
* **Email Security:** Implement advanced email filtering to block malicious documents
* **User Training:** Educate users about malicious document threats
* **Application Control:** Consider application whitelisting and document analysis tools
* **Network Segmentation:** Limit potential lateral movement capabilities

### 9.3 Detection and Response

* **Signature Development:** Create detection rules for CVE-2017-11882 exploitation attempts
* **Behavioral Analysis:** Monitor for suspicious Office process behavior and EQNEDT32.EXE execution
* **Network Monitoring:** Detect HTTP communications to suspicious IPs like `185.36.74.48`
* **File Monitoring:** Alert on creation of suspicious executables and downloads to `%APPDATA%` directory
* **URL Filtering:** Block access to `seed-bc.com` and similar suspicious domains
* **API Monitoring:** Monitor for suspicious API call sequences (ExpandEnvironmentStringsW → URLDownloadToFileW → ShellExecuteW)
* **Memory Analysis:** Detect shellcode execution patterns in Office processes
* **Incident Response:** Test and refine document-based attack response procedures

---

## 10. Lessons Learned

* **Sophisticated Shellcode:** The malware uses advanced API resolution and dynamic library loading techniques
* **Environment Variable Abuse:** Uses `%APPDATA%` directory for stealth file placement
* **File Renaming:** Downloads as `jan2.exe` but renames to `aro.exe` for evasion
* **HTTP-based C2:** Uses standard HTTP protocol for communication stealth
* **Multi-Stage Infection:** Complex chain from document → shellcode → download → execution

---

✅ **Conclusion:**
The analysis of `factura.doc` confirms exploitation of the critical CVE-2017-11882 vulnerability in Microsoft Office Equation Editor. The malicious document successfully downloaded `jan2.exe` from `185.36.74.48:80` and dropped `aro.exe` to establish persistence on the victim system. This 17-year-old component continues to serve as an effective attack vector for threat actors, demonstrating the persistent threat posed by unpatched legacy software components. The incident emphasizes the importance of comprehensive patch management, advanced email security controls, and behavioral monitoring for Office applications in modern cybersecurity defense strategies.