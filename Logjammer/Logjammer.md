# LogJammer Sherlock Analysis Report

* **Date of Analysis:** September 12, 2025
* **Analyst:** Belhamici Abderrahmane
* **Source:** [HackTheBox Sherlock — *LogJammer*](https://app.hackthebox.com/sherlocks/LogJammer)
* **Dataset:** Windows Event Log files

---

## Overview
This analysis focuses on a Windows Event Log investigation of suspicious activities performed by the "CyberJunkie" user. The investigation examines multiple Windows Event Log files to identify potential malicious actions including firewall manipulation, scheduled task creation, audit policy changes, and antivirus detections during a security incident.

## Investigation Details
- **Challenge**: LogJammer Sherlock
- **Analysis Tool**: Splunk
- **Splunk Index**: htb-logjammer
- **Primary Timeline**: March 27, 2023 - February 14, 2024
- **Investigation Focus**: Windows Event Log Analysis for user "CyberJunkie"

---

## Event Log Files Analyzed

| File Name | Purpose | Key Events Captured |
|-----------|---------|-------------------|
| **Security.evtx** | Security-related events | User logons, audit policy changes, scheduled task creation |
| **Windows Firewall-Firewall.evtx** | Firewall configuration changes | Rule additions, policy modifications |
| **Windows Defender-Operational.evtx** | Antivirus detections and actions | Malware detection, quarantine actions |
| **PowerShell-Operational.evtx** | PowerShell script execution | Command execution, script block logging |
| **System.evtx** | System-level events | Event log clearing, system changes |

---

## Windows Event IDs Reference

| Event ID | Event Type | Source Log | Description |
|----------|------------|------------|-------------|
| **4624** | Successful Logon | Security | Logs successful user authentication |
| **2004** | Firewall Rule Added | Firewall | Logs addition of new firewall rules |
| **4719** | Audit Policy Change | Security | Logs changes to system audit policies |
| **4698** | Scheduled Task Created | Security | Logs creation of scheduled tasks |
| **1117** | Malware Detection | Defender | Logs antivirus threat detection and actions |
| **4104** | PowerShell Script Block | PowerShell | Logs PowerShell command execution |
| **401** | Event Log Cleared | System | Logs clearing of event log files |

---

## Task Analysis Summary

### User Authentication Analysis

#### Task 1: Initial User Logon
- **Question**: When did the cyberjunkie user first successfully log into his computer? (UTC)
- **Answer**: 27/03/2023 14:37:09
- **Event ID Used**: 4624
- **Source Log**: Security.evtx
- **Event Definition**: Successful logon events - logged when a user successfully authenticates to the system
- **Significance**: Establishes the initial timeline of user activity

### Firewall Configuration Tampering

#### Tasks 2-3: Firewall Rule Manipulation
- **Rule Addition Question**: The user tampered with firewall settings on the system. What is the Name of the firewall rule added?
- **Answer**: Metasploit C2 Bypass
- **Direction Question**: What's the direction of the firewall rule?
- **Answer**: Outbound
- **Timestamp**: 27/03/2023 14:44:43
- **Event ID Used**: 2004 (not 4946 as initially expected)
- **Source Log**: Windows Firewall-Firewall.evtx
- **Analysis Notes**: 
  - Event ID 4946 returned zero results, requiring keyword-based searching
  - Rule name strongly suggests Command & Control (C2) communication bypass
  - Outbound direction indicates attempts to establish external connections

### System Audit Policy Modification

#### Task 4: Audit Policy Changes
- **Question**: The user changed audit policy of the computer. What's the Subcategory of this changed policy?
- **Answer**: Other Object Access Events
- **Timestamp**: 27/03/2023 14:50:03
- **Event ID Used**: 4719
- **Source Log**: Security.evtx
- **Policy Definition**: Audit Other Object Access Events monitors operations with scheduled tasks, COM+ objects, and indirect object access requests
- **Significance**: Modification of audit policies suggests attempts to reduce logging of subsequent malicious activities

### Scheduled Task Creation and Configuration

#### Tasks 5-7: Malicious Scheduled Task
- **Task Name**: HTB-AUTOMATION
- **File Path**: C:\Users\CyberJunkie\Desktop\Automation-HTB.ps1
- **Command Arguments**: -A cyberjunkie@hackthebox.eu
- **Creation Time**: 27/03/2023 14:51:21
- **Event ID Used**: 4698
- **Source Log**: Security.evtx

#### Scheduled Task Configuration Details
| Attribute | Value |
|-----------|-------|
| **Author** | DESKTOP-887GK2L\CyberJunkie |
| **Description** | practice |
| **URI** | \HTB-AUTOMATION |
| **Start Time** | 2023-03-27T09:00:00 |
| **Schedule** | Daily execution |
| **Run Level** | LeastPrivilege |
| **Execution Time Limit** | 3 days (P3D) |

### Antivirus Detection and Response

#### Tasks 8-10: Malware Detection
- **Malware Identified**: SharpHound
- **File Path**: C:\Users\CyberJunkie\Downloads\SharpHound-v1.1.0.zip
- **Action Taken**: Quarantine
- **Detection Time**: 14/02/2024 14:42:48
- **Event ID Used**: 1117
- **Source Log**: Windows Defender-Operational.evtx

#### SharpHound Analysis
**Tool Definition**: SharpHound is a data collection tool for BloodHound, developed by SpecterOps, that maps Active Directory (AD) environments by gathering information on users, groups, sessions, and permissions.

**Detection Details**:
- **Container Path**: containerfile:_C:\Users\CyberJunkie\Downloads\SharpHound-v1.1.0.zip
- **Executable Path**: file:_C:\Users\CyberJunkie\Downloads\SharpHound-v1.1.0.zip->SharpHound.exe
- **Detection Origin**: Internet
- **Detection Type**: Concrete
- **Detection Source**: Downloads and attachments

### PowerShell Command Execution

#### Task 11: PowerShell Activity
- **Question**: What command was executed by the user?
- **Answer**: Get-FileHash -Algorithm md5 .\Desktop\Automation-HTB.ps1
- **Execution Time**: 14/02/2024 14:58:33
- **Event ID Used**: 4104
- **Source Log**: PowerShell-Operational.evtx
- **Purpose**: Computing MD5 hash of the scheduled task PowerShell script, likely for verification or anti-forensics

### Evidence Destruction

#### Task 12: Event Log Tampering
- **Question**: Which Event log file was cleared?
- **Answer**: Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
- **Clearing Time**: 14/02/2024 15:01:56
- **Event ID Used**: 401
- **Source Log**: System.evtx
- **Significance**: Attempt to destroy evidence of firewall rule modifications

---

## Attack Timeline

### Phase 1: Initial Access (March 27, 2023)
- **14:37:09** - CyberJunkie user successful logon
- **14:44:43** - Firewall rule "Metasploit C2 Bypass" added (outbound)
- **14:50:03** - Audit policy changed to "Other Object Access Events"
- **14:51:21** - Scheduled task "HTB-AUTOMATION" created

### Phase 2: Tool Acquisition & Analysis (February 14, 2024)
- **14:42:48** - SharpHound malware detected and quarantined
- **14:58:33** - PowerShell command executed to hash automation script
- **15:01:56** - Firewall event logs cleared

---

## TTPs (Tactics, Techniques, and Procedures)

### MITRE ATT&CK Framework Mapping

| Tactic | Technique | Evidence |
|--------|-----------|----------|
| **Persistence** | T1053.005 - Scheduled Task/Job | HTB-AUTOMATION task creation |
| **Defense Evasion** | T1562.004 - Disable/Modify System Firewall | Metasploit C2 Bypass rule |
| **Defense Evasion** | T1070.001 - Clear Windows Event Logs | Firewall log clearing |
| **Defense Evasion** | T1562.002 - Disable Windows Event Logging | Audit policy modification |
| **Discovery** | T1087 - Account Discovery | SharpHound AD enumeration tool |
| **Command and Control** | T1071.001 - Web Protocols | Outbound firewall bypass rule |

### Attack Patterns
1. **Initial Access**: User authentication to establish foothold
2. **Defense Evasion**: Firewall rule creation to bypass network restrictions
3. **Persistence**: Scheduled task creation for recurring execution
4. **Discovery**: SharpHound deployment for AD reconnaissance 
5. **Anti-Forensics**: Event log clearing to destroy evidence

---

## Key Findings

### IOCs (Indicators of Compromise)
- **User Account**: CyberJunkie
- **Firewall Rule**: "Metasploit C2 Bypass"
- **Scheduled Task**: HTB-AUTOMATION
- **Script Path**: C:\Users\CyberJunkie\Desktop\Automation-HTB.ps1
- **Email Parameter**: cyberjunkie@hackthebox.eu
- **Malware**: SharpHound-v1.1.0.zip

### Security Implications
1. **Firewall Bypass**: Creation of C2 bypass rule indicates attempted external communication
2. **Persistence Mechanism**: Daily scheduled task ensures continued access
3. **AD Reconnaissance**: SharpHound suggests preparation for lateral movement
4. **Audit Evasion**: Policy modifications reduce security visibility
5. **Evidence Destruction**: Log clearing demonstrates anti-forensic awareness

### Detection Gaps
- **PowerShell Logging**: Limited to single command execution
- **Network Monitoring**: No evidence of actual C2 communication
- **File System Monitoring**: Missing file creation/modification events
- **Process Execution**: Lack of process creation logging

---

## Conclusion
This investigation reveals a sophisticated multi-phase attack involving firewall manipulation, scheduled task persistence, and Active Directory reconnaissance. The attacker demonstrated advanced knowledge of Windows logging and attempted to evade detection through audit policy modification and log clearing. The presence of SharpHound indicates preparation for lateral movement within the Active Directory environment. The timeline spanning nearly 11 months suggests either a long-term persistent threat or multiple related incidents requiring further investigation.