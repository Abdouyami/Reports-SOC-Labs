# 🕸️ Incident Analysis Report — Web Shell Attack

* **Date of Analysis:** 28 August 2025
* **Analyst:** Belhamici Abderrahmane
* **Source:** [Blue Team Labs Online — *Network Analysis - Web Shell*](https://blueteamlabs.online/home/challenge/network-analysis-web-shell-d4d3a2821b)
* **Dataset:** Network packet capture (PCAP) and web server logs

---

## 1. Executive Summary

This report details the analysis of a sophisticated web shell attack involving systematic reconnaissance, vulnerability exploitation, and establishment of persistent remote access. The incident demonstrates a complete attack lifecycle from initial port scanning through web shell deployment to reverse shell establishment, showcasing advanced persistent threat (APT) tactics on a compromised web server.

The attacker successfully gained remote command execution capabilities and established a reverse shell connection for ongoing system control.

---

## 2. Case Overview

* **Incident Date (UTC):** February 7, 2021
* **Time Range of Attack:** 16:33:06 — 16:45:56 (≈ 12 minutes 50 seconds)
* **Compromised System:** `bob-appserver` (10.251.96.5)
* **Attacker Source:** 10.251.96.4
* **Attack Vector:** Web application vulnerability leading to file upload
* **Persistence Mechanism:** Web shell deployment and reverse shell establishment

---

## 3. Key Findings

### 3.1 Network Summary

* **Attacker IP:** `10.251.96.4`
* **Target System:** `10.251.96.5` (bob-appserver)
* **Compromised User:** `www-data` (web server process)
* **Open Services:** Port 22 (SSH), Port 80 (HTTP)
* **Attack Duration:** 12 minutes 50 seconds (highly efficient)

### 3.2 Attack Timeline

**February 7, 2021 16:33:06 UTC**
* **Phase:** Initial reconnaissance
* **Activity:** TCP SYN port scan conducted
* **Source:** 10.251.96.4:41675
* **Target:** 10.251.96.5
* **Port Range:** 1-1024
* **Duration:** < 1 second (automated scanning)
* **Results:** Identified ports 22 (SSH) and 80 (HTTP) as open

**February 7, 2021 16:34:05 UTC**
* **Phase:** Web application enumeration
* **Tool:** Gobuster 3.0.1
* **Duration:** 1 second (16:34:05 - 16:34:06)
* **Purpose:** Directory and file discovery on web server
* **Results:** Identification of potential upload vectors

**February 7, 2021 16:36:17 UTC**
* **Phase:** SQL injection testing
* **Tool:** sqlmap 1.4.7
* **Duration:** 1 minute 11 seconds (16:36:17 - 16:37:28)
* **Purpose:** Database vulnerability assessment
* **Results:** Potential identification of vulnerable parameters

**February 7, 2021 16:40:39 UTC**
* **Phase:** Web shell deployment
* **Activity:** Successful file upload exploitation
* **Upload Vector:** `editprofile.php`
* **Uploaded Shell:** `dbfunctions.php`
* **Shell Parameter:** `cmd` (for command execution)
* **First Command:** `id` (user identification)
* **Additional Commands:** `whoami`, Python reverse shell script

**February 7, 2021 16:42:35 UTC**
* **Phase:** Reverse shell establishment
* **Connection Type:** TCP reverse shell
* **Callback Destination:** 10.251.96.4:4422
* **Shell Type:** Interactive bash shell (`bash -i`)
* **Commands Executed:** `whoami`, `cd`, `ls`, `python`, `rm db`

**February 7, 2021 16:45:56 UTC**
* **Phase:** Final activity
* **Last observed:** Attacker activity termination

---

## 4. Technical Analysis

### 4.1 Port Scan Analysis

**Scan Characteristics:**
* **Type:** TCP SYN scan (stealth scanning technique)
* **Range:** Ports 1-1024 (standard service ports)
* **Speed:** Completed within seconds (automated tool usage)
* **Results:** Ports 22/TCP (SSH) and 80/TCP (HTTP) identified as open
* **Source Port:** 41675 (high ephemeral port)

### 4.2 Reconnaissance Phase

**Tool #1 - Gobuster 3.0.1:**
* **Purpose:** Web directory and file enumeration
* **Target:** HTTP service on port 80
* **Duration:** 1 second (very focused scan)
* **Likely Results:** Discovery of `editprofile.php` upload functionality

**Tool #2 - sqlmap 1.4.7:**
* **Purpose:** SQL injection vulnerability assessment
* **Duration:** 1 minute 11 seconds (thorough analysis)
* **Target:** Web application parameters
* **Results:** Potential identification of injectable parameters

### 4.3 Web Shell Deployment

**Upload Vector Analysis:**
* **Vulnerable File:** `editprofile.php`
* **Vulnerability Type:** Unrestricted file upload
* **Shell File:** `dbfunctions.php` (disguised as database functions)
* **Command Parameter:** `cmd`
* **Execution Method:** HTTP GET/POST requests with command parameter

**Web Shell Capabilities:**
* **Command Execution:** Direct OS command execution via `cmd` parameter
* **User Context:** `www-data` (web server user)
* **Initial Commands:**
  1. `id` - User identification and privilege assessment
  2. `whoami` - User context verification
  3. Python reverse shell script - Callback preparation

### 4.4 Reverse Shell Analysis

**Connection Details:**
* **Type:** TCP reverse shell connection
* **Direction:** 10.251.96.5 → 10.251.96.4:4422
* **Shell:** Interactive bash (`bash -i`)
* **Established:** 2021-02-07 16:42:35 UTC

**Commands Executed:**
1. `bash -i` - Interactive shell establishment
2. `whoami` - User verification (www-data)
3. `cd` - Directory navigation
4. `ls` - Directory listing
5. `python` - Python interpreter access
6. `rm db` - File cleanup/evidence removal

---

## 5. Network Indicators

### 5.1 Suspicious Network Activity

| Timestamp | Source IP | Destination IP | Activity | Protocol/Port |
|-----------|-----------|----------------|----------|---------------|
| 16:33:06 | 10.251.96.4 | 10.251.96.5 | Port scan (1-1024) | TCP SYN |
| 16:34:05-06 | 10.251.96.4 | 10.251.96.5 | Gobuster enumeration | HTTP/80 |
| 16:36:17-37:28 | 10.251.96.4 | 10.251.96.5 | sqlmap injection testing | HTTP/80 |
| 16:40:39 | 10.251.96.4 | 10.251.96.5 | Web shell upload | HTTP/80 |
| 16:42:35 | 10.251.96.5 | 10.251.96.4 | Reverse shell callback | TCP/4422 |

### 5.2 Timeline Analysis

* **Total Attack Duration:** 12 minutes 50 seconds
* **Reconnaissance Time:** ~4 minutes (port scan + tools)
* **Exploitation Time:** ~3 minutes (upload to shell)
* **Post-Exploitation:** ~3 minutes (reverse shell operations)
* **Attack Efficiency:** Highly automated and systematic

---

## 6. Indicators of Compromise (IOCs)

| Indicator | Type | Description |
|-----------|------|-------------|
| `10.251.96.4` | IP Address | Attacker source IP |
| `10.251.96.5` | IP Address | Compromised target (bob-appserver) |
| `editprofile.php` | Filename | Vulnerable upload script |
| `dbfunctions.php` | Filename | Deployed web shell |
| `4422/TCP` | Port | Reverse shell callback port |
| `cmd` | Parameter | Web shell command parameter |
| Gobuster 3.0.1 | Tool | Directory enumeration tool |
| sqlmap 1.4.7 | Tool | SQL injection testing tool |

---

## 7. Attack Methodology

### 7.1 Reconnaissance Phase
1. **Network Discovery:** TCP SYN scan of ports 1-1024 to identify running services
2. **Service Enumeration:** Gobuster used for web directory/file discovery
3. **Vulnerability Assessment:** sqlmap employed for SQL injection testing
4. **Target Selection:** HTTP service (port 80) chosen as primary attack vector

### 7.2 Initial Access
1. **Vulnerability Identification:** `editprofile.php` identified as file upload vector
2. **Web Shell Upload:** `dbfunctions.php` successfully uploaded through vulnerable script
3. **Command Execution Testing:** Initial `id` and `whoami` commands executed
4. **Capability Assessment:** Confirmed remote command execution as `www-data` user

### 7.3 Persistence and Escalation
1. **Reverse Shell Preparation:** Python script executed to establish callback
2. **Network Connection:** TCP reverse shell established on port 4422
3. **Interactive Access:** Interactive bash shell (`bash -i`) obtained
4. **System Exploration:** Directory navigation and file system reconnaissance
5. **Cleanup Activities:** Evidence removal (`rm db`) performed

---

## 8. Impact Assessment

### 8.1 Immediate Impact
* Complete compromise of web server (bob-appserver)
* Remote command execution capability established
* Interactive shell access obtained
* System reconnaissance and file manipulation performed

### 8.2 Potential Consequences
* **Data Breach:** Access to web application data and databases
* **Lateral Movement:** Potential pivot point to internal network
* **Service Disruption:** Web application availability compromise
* **Compliance Violations:** Unauthorized access to protected systems
* **Reputation Damage:** Security incident exposure

---

## 9. Recommendations

### 9.1 Immediate Actions
* **Isolate Compromised System:** Immediately isolate `bob-appserver` (10.251.96.5)
* **Block Attacker IP:** Implement firewall rules blocking 10.251.96.4
* **Remove Web Shell:** Delete `dbfunctions.php` and scan for additional backdoors
* **Patch Upload Vulnerability:** Fix or disable `editprofile.php` functionality
* **Reset Credentials:** Change all service accounts and administrative passwords
* **Network Monitoring:** Monitor for additional connections to port 4422

### 9.2 Forensic Analysis
* **Memory Dump:** Capture system memory for forensic analysis
* **Log Collection:** Preserve web server, system, and network logs
* **File System Analysis:** Comprehensive scan for malicious files and modifications
* **Network Traffic Analysis:** Deep packet inspection for additional IOCs
* **Timeline Reconstruction:** Complete incident timeline development

### 9.3 Long-term Security Measures
* **Input Validation:** Implement strict file upload validation and restrictions
* **Web Application Firewall:** Deploy WAF with file upload filtering
* **Network Segmentation:** Isolate web servers from critical internal systems
* **Intrusion Detection:** Deploy network and host-based intrusion detection
* **Regular Vulnerability Assessment:** Scheduled penetration testing and assessments
* **Security Awareness:** Developer training on secure coding practices

### 9.4 Detection and Response
* **Automated Monitoring:** Implement detection rules for:
  - Port scanning activity
  - Web shell deployment patterns
  - Reverse shell connections
  - Suspicious tool usage (Gobuster, sqlmap)
* **Incident Response Plan:** Update procedures for web shell incidents
* **Threat Hunting:** Proactive hunting for similar attack patterns

---

## 10. Lessons Learned

### 10.1 Attack Characteristics
* **Speed and Efficiency:** 12-minute attack demonstrates automated tooling and pre-planned methodology
* **Tool Sophistication:** Use of legitimate security tools (Gobuster, sqlmap) for reconnaissance
* **Systematic Approach:** Methodical progression from scanning to shell access
* **Stealth Techniques:** TCP SYN scanning and legitimate-looking file names

### 10.2 Security Gaps Identified
* **File Upload Vulnerabilities:** Unrestricted file upload in `editprofile.php`
* **Input Validation:** Insufficient validation of uploaded file types and content
* **Network Monitoring:** Lack of detection for port scanning and tool usage
* **Web Application Security:** Missing security controls for file upload functionality

### 10.3 Detection Failures
* **Port Scan Detection:** No alerting on systematic port scanning activity
* **Tool Usage:** Gobuster and sqlmap activity went undetected
* **Web Shell Upload:** File upload not monitored or restricted
* **Reverse Shell:** Outbound connection on port 4422 not blocked or detected

---

✅ **Conclusion:**
The analysis confirmed a highly efficient and systematic web server compromise through file upload vulnerability exploitation. The attacker demonstrated advanced techniques including stealth scanning, legitimate tool usage for reconnaissance, and establishment of persistent access through web shell and reverse shell deployment. The 12-minute attack timeline indicates automated tooling and extensive preparation. This incident highlights critical gaps in web application security, network monitoring, and incident response capabilities that require immediate attention to prevent similar compromises.