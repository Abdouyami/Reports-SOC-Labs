# 🛡️ Incident Analysis Report — Hawkeye Keylogger Campaign

* **Date of Analysis:** 30 August 2025
* **Analyst:** Belhamici Abderrahmane
* **Source:** [CyberDefenders CTF — *Hawkeye*](https://cyberdefenders.org/blueteam-ctf-challenges/hawkeye/)
* **Dataset:** Network packet capture (PCAP)

---

## 1. Executive Summary

This report details the analysis of a malicious network activity associated with the **Hawkeye Keylogger** malware family. The PCAP evidence demonstrates the compromise of a victim system through phishing, the download of a malicious executable, and subsequent data exfiltration to an attacker-controlled mail server.

The infection chain shows how the malware performed reconnaissance, communicated with external servers, and exfiltrated sensitive banking credentials every 10 minutes over a period of approximately 1 hour.

---

## 2. Case Overview

* **Incident Date (UTC):** April 10, 2019
* **Time Range of Capture:** 20:37:54 — 21:40:04 (1h 2m 10s)
* **First Packet Captured:** 2019-04-10 20:37:54 UTC
* **Victim System:** `BEIJING-5CD1-PC` (Windows 10 6.3)
* **Malware:** *Hawkeye Keylogger — Reborn v9*
* **Initial Infection Vector:** Phishing email leading to download of malicious file

---

## 3. Key Findings

### 3.1 Network Summary

* **Total Packets Captured:** 4521
* **Capture Duration:** 01:02:10 (1 hour, 2 minutes, 10 seconds)
* **Most Active Host (MAC):** `00:08:02:1c:47:ae` (Hewlett-Packard)
* **NIC Manufacturer:** Hewlett-Packard (HQ: Palo Alto, USA)
* **Internal Hosts Observed (/24 Network):** 3
* **DNS Server (Internal):** `10.4.10.4`
* **Victim Operating System:** Windows 10 6.3

### 3.2 Infection Flow

1. **Phishing & Download**
   * **Timeline:** April 10, 2019 @ 20:37:54 UTC
   * Victim accessed malicious domain: `proforma-invoices.com`
   * Downloaded file: `tkraw_Protected99.exe`
   * File classified as *Hawkeye* trojan with **keylogging** capability
   * **MD5 Hash:** `71826ba081e303866ce2a2534491a2f7`
   * Hosted on a **LiteSpeed web server** at `217.182.138.150` (France)

2. **Reconnaissance**
   * **Timeline:** April 10, 2019 @ 20:38:15 UTC
   * Host: `BEIJING-5CD1-PC` querying domain: `whatismyipaddress.com`
   * Malware identified victim's public IP: `173.66.146.112` (United States)
   * Purpose: External IP identification for C2 communication setup

3. **Command & Control Setup**
   * **Timeline:** April 10, 2019 @ 20:38:16 UTC
   * Communication established with mail server: `23.229.162.69` (United States)
   * Email Server Software: **Exim 4.91**
   * Authenticated using: `sales.del@macwinlogistics.in`
   * Authentication Password: `Sales@23`

4. **Data Exfiltration**
   * **Initial Exfiltration:** April 10, 2019 @ 20:38:16 UTC
   * **Second Transmission:** April 10, 2019 @ 21:38:43 UTC  
   * **Final Activity:** April 10, 2019 @ 21:40:04 UTC
   * **Exfiltration Interval:** Every **10 minutes**
   * **Target Email:** `sales.del@macwinlogistics.in`

---

## 4. Stolen Data

### 4.1 Banking Credentials Compromised

* **Bank of America Credentials:**
  * Username: `roman.mcguire`
  * Password: `P@ssw0rd$`

### 4.2 Additional Data Exfiltrated

* User authentication credentials
* System information from victim machine
* Keylogged data including passwords and personal information
* Email account details and system activity logs

---

## 5. Malware Analysis

### 5.1 Hawkeye Keylogger Details

* **Malware Family:** Hawkeye Keylogger (Reborn v9)
* **Type:** Trojan / Keylogger / Information Stealer
* **Delivery Method:** Phishing email with malicious link
* **Persistence:** Continuous keylogging and periodic data transmission

### 5.2 Capabilities Observed

* **Keylogging:** Capture of user keystrokes including banking credentials
* **Data Exfiltration:** SMTP-based transmission to attacker-controlled email
* **Credential Theft:** Banking, email, and system authentication data
* **Reconnaissance:** Public IP identification and system profiling
* **Stealth Communication:** Use of legitimate email protocols for C2

### 5.3 Network Behavior

* **C2 Protocol:** SMTP (legitimate email protocol for stealth)
* **Data Transmission:** Base64 encoded stolen credentials
* **Communication Pattern:** Regular 10-minute intervals
* **Persistence:** Maintained connection for over 1 hour
* **Geographic Distribution:** France (hosting) → USA (victim) → USA (exfiltration)

---

## 6. Timeline Analysis

| Time (UTC) | Event | Description |
|------------|-------|-------------|
| 20:37:54 | Initial Infection | Access to `proforma-invoices.com`, download of `tkraw_Protected99.exe` |
| 20:38:15 | Reconnaissance | Query to `whatismyipaddress.com` for external IP identification |
| 20:38:16 | C2 Establishment | First communication with mail server `23.229.162.69` |
| 20:38:16 | Data Exfiltration #1 | Banking credentials sent to `sales.del@macwinlogistics.in` |
| 21:38:43 | Data Exfiltration #2 | Repeated transmission of collected data (10-minute interval) |
| 21:40:04 | Final Activity | Last observed mail server communication |

---

## 7. Indicators of Compromise (IOCs)

| Indicator | Type | Description |
|-----------|------|-------------|
| `proforma-invoices.com` | Domain | Malware distribution site |
| `217.182.138.150` | IP | Hosting server (France) |
| `tkraw_Protected99.exe` | File | Malicious executable |
| `71826ba081e303866ce2a2534491a2f7` | MD5 | File hash |
| `whatismyipaddress.com` | Domain | Reconnaissance query |
| `23.229.162.69` | IP | Attacker's mail server (USA) |
| `sales.del@macwinlogistics.in` | Email | Exfiltration account |
| `Sales@23` | Password | Email authentication credential |
| `BEIJING-5CD1-PC` | Hostname | Compromised victim system |
| `173.66.146.112` | IP | Victim's public IP address |

---

## 8. Network Infrastructure Analysis

### 8.1 Victim Environment

* **Network Segment:** Private /24 network with 3 active hosts
* **DNS Infrastructure:** Internal DNS server at `10.4.10.4`
* **Most Active System:** MAC `00:08:02:1c:47:ae` (Hewlett-Packard NIC)
* **Operating System:** Windows 10 version 6.3
* **Hostname:** `BEIJING-5CD1-PC`

### 8.2 Attack Infrastructure

* **Malware Hosting:** France (`217.182.138.150`) - LiteSpeed web server
* **Data Exfiltration:** United States (`23.229.162.69`) - Exim 4.91 mail server
* **Geographic Spread:** Multi-national infrastructure for resilience

---

## 9. Impact Assessment

### 9.1 Immediate Impact

* **Banking Credential Theft:** Bank of America login credentials compromised
* **Keylogging Activity:** Continuous monitoring of user keystrokes
* **Data Breach:** Personal and financial information exfiltrated
* **System Compromise:** Complete workstation compromise

### 9.2 Potential Consequences

* **Financial Loss:** Unauthorized banking access with stolen credentials
* **Identity Theft:** Personal information compromise
* **Corporate Data Exposure:** Business information potentially compromised
* **Lateral Movement:** Potential for network-wide compromise
* **Compliance Violations:** Potential regulatory implications for data breach

---

## 10. Recommendations

### 10.1 Immediate Actions

* **Credential Reset:** Immediately change Bank of America credentials for `roman.mcguire`
* **System Isolation:** Isolate `BEIJING-5CD1-PC` from network
* **Malware Removal:** Full system scan and Hawkeye removal
* **Network Blocking:** Block all identified IOCs (IPs, domains, email addresses)
* **Email Security:** Block `sales.del@macwinlogistics.in` and monitor for similar accounts

### 10.2 Long-term Security Measures

* **Endpoint Security:** Deploy/update anti-malware solutions to detect Hawkeye variants
* **Email Security:** Implement advanced email security filters to block phishing attempts
* **Multi-Factor Authentication:** Enable MFA for all banking and critical email accounts
* **User Training:** Conduct phishing awareness training for all staff
* **Network Monitoring:** Implement network monitoring for suspicious SMTP communications

### 10.3 Detection and Response

* **Signature Development:** Create detection rules for Hawkeye keylogger behavior
* **Email Monitoring:** Monitor for suspicious SMTP authentication patterns
* **File Hash Monitoring:** Block known malicious file hashes
* **DNS Monitoring:** Monitor for reconnaissance queries to IP identification services
* **Incident Response:** Test and refine incident response procedures

---

## 11. Lessons Learned

* **Phishing Effectiveness:** Social engineering remains highly effective attack vector
* **Legitimate Protocol Abuse:** SMTP used for covert C2 communication
* **Rapid Compromise:** Full credential theft achieved within minutes of infection
* **International Infrastructure:** Attackers use geographically distributed infrastructure
* **Periodic Exfiltration:** Regular data transmission patterns aid in detection
* **Reconnaissance Importance:** Malware performs systematic environment reconnaissance

---

✅ **Conclusion:**
The PCAP analysis confirmed a sophisticated **Hawkeye Keylogger (Reborn v9)** infection delivered via phishing campaign. The malware successfully exfiltrated banking credentials through SMTP communication with an attacker-controlled mail server, demonstrating the effectiveness of credential-focused attacks. The incident emphasizes the critical need for comprehensive phishing defenses, endpoint monitoring, credential protection measures, and rapid incident response capabilities. The 10-minute exfiltration interval and use of legitimate email protocols highlight the importance of behavioral analysis in malware detection.