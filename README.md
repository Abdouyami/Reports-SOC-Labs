# 🔒 SOC Lab Reports Portfolio

**Analyst:** Belhamici Abderrahmane  
**Repository:** Collection of Security Operations Center (SOC) Lab Analysis Reports

---

## 📋 Overview

This repository contains a comprehensive collection of cybersecurity incident analysis reports completed through various SOC labs and blue team training platforms. Each report demonstrates practical skills in threat detection, log analysis, network forensics, malware analysis, and incident response methodologies.

These reports showcase hands-on experience analyzing real-world attack scenarios, demonstrating proficiency in identifying attack vectors, reconstructing attack chains, and documenting security incidents following industry-standard practices.

---

## 🎯 Skills Demonstrated

### Core Competencies
- **Incident Response & Analysis** - Complete attack lifecycle investigation from initial compromise to data exfiltration
- **Log Analysis** - Windows Event Logs, Sysmon, Linux system logs (auth.log, kern.log, syslog), web server logs
- **Network Forensics** - PCAP analysis, traffic pattern identification, protocol analysis
- **Malware Analysis** - Behavioral analysis, IOC identification, payload extraction
- **Threat Detection** - Signature and anomaly-based detection, attack pattern recognition
- **Email Security Analysis** - Email header analysis, phishing detection, attachment analysis
- **Active Directory Security** - Kerberos attack analysis, domain controller investigation
- **Web Application Security** - SQL injection, file upload vulnerabilities, authentication bypass

### Tools & Platforms Used
- **Analysis Tools:** Splunk, Wireshark, Volatility, Sysinternals, Zeek, ELK Stack
- **Platforms:** CyberDefenders CTF, Blue Team Labs Online (BTLO), HackTheBox Sherlock, Unit42
- **File Formats:** PCAP, EVTX, EML, CSV, Log files, SQLite databases

---

## 📁 Reports Catalog

### 🌐 Web Application Attacks

#### [Bumblebee - phpBB Forum Compromise](./Bumblebee/Bumblebee.md)
- **Platform:** HackTheBox Sherlock
- **Analysis Date:** September 7, 2025
- **Focus:** Web application credential brute-force, privilege escalation, database exfiltration
- **Techniques:** Social engineering, fake login forms, administrative access exploitation

#### [Web Shell Attack](./Web%20Shell%20Attack/Web%20Shell%20Attack.md)
- **Platform:** Blue Team Labs Online
- **Analysis Date:** August 28, 2025
- **Focus:** Web shell deployment, reverse shell establishment, network reconnaissance
- **Techniques:** Port scanning, vulnerability exploitation, persistence mechanisms

#### [WordPress Compromise](./Wordpress%20Compromise/WordPress%20Compromise.md)
- **Focus:** WordPress security incident analysis

#### [Tomcat Takeover](./Tomcat%20Takeover/Tomcat%20Takeover.md)
- **Focus:** Apache Tomcat server compromise analysis with network traffic and log data

---

### 🪟 Windows & Active Directory

#### [Campfire-1 - Kerberoasting Attack](./Campfire%201/Campfire%201.md)
- **Platform:** HackTheBox Sherlock
- **Analysis Date:** September 15, 2025
- **Focus:** Active Directory Kerberoasting attack analysis
- **Techniques:** SPN enumeration, ticket harvesting, credential cracking
- **Dataset:** Windows Event Logs, PowerShell operational logs, Prefetch files

#### [Unit42 - UltraVNC Backdoor](./Unit42/Unit42.md)
- **Platform:** HackTheBox Sherlock (Unit42)
- **Analysis Date:** September 11, 2025
- **Focus:** Backdoored UltraVNC malware campaign
- **Techniques:** Process injection, malicious binary execution, network communication
- **Dataset:** Sysmon logs

#### [Meerkat](./Meerkat/Meerkat.md)
- **Focus:** Windows-based security incident analysis

---

### 🐧 Linux System Analysis

#### [Hammered - SSH Honeypot Compromise](./Hammered%20-%20Linux%20Analysis/Hammered%20-%20Linux%20Analysis.md)
- **Platform:** CyberDefenders CTF
- **Analysis Date:** October 3, 2025
- **Focus:** Linux SSH brute-force attacks, account compromise, system reconnaissance
- **Techniques:** Credential stuffing, backdoor account creation, firewall manipulation
- **Dataset:** Linux system logs (auth.log, kern.log, daemon.log, dpkg.log), Apache logs

---

### 📧 Email Security & Phishing

#### [Email Phishing Analysis - The Planets Prestige](./Email%20Phishing%20Analysis/Email%20Phishing%20Analysis.md)
- **Platform:** Blue Team Labs Online
- **Analysis Date:** August 30, 2025
- **Focus:** Advanced phishing campaign with social engineering
- **Techniques:** Email spoofing, domain impersonation, multi-stage payload delivery
- **Dataset:** EML format email with attachments

#### [Brute Force Attack](./Brute%20Force/Brute%20Force.md)
- **Focus:** Credential brute-force attack analysis

---

### 🦠 Malware & Advanced Threats

#### [Hawkeye Keylogger Campaign](./Howkeye%20Analysis/Hawkeye%20Analysis.md)
- **Platform:** CyberDefenders CTF
- **Analysis Date:** August 30, 2025
- **Focus:** Hawkeye Keylogger Reborn v9 malware analysis
- **Techniques:** Phishing email, malicious executable download, credential exfiltration
- **Dataset:** Network packet capture (PCAP)

#### [Malware Compromise](./Malware%20Compromise/Malware%20Compromise.md)
- **Focus:** General malware compromise incident analysis

#### [Malicious Document](./Malicious%20Doc/Malicious%20Doc.md)
- **Focus:** Malicious document analysis (likely Office macros, PDF exploitation)

---

### 💾 Digital Forensics

#### [BTLO Suspicious USB Device](./BTLO%20Suspicious%20USB/BTLO%20Suspicious%20USB.md)
- **Platform:** Blue Team Labs Online
- **Analysis Date:** September 30, 2025
- **Focus:** Physical attack vector via USB drive
- **Techniques:** Autorun exploitation, PDF-based malware, JavaScript exploitation
- **Dataset:** USB drive contents (autorun.inf, malicious PDF)

#### [Logjammer](./Logjammer/Logjammer.md)
- **Focus:** Log analysis and security incident investigation

---

## 📊 Report Statistics

- **Total Reports:** 15+ detailed incident analysis reports
- **Platform Coverage:** 4 major training platforms
- **Attack Vectors Analyzed:** 10+ distinct attack methodologies
- **Operating Systems:** Windows, Linux
- **Analysis Duration:** August - October 2025

---

## 🔍 Analysis Methodology

Each report follows a structured investigative approach:

1. **Executive Summary** - High-level overview of the incident
2. **Case Overview** - Timeline, affected systems, attack vectors
3. **Key Findings** - Detailed technical analysis and evidence
4. **Attack Chain Reconstruction** - Step-by-step attack progression
5. **Indicators of Compromise (IOCs)** - IP addresses, hashes, domains, file paths
6. **Mitigation Recommendations** - Security controls and best practices

---

## 🎓 Training Platforms

- **[CyberDefenders CTF](https://cyberdefenders.org/)** - Blue team CTF challenges
- **[Blue Team Labs Online (BTLO)](https://blueteamlabs.online/)** - Practical SOC exercises
- **[HackTheBox Sherlock](https://app.hackthebox.com/sherlocks)** - Advanced blue team scenarios
- **[Unit42](https://www.paloaltonetworks.com/unit42)** - Threat intelligence and analysis

---

## 💼 Professional Value

This portfolio demonstrates:

✅ **Technical Expertise** - Hands-on experience with industry-standard tools and platforms  
✅ **Analytical Thinking** - Systematic approach to complex security incidents  
✅ **Documentation Skills** - Professional report writing following SOC standards  
✅ **Continuous Learning** - Active engagement with cybersecurity training platforms  
✅ **Threat Landscape Awareness** - Experience with diverse attack vectors and techniques

---

## 📝 Notes

- All reports are based on lab environments and training scenarios
- Analysis dates reflect when reports were completed
- Reports follow real-world SOC incident response documentation standards
- Techniques and methodologies are based on industry best practices

---

## 🤝 Contact

**Analyst:** Belhamici Abderrahmane

---

*This repository serves as a portfolio demonstrating practical cybersecurity analysis skills through hands-on SOC lab reports. Each report represents a complete investigation from initial alert to final documentation.*

---

**Last Updated:** October 2025

