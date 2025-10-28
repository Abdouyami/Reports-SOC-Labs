# 🛡️ Incident Analysis Report — Hammered SSH Honeypot Compromise

* **Date of Analysis:** October 03, 2025
* **Analyst:** Belhamici Abderrahmane
* **Source:** [CyberDefenders CTF — *Hammered*](https://cyberdefenders.org/blueteam-ctf-challenges/hammered/)
* **Target Environment:** Ubuntu Linux Web Server Honeypot
* **Dataset:** System logs (auth.log, kern.log, daemon.log, dpkg.log) and Apache logs
* **Incident Timeline:** March 16 - May 2, 2010

---

## 1. Executive Summary

This report details the analysis of a compromised Ubuntu Linux web server honeypot that experienced sustained SSH brute-force attacks resulting in multiple successful account compromises. The investigation reveals extensive unauthorized access, account creation activities, reconnaissance tool installation, and firewall rule modifications by multiple threat actors over a 47-day period.

The compromise demonstrates a multi-attacker scenario where the root account was successfully breached after 5,479 failed login attempts, followed by system reconnaissance, installation of scanning tools (nmap), creation of backdoor accounts, and firewall configuration changes. The honeypot also exposed critical MySQL database vulnerabilities with passwordless root accounts.

---

## 2. Case Overview

* **Incident Timeline:** March 16 - May 2, 2010 (47 days)
* **Target System:** Ubuntu 4.2.4-1ubuntu3 (app-1)
* **Attack Vector:** SSH brute-force attacks
* **Compromised Account:** root
* **Total Unique Attackers:** 6 successful IP addresses
* **Most Active Attacker:** 219.150.161.20
* **Attack Duration:** Sustained attacks over multiple weeks

---

## 3. Key Findings

### 3.1 System Information

* **Target Hostname:** app-1
* **Operating System:** Ubuntu 4.2.4-1ubuntu3
* **Primary Service Attacked:** SSH (sshd)
* **Web Server:** Apache 2 (running concurrently)
* **Database:** MySQL (with critical security issues)
* **Log Coverage:**
  - auth.log: Mar 16 08:12:04 - May 2 23:11:13
  - kern.log: Mar 16 08:09:58 - May 2 23:07:22
  - daemon.log: Mar 16 08:23:50 - May 2 23:06:00
  - dpkg.log: Apr 19 12:00:17 - Apr 26 04:53:23
  - Apache logs: Apr 19 06:36:15 - Apr 24 18:51:54

### 3.2 Attack Summary

* **Total Failed SSH Login Attempts:** 20,000+ (across all accounts)
* **Failed Root Login Attempts:** 5,479
* **Successful Root Logins:** 28
* **Total Successful Logins (All Accounts):** 120+
* **Unique Attacker IPs (Successful):** 6
* **Apache HTTP Requests Logged:** 365
* **Firewall Rules Added:** 6
* **User Accounts Created:** Multiple (including backdoor accounts)

---

## 4. Compromised Account Analysis

### 4.1 Root Account Compromise

**Attack Pattern:**
```
Failed password attempts: 5,479
Successful logins: 28
Compromise confirmed: YES
```

**Brute-Force Statistics by Account:**
```
14,481 - invalid (non-existent usernames)
 5,479 - root ⚠️ COMPROMISED
    44 - mysql
    38 - user1 (successful logins: 38)
    35 - games
    29 - backup
    27 - mail
    25 - nobody
    24 - user3 (successful logins: 24)
    23 - sshd
    23 - lp
    22 - dhg (successful logins: 22)
    22 - news
```

**Successful Authentication Summary:**
```
38 logins - user1
28 logins - root ⚠️
24 logins - user3
22 logins - dhg
 5 logins - user2
 1 login  - fido
```

The root account showed the clearest signs of compromise with 5,479 failed attempts followed by 28 successful authentications, indicating a successful brute-force campaign.

---

## 5. Attacker Infrastructure Analysis

### 5.1 Successful Attacker IP Addresses

**Most Active Attacker:** 219.150.161.20
- **Successful root logins:** 4
- **Last activity:** April 19, 2010 at 05:56:05 AM
- **Attack timeline:**
  ```
  Apr 19 05:41:44 - First successful login
  Apr 19 05:42:27 - Second login
  Apr 19 05:55:20 - Third login  
  Apr 19 05:56:05 - Final login (last observed)
  ```

**Additional Successful Attacker IPs:**
```
219.150.161.20  - 4 successful root logins ⚠️ MOST ACTIVE
188.131.23.37   - 4 successful root logins
190.166.87.164  - 3 successful root logins
122.226.202.12  - 2 successful root logins
121.11.66.70    - 2 successful root logins
10.0.1.2        - 1 successful root login (internal/suspicious)
```

Plus additional IPs with single successful authentications:
- 94.52.185.9
- 61.168.227.12
- 222.66.204.246
- 222.169.224.197
- 201.229.176.217
- 193.1.186.197
- 190.167.74.184
- 190.167.70.87
- 188.131.22.69
- 151.82.3.201
- 151.81.205.100
- 151.81.204.141

### 5.2 Geographic Distribution

The attacking IP addresses show global distribution, indicating a coordinated or opportunistic attack campaign from multiple regions.

---

## 6. Post-Compromise Activities

### 6.1 Reconnaissance Tool Installation

**Tool Deployed:** nmap (network scanning tool)
**Source:** dpkg.log package installation records
**Purpose:** Network reconnaissance and service enumeration
**Threat Level:** Critical - indicates active reconnaissance phase

### 6.2 Firewall Modification Activities

**Total Firewall Rules Added:** 6

**Timeline and Commands:**
```
Apr 24 19:25:37 - /sbin/iptables -L (listing existing rules)
Apr 24 20:03:06 - /sbin/iptables -A INPUT -p ssh -dport 2424 -j ACCEPT
Apr 24 20:03:44 - /sbin/iptables -A INPUT -p tcp -dport 53 -j ACCEPT
Apr 24 20:04:13 - /sbin/iptables -A INPUT -p udp -dport 53 -j ACCEPT
Apr 24 20:06:22 - /sbin/iptables -A INPUT -p tcp --dport ssh -j ACCEPT
Apr 24 20:11:00 - /sbin/iptables -A INPUT -p tcp --dport 53 -j ACCEPT
Apr 24 20:11:08 - /sbin/iptables -A INPUT -p tcp --dport 113 -j ACCEPT
```

**Analysis:**
- SSH port modification (2424) - likely backdoor or alternative access
- DNS port access (53) - TCP/UDP allowed
- IDENT port (113) - additional service exposure
- All executed with root privileges via sudo

**Additional iptables Activity:**
```
Apr 15 12:49:09 - user1 executed iptables configuration (via tee)
Apr 15 15:06:13 - user1 iptables configuration
Apr 15 15:17:45 - user1 iptables configuration
Apr 15 15:18:23 - user1 iptables configuration
```

### 6.3 Backdoor Account Creation

**Account Created:** wind3str0y
**Creation Date:** April 26, 2010 at 04:43:15
**Source:** auth.log
**Purpose:** Likely backdoor account for persistent access
**Threat Level:** Critical

---

## 7. Apache Web Server Activity

### 7.1 HTTP Traffic Analysis

**Total HTTP Requests:** 365
**Log Period:** April 19 - April 24, 2010
**Server:** Apache/2.4.56 (Debian)

### 7.2 Proxy Scanner Detection

**User-Agent Identified:** pxyscand/2.1
**Description:** Proxy scanning tool
**Purpose:** Attackers using proxy infrastructure to obscure origin
**Detection Method:** User-agent string analysis

**Additional User-Agents Observed:**
- WordPress/2.9.2 (legitimate or reconnaissance)
- Mozilla/5.0 (standard browser)
- Mozilla/4.0 (older browser/tool)
- Apple-PubSub/65.12.1 (Apple service)

---

## 8. Database Security Issues

### 8.1 Critical MySQL Vulnerability

**Warning Message:** "mysql.user contains 2 root accounts without password!"

**Frequency:** Multiple occurrences throughout incident timeline:
```
Mar 18 10:18:42
Mar 18 17:01:44
Mar 22 13:49:49
Mar 22 18:43:41
Mar 22 18:45:25
Mar 25 11:56:53
Apr 14 14:44:34
Apr 18 18:04:00
Apr 24 20:21:24
Apr 28 07:34:26
May  2 23:05:54
```

**Threat Assessment:** Critical
- Two root database accounts accessible without authentication
- Complete database access available to any attacker
- Persistent vulnerability throughout entire incident period

### 8.2 Additional Database Issues

**Secondary Warning:** "mysqlcheck has found corrupt tables"
**Occurrences:**
- Apr 14 14:44:36
- Apr 28 07:34:27

**Impact:** Potential data integrity issues or malicious database manipulation

---

## 9. Attack Timeline

| Date/Time | Event | Description |
|-----------|-------|-------------|
| Mar 16 08:12:04 | Initial Activity | First log entries, brute-force attacks begin |
| Mar 18 10:18:42 | MySQL Warning | First passwordless root account warning |
| Apr 15 12:49:09 | User1 Activity | Legitimate user modifying iptables configuration |
| Apr 19 05:41:44 | Root Compromise | First successful root login from 219.150.161.20 |
| Apr 19 05:56:05 | Peak Attack | Last observed login from most active attacker IP |
| Apr 19 - Apr 26 | Tool Installation | nmap reconnaissance tool deployed (dpkg.log) |
| Apr 24 19:25:37 | Firewall Recon | Attacker listing firewall rules |
| Apr 24 20:03:06 | Firewall Mod #1 | SSH port 2424 rule added |
| Apr 24 20:11:08 | Firewall Mod #6 | Final firewall rule modification |
| Apr 26 04:43:15 | Backdoor Account | wind3str0y account created |
| May 2 23:11:13 | Final Log Entry | Last recorded activity in auth.log |

---

## 10. Indicators of Compromise (IOCs)

### 10.1 Network Indicators

| Indicator | Type | Description | Threat Level |
|-----------|------|-------------|--------------|
| 219.150.161.20 | IP Address | Most active attacker (4 root logins) | Critical |
| 188.131.23.37 | IP Address | Secondary attacker (4 root logins) | Critical |
| 190.166.87.164 | IP Address | Tertiary attacker (3 root logins) | High |
| 122.226.202.12 | IP Address | Successful attacker (2 logins) | High |
| 121.11.66.70 | IP Address | Successful attacker (2 logins) | High |
| 10.0.1.2 | IP Address | Internal/suspicious IP with root access | Critical |
| pxyscand/2.1 | User-Agent | Proxy scanning tool | Medium |

### 10.2 Account Indicators

| Indicator | Type | Description | Threat Level |
|-----------|------|-------------|--------------|
| root | Username | Compromised system account | Critical |
| wind3str0y | Username | Backdoor account created Apr 26 | Critical |
| user1 | Username | 38 successful logins (legitimacy unclear) | Medium |
| user3 | Username | 24 successful logins (legitimacy unclear) | Medium |

### 10.3 System Indicators

| Indicator | Type | Description | Threat Level |
|-----------|------|-------------|--------------|
| nmap | Package | Network scanning tool installed | High |
| SSH port 2424 | Configuration | Non-standard SSH port configured | High |
| Passwordless MySQL root | Vulnerability | 2 root DB accounts without password | Critical |

---

## 11. Impact Assessment

### 11.1 System Compromise Severity

* **Full Root Access:** Complete system control achieved by multiple attackers
* **Persistent Access:** Backdoor accounts created for long-term access
* **Network Reconnaissance:** Scanning tools installed for further attacks
* **Firewall Manipulation:** Security controls modified to allow additional access
* **Database Exposure:** Complete database access without authentication

### 11.2 Honeypot Analysis Context

**Note:** This system appears to be intentionally configured as a honeypot for security research, which explains:
- Weak/default credentials allowing successful brute-force
- Passwordless database root accounts
- Extended attacker access without remediation
- Comprehensive logging of attacker activities

The compromise demonstrates real-world SSH brute-force attack patterns, multi-stage post-exploitation activities, and attacker techniques for maintaining persistent access.

---

## 12. Attack Techniques Observed

### 12.1 Initial Access
- **Technique:** SSH brute-force attacks
- **Scale:** 20,000+ failed attempts across multiple accounts
- **Success Rate:** Low but eventually successful
- **Persistence:** Sustained attacks over weeks

### 12.2 Post-Exploitation
- **Reconnaissance:** nmap tool installation
- **Persistence:** Backdoor account creation (wind3str0y)
- **Defense Evasion:** Firewall rule modifications
- **Lateral Movement Preparation:** Network scanning capabilities

### 12.3 Operational Security
- **Proxy Usage:** pxyscand/2.1 for anonymization
- **Multiple IPs:** Distributed attack infrastructure
- **Service Diversification:** Multiple access ports configured

---

✅ **Conclusion:**

The Hammered honeypot successfully captured a real-world SSH brute-force attack campaign spanning 47 days with 6 successful attacker IP addresses compromising the root account. The most active attacker (219.150.161.20) achieved 4 successful root logins on April 19, 2010, with the final observed access at 05:56:05 AM. Post-compromise activities included installation of the nmap reconnaissance tool, creation of the wind3str0y backdoor account on April 26 at 04:43:15, and addition of 6 firewall rules to enable persistent access. The investigation also revealed critical MySQL security vulnerabilities with 2 passwordless root database accounts persisting throughout the entire incident period. The honeypot data demonstrates typical attacker behavior patterns including reconnaissance, privilege maintenance, and infrastructure modification for sustained access.