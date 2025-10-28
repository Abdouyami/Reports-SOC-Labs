# 🔒 Incident Analysis Report — WordPress Compromise

* **Date of Analysis:** 30 August 2025
* **Analyst:** Belhamici Abderrahmane
* **Source:** [Blue Team Labs Online — *Log Analysis - Compromised WordPress*](https://blueteamlabs.online/home/challenge/log-analysis-compromised-wordpress-ce000f5b59)
* **Dataset:** Web server access logs

---

## 1. Executive Summary

This report details the analysis of a successful compromise of a WordPress website through exploitation of vulnerable plugins and subsequent web shell deployment. The attack demonstrates a multi-stage intrusion involving reconnaissance, exploitation of known vulnerabilities, privilege escalation through admin panel access, and persistence establishment via web shell deployment.

The attacker successfully gained administrative access to the WordPress installation and deployed a PHP web shell for persistent access to the compromised system.

---

## 2. Case Overview

* **Incident Date (UTC):** January 2024
* **Time Range of Analysis:** Multiple log entries spanning several days
* **Target System:** WordPress website
* **Attack Vector:** Plugin vulnerability exploitation
* **Persistence Mechanism:** PHP web shell deployment

---

## 3. Key Findings

### 3.1 Attack Timeline

**January 12 @ 15:56:41 UTC**
* **Phase:** Plugin activation - Contact Form 7
* Plugin `contact-form-7` was activated
* Vulnerable version ≤ 5.3.1 with RCE capabilities

**January 12 @ 15:57:07 UTC**
* **Phase:** Plugin activation - Simple File List  
* Plugin `simple-file-list` was activated
* Vulnerable version ≤ 4.2.2 with RCE capabilities
* Both plugins have vulnerabilities leading to Remote Code Execution

**January 14 @ 05:42:34 UTC**
* **Phase:** External reconnaissance and interaction
* External IP activity: `119.241.22.191` - Japan
* Interacting with both plugins
* Crawling file paths on `172.21.0.3`

**January 14 @ 05:54:14 UTC**
* **Phase:** Admin token identification
* Identified admin login token
* Full URI: `/wp-login.php?itsec-hb-token=adminlogin`

**January 14 @ 06:01:41 UTC**
* **Phase:** WordPress scanning
* IP: `119.241.22.121` - Japan
* Tool used: **WPScan** (WordPress Scanner)
* Active reconnaissance of WordPress installation

**January 14 @ 06:08:31 UTC**
* **Phase:** Secondary attacker involvement
* IP: `103.69.55.212` - Taiwan
* Crawling plugins on `172.21.0.3`
* Coordinated attack from multiple sources

**January 14 @ 06:26:53 UTC**
* **Phase:** Successful exploitation
* IP: `119.241.22.121` - Japan
* **Exploited Plugin:** `simple-file-list`
* **Uploaded File:** `fr34k.png` (malicious payload)

**January 14 @ 06:30:11 UTC**
* **Phase:** Web shell access
* IP: `103.69.55.212` - Taiwan  
* GET request towards `fr34k.php`
* Successful web shell deployment and access

### 3.2 Exploitation Details

**Contact Form 7 Vulnerability - CVE-2020-35489**
* **CVE Identifier:** CVE-2020-35489
* **Vulnerability Type:** Unrestricted File Upload leading to Remote Code Execution (RCE)
* **CVSS Score:** 9.8 (Critical)
* **Affected Plugin:** Contact Form 7 (WordPress)
* **Vulnerable Versions:** < 5.3.2 (before version 5.3.2)
* **Patched Version:** 5.3.2 and above
* **Root Cause:** Inadequate filename validation allowing special characters in uploaded filenames
* **Attack Vector:** Attackers could simply upload files of any type, bypassing all restrictions placed regarding the allowed upload-able file types on a website
* **Impact Scale:** An estimated 5 million websites were affected

**Simple File List Vulnerability - CVE-2020-36847**
* **CVE Identifier:** CVE-2020-36847
* **Vulnerability Type:** Unauthenticated Arbitrary File Upload leading to Remote Code Execution (RCE)
* **Affected Plugin:** Simple File List (WordPress)
* **Vulnerable Versions:** ≤ 4.2.2 (version 4.2.2 and below)
* **Root Cause:** Vulnerable to Remote Code Execution in versions up to, and including, 4.2.2 via the rename function which can be used to rename uploaded PHP code with a png extension to use a php extension
* **Attack Vector:** Unauthenticated file upload with file extension manipulation
* **Authentication Required:** None - pre-authentication vulnerability

### 3.3 Tools and Techniques Used

Based on analysis, the attacker employed:
1. **Reconnaissance tools** for initial system profiling
2. **Exploitation frameworks** targeting WordPress plugin vulnerabilities
3. **Web shell deployment** for persistent access

---

## 4. Technical Analysis

### 4.1 Vulnerability Analysis (CVE-2020-35489)

**Technical Details:**

**Contact Form 7 (CVE-2020-35489):**
* **Weakness Type:** CWE-434 (Unrestricted Upload of File with Dangerous Type)
* **Attack Mechanism:** By exploiting this vulnerability, attackers could simply upload files of any type, bypassing all restrictions placed regarding the allowed upload-able file types on a website
* **Discovery Timeline:** An estimated 5 million websites were affected

**Simple File List (CVE-2020-36847):**
* **Weakness Type:** CWE-434 (Unrestricted Upload of File with Dangerous Type)  
* **Attack Mechanism:** The Simple-File-List Plugin for WordPress is vulnerable to Remote Code Execution in versions up to, and including, 4.2.2 via the rename function which can be used to rename uploaded PHP code with a png extension to use a php extension
* **Authentication Required:** This allows unauthenticated attackers to execute code

**Attack Flow (Based on Exploit Code Analysis):**
1. **Target Identification:** Attacker identifies WordPress site running both vulnerable plugins
2. **Primary Exploitation:** Simple File List chosen as attack vector due to unauthenticated access
3. **Malicious File Upload:** Creates PHP payload disguised as PNG file (`fr34k.png`)
4. **File Manipulation:** Exploits rename function to convert `fr34k.png` to `fr34k.php`
5. **Code Execution:** Executes uploaded PHP shell for remote command execution

### 4.2 Admin Panel Access

* **Compromised URI:** `/wp-login.php?itsec-hb-token=adminlogin` (including authentication token)
* **Method:** Exploitation of password reset functionality
* **Result:** Administrative access to WordPress dashboard

### 4.3 Plugin Exploitation

**Primary Target:** Simple File List plugin (CVE-2020-36847)
* **Exploitation Method:** Unauthenticated arbitrary file upload with file extension manipulation via rename function
* **Attack Capability:** Direct RCE through unauthenticated malicious file upload and rename
* **File Extension Bypass:** Upload as PNG, rename to PHP using vulnerable rename function

**Secondary Vulnerable Plugin:** Contact Form 7 (CVE-2020-35489)  
* **Vulnerability Type:** Unrestricted file upload bypassing file type restrictions
* **CVSS Score:** 9.8 - Critical severity
* **Impact:** Could allow upload of any file type, potentially leading to RCE

**Attack Execution:**
* Attacker chose Simple File List as the primary attack vector due to unauthenticated access
* Successfully uploaded `fr34k.png` and manipulated it to `fr34k.php` web shell
* Contact Form 7 remained as backup exploitation option

### 4.3 Web Shell Deployment

* **Shell File:** `fr34k.php` (PHP web shell)
* **Final Access Response:** HTTP 200 (successful access maintained)
* **Purpose:** Persistent backdoor access to compromised system

---

## 5. Network Indicators

### 5.1 Suspicious IP Addresses

| IP Address | Location/Notes | Activity |
|------------|----------------|----------|
| `119.241.22.121` | External attacker IP (Japan) | Primary attack source, WPScan, exploitation |
| `103.69.55.212` | Secondary IP (Taiwan) | Web shell access, coordinated attack |
| `172.21.0.3` | Target/victim network | Plugin crawling target |

### 5.2 Timeline Analysis

* **Total Duration:** ~47 minutes 37 seconds (concentrated attack)
* **Attack Pattern:** Multi-stage coordinated attack from Japan and Taiwan
* **Peak Activity:** January 14, systematic exploitation sequence
* **Tool Usage:** WPScan for reconnaissance, Simple File List exploitation
* **Coordination:** Two distinct IP addresses working in sequence

---

## 6. Indicators of Compromise (IOCs)

| Indicator | Type | Description |
|-----------|------|-------------|
| `fr34k.php` | Filename | Deployed PHP web shell |
| `fr34k.png` | Filename | Initial malicious upload (disguised as PNG) |
| `119.241.22.121` | IP Address | Primary attacker IP (Japan) |
| `103.69.55.212` | IP Address | Secondary malicious IP (Taiwan) |
| `/wp-login.php?itsec-hb-token=adminlogin` | URI | Compromised admin login |
| Simple File List ≤ 4.2.2 | Plugin Version | Vulnerable component (CVE-2020-36847) |
| Contact Form 7 < 5.3.2 | Plugin Version | Vulnerable component (CVE-2020-35489) |
| CVE-2020-36847 | CVE | Simple File List - Unauthenticated Arbitrary File Upload |
| CVE-2020-35489 | CVE | Contact Form 7 - Unrestricted File Upload |
| WPScan | Tool | WordPress vulnerability scanner used |

---

## 7. Attack Methodology

### 7.1 Initial Access
1. **Plugin Deployment:** Both Contact Form 7 (≤5.3.1) and Simple File List (≤4.2.2) plugins activated with known RCE vulnerabilities
2. **Reconnaissance:** WPScan tool used to identify WordPress installation and vulnerable plugins  
3. **Target Selection:** Simple File List chosen as primary attack vector

### 7.2 Exploitation Phase
1. **Coordinated Attack:** Two IP addresses (Japan: 119.241.22.121, Taiwan: 103.69.55.212) working in sequence
2. **Plugin Crawling:** Systematic examination of plugin paths and functionality
3. **File Upload Exploit:** Successful upload of `fr34k.png` through Simple File List vulnerability
4. **File Conversion:** Malicious PNG converted/renamed to `fr34k.php` web shell

### 7.3 Persistence and Access
1. **Web Shell Deployment:** `fr34k.php` successfully deployed and accessible
2. **Admin Token Discovery:** Identification of admin login token for potential privilege escalation
3. **Coordinated Access:** Secondary IP (Taiwan) successfully accessing the deployed web shell
4. **Duration:** Entire attack completed within 47 minutes 37 seconds

---

## 8. Impact Assessment

### 8.1 Immediate Impact
* Complete compromise of WordPress website
* Administrative access obtained
* Persistent backdoor established

### 8.2 Potential Consequences
* Website defacement or manipulation
* Data theft from website database
* Use as pivot point for further network compromise
* SEO poisoning and reputation damage

---

## 9. Recommendations

### 9.1 Immediate Actions
* **Critical Priority - Remove Web Shell:** Immediately delete `fr34k.php` and scan for additional backdoors
* **Update Vulnerable Plugins:** 
  - Remove or upgrade Simple File List plugin to version > 4.2.2 immediately
  - Upgrade Contact Form 7 to version ≥ 5.3.2 immediately
* **Reset All Credentials:** Change all WordPress administrative passwords and database credentials
* **Block Malicious IPs:** Implement firewall rules blocking identified attacker IPs (119.241.22.121, 103.69.55.212)
* **File System Audit:** Comprehensive scan of wp-content/uploads/simple-file-list/ directory for malicious files

### 9.2 Long-term Security Measures
* **Plugin Management:** Implement automated plugin update mechanisms
* **Security Monitoring:** Deploy WordPress security plugins and monitoring
* **Access Logging:** Enhanced logging and monitoring of admin panel access
* **Backup Strategy:** Regular, tested backups stored securely offline
* **Security Hardening:** Implement WordPress security best practices

### 9.3 Detection and Response
* **WAF Implementation:** Deploy Web Application Firewall with WordPress-specific rules
* **Log Analysis:** Regular analysis of access logs for suspicious patterns
* **Vulnerability Management:** Regular security scanning and assessment
* **Incident Response:** Develop and test incident response procedures

---

## 10. Vulnerability Impact Assessment

### 10.1 Vulnerability Impact Assessment

**CVE-2020-36847 (Simple File List):**
* **Affected Plugin:** Simple File List for WordPress  
* **Affected Versions:** 4.2.2 and below
* **Authentication Required:** None - unauthenticated vulnerability
* **Attack Complexity:** Low - file upload with rename function exploitation
* **Impact:** Complete site takeover through RCE

**CVE-2020-35489 (Contact Form 7):**
* **Affected Plugin:** Contact Form 7 for WordPress
* **Affected Versions:** < 5.3.2
* **CVSS Score:** 9.8 (Critical)
* **Impact Scale:** An estimated 5 million websites affected
* **Attack Method:** Unrestricted file upload bypassing all file type restrictions
* **Exploit Availability:** Public exploit code available

### 10.2 Lessons Learned

* Multiple vulnerable plugins exponentially increase attack surface - both Contact Form 7 and Simple File List had RCE vulnerabilities
* Coordinated attacks from multiple geographic locations (Japan/Taiwan) indicate sophisticated threat actors
* Speed of attack (47 minutes) demonstrates automated tooling and pre-planned methodology
* WPScan usage shows attackers are using legitimate security tools for malicious reconnaissance
* File upload vulnerabilities remain extremely dangerous, especially when no authentication is required
* Web shells provide persistent access that can be difficult to detect
* Multi-stage attacks require comprehensive monitoring and response

---

✅ **Conclusion:**
The analysis confirmed a successful multi-stage compromise of a WordPress website through Simple File List plugin exploitation (CVE-2020-35489). The attacker leveraged a pre-authentication arbitrary file upload vulnerability to gain initial access, then achieved administrative access and deployed a persistent PHP web shell backdoor. This incident highlights the critical importance of maintaining updated plugins, especially those handling file operations, implementing comprehensive monitoring, and having rapid incident response capabilities for WordPress environments. The availability of public exploit code makes this vulnerability particularly dangerous for unpatched installations.