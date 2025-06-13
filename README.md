# Cybersecurity Portfolio Projects

This README contains summaries and findings from various cybersecurity and digital forensics projects.

---

## 📧 **Cyberattacks Lab – Email and Malware Analysis**

### Task 1: Email Header & Link Analysis
- **IP Analyzed:** `17.50.10.134` → Not flagged malicious by VirusTotal or IBM X-Force.
- **Domain:** `maxsgmail.top` → No DNS record; risk unknown.
- **Malicious URL:** `https://dtec.com.my/ash?email=ad@malware-traffic-analysis.net`
  - Flagged by 5 vendors (3 phishing, 2 malware).
- **SHA256 Hash:** Verified, not flagged.
- **Conclusion:** Email determined to be **phishing** due to malicious hyperlink.

### Task 2: Malware Sample Analysis
#### `Compliant_29769200-352`
- **VirusTotal:** 30 vendors flagged as malicious.
- **Hybrid Analysis & IBM X-Force:** High-risk file.
- **Conclusion:** Confirmed malicious script.

#### `ImportantSign_PDF`
- **VirusTotal:** 33 vendors flagged.
- **Hybrid Analysis:** Classified as Trojan.
- **MITRE ATT&CK Mapping:** Execution, Persistence, Privilege Escalation.
- **Conclusion:** File is a **Trojan** with several malicious capabilities.

#### `StolenImages.js`
- **VirusTotal:** Flagged by 21 vendors.
- **Hybrid Analysis:** Threat score 100/100.
- **MITRE ATT&CK:** Uses PowerShell, CLI, Hooking, Process Injection.
- **Conclusion:** Highly **malicious JavaScript trojan**.

---

## 🔐 **Web Application Security Project**

### DVWA Attacks
- **CSRF:** Password change through forged request.
- **SQL Injection:** Extracted usernames and hashed passwords via UNION SELECT.
- **XSS:** Reflected XSS via `<script>alert("this is me")</script>`.
- **Tool Used:** Burp Suite for HTTP interception and manipulation.

### Firewall Activity (ZoneAlarm)
- **Ping Block:** Kali Linux IP added to block list.
- **Website Block:** Facebook URL blocked via firewall.
- **Log Verification:** Ping attempts logged and blocked.

### Shodan
- **Used to identify vulnerable webcams and WAF (Web Application Firewall) presence.**

---

## 🛡️ **Incident Response Project (LetsDefend.io)**

### Alert: SOC145 - Ransomware Detected
- **Severity:** High
- **Action Taken:**
  - Analyzed file via VirusTotal (60 vendors flagged).
  - No endpoint/browser logs found (possible tampering).
  - Verified absence of C2 communication.
  - Case created, marked as **True Positive**.
- **Tool:** LetsDefend.io

---

## 🧪 **Digital Forensics Project**

### Task 1: Hash Generation
- **File:** `cyberkill.dd`
- **MD5:** `7dc4344d66763f4dee0766a6c2014770`
- **SHA1:** `97cdf0ada549d940ece0e9aa8f94aa86f725b9db`

### Task 2: File Recovery using Autopsy
- **Recovered:** 2 deleted PDF files.
- **Passwords Cracked:**
  - File 1: `salt12`
  - File 2: `cipher`
- **Tools:** Autopsy, crunch, pdfcrack

### Task 3: NIST Forensic Process
1. **Collection**
2. **Examination**
3. **Analysis**
4. **Reporting**

### Task 4: Legal Admissibility
- **Yes**, results can be court-admissible if data is collected legally and process is forensically sound.

---

## 📝 Notes
- Tools Used: Kali Linux, Autopsy, pdfcrack, crunch, Hybrid Analysis, VirusTotal, IBM X-Force, ZoneAlarm, Shodan, Burp Suite.
- Skills Demonstrated: Phishing detection, malware analysis, SQLi/XSS/CSRF exploitation, digital evidence handling, firewall rules, incident response.

---

## 🔗 Author
**Inayath Rahman**  
*Cybersecurity & DevOps Enthusiast*
