# Lab Tasks Checklist: Hacking Web Applications

## Lab 1: Footprint the Web Infrastructure

### **Lab Scenario**

Gather complete information about the target web application, its related components, and vulnerabilities in specific parts of its architecture.

### **Lab Objectives**

- Perform web application reconnaissance using Nmap and Telnet.
- Identify web server directories using Nmap and Gobuster.
- Detect load balancers using dig and lbd.
- Use OWASP ZAP for web spidering.
- Perform vulnerability scanning using Vega.

### **Lab Environment**

- **Virtual Machines**: Windows 11, Windows Server 2022, Parrot Security
- **Tools**: Nmap, Telnet, Gobuster, OWASP ZAP, Vega
- **Permissions**: Administrator access

### **Checklist**

#### Reconnaissance with Nmap and Telnet

- [ ]  Run Nmap to perform port scanning on the target website.
- [ ]  Perform banner grabbing using Telnet to identify server details.

#### Identify Directories with Gobuster

- [ ]  Use Gobuster to brute-force web server directories using a wordlist.

#### Detect Load Balancers

- [ ]  Use the dig command to identify multiple IP addresses indicating load balancers.
- [ ]  Confirm results with lbd for DNS and HTTP load balancing.

#### Perform Web Spidering

- [ ]  Launch OWASP ZAP and execute automated scans.
- [ ]  Observe spidering results under the Spider tab for URLs and vulnerabilities.

#### Vulnerability Scanning

- [ ]  Run Vega to identify vulnerabilities like SQL injection and XSS.
- [ ]  Document results for later analysis.

---

## Lab 2: Perform Web Application Attacks

### **Lab Scenario**

Simulate attacks on a web application to test its security by exploiting vulnerabilities such as brute-force login, XSS, and parameter tampering.

### **Lab Objectives**

- Conduct brute-force attacks with Burp Suite.
- Identify and exploit XSS vulnerabilities with PwnXSS.
- Exploit file upload and remote command execution vulnerabilities.
- Hack WordPress using WPScan.

### **Lab Environment**

- **Virtual Machines**: Windows 11, Windows Server 2022, Parrot Security
- **Tools**: Burp Suite, PwnXSS, WPScan
- **Permissions**: Administrator access

### **Checklist**

#### Brute-Force Login with Burp Suite

- [ ]  Intercept login requests with Burp Suite Proxy.
- [ ]  Perform a brute-force attack using a list of credentials.

#### Exploit XSS Vulnerabilities

- [ ]  Use PwnXSS to identify reflected and stored XSS.
- [ ]  Test injection payloads in vulnerable fields.

#### File Upload Vulnerabilities

- [ ]  Attempt to upload malicious scripts in unrestricted upload fields.
- [ ]  Bypass restrictions using obfuscated payloads.

#### Hack WordPress

- [ ]  Enumerate WordPress plugins and users with WPScan.
- [ ]  Exploit vulnerabilities in outdated plugins using Metasploit.

---

## Lab 3: Detect and Mitigate Vulnerabilities

### **Lab Scenario**

Test web applications for vulnerabilities and learn how to apply fixes and secure them from exploitation.

### **Lab Objectives**

- Detect clickjacking vulnerabilities using ClickjackPoc.
- Analyze application security with N-Stalker.
- Implement basic mitigation strategies.

### **Lab Environment**

- **Virtual Machines**: Windows 11, Parrot Security
- **Tools**: ClickjackPoc, N-Stalker
- **Permissions**: Administrator access

### **Checklist**

#### Clickjacking Detection

- [ ]  Use ClickjackPoc to scan for clickjacking vulnerabilities.
- [ ]  Open the generated PoC in a browser to confirm vulnerability.

#### Application Security with N-Stalker

- [ ]  Run N-Stalker to scan for application-level vulnerabilities.
- [ ]  Review generated reports and prioritize fixes.

#### Mitigation

- [ ]  Add X-Frame-Options headers to prevent clickjacking.
- [ ]  Apply input validation for user inputs to mitigate XSS and parameter tampering.

---
---

# Step-by-Step

