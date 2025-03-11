# Lab Tasks Checklist: Evading IDS, Firewalls, and Honeypots

## Lab 1: Detect Intrusions Using Various Tools

### **Lab Scenario**

An Intrusion Detection System (IDS) monitors network traffic for suspicious activities. This lab focuses on using IDS tools to detect malicious activities and analyze intrusion patterns.

### **Lab Objectives**

- Detect intrusions using Snort.
- Identify malicious traffic using ZoneAlarm FREE FIREWALL.
- Monitor attacks with HoneyBOT.

### **Lab Environment**

- **Virtual Machines**: Windows 11, Windows Server 2022, Windows Server 2019, Parrot Security
- **Tools**: Snort, ZoneAlarm FREE FIREWALL, HoneyBOT
- **Permissions**: Administrator access
- **Internet Connection**: Required

### **Checklist**

#### Snort

1. [ ]  Install Snort on the Windows Server 2019 VM.
2. [ ]  Configure `snort.conf` to include target network variables and rule paths.
3. [ ]  Add custom rules to detect ICMP traffic.
4. [ ]  Test Snort by generating ping requests to the target machine.
5. [ ]  Verify triggered alerts in the Snort logs.

#### ZoneAlarm FREE FIREWALL

1. [ ]  Install ZoneAlarm on Windows 11.
2. [ ]  Configure logging to monitor inbound and outbound traffic.
3. [ ]  Simulate malicious activity and observe alerts.

#### HoneyBOT

1. [ ]  Deploy HoneyBOT on Parrot Security.
2. [ ]  Set up the application to listen on common ports.
3. [ ]  Simulate attacks and analyze captured packets.

---

## Lab 2: Evade Firewalls Using Various Techniques

### **Lab Scenario**

Attackers often bypass firewalls using techniques like tunneling, packet fragmentation, or spoofing. This lab demonstrates how to perform and detect these evasion methods.

### **Lab Objectives**

- Evade firewalls using Nmap.
- Use HTTP/FTP tunneling for bypassing rules.
- Bypass antivirus software with Metasploit templates.
- Use BITSAdmin to bypass firewall restrictions.

### **Lab Environment**

- **Virtual Machines**: Windows 11, Windows Server 2022, Parrot Security
- **Tools**: Nmap, HTTP/FTP tunneling tools, Metasploit, BITSAdmin
- **Permissions**: Administrator access
- **Internet Connection**: Required

### **Checklist**

#### Nmap Evasion

1. [ ]  Use Nmap to scan with fragmented packets: `nmap -f <target_IP>`.
2. [ ]  Test spoofed scans: `nmap -S <spoofed_IP> <target_IP>`.
3. [ ]  Observe firewall logs for bypass attempts.

#### HTTP/FTP Tunneling

1. [ ]  Set up HTTP tunneling using an open-source tool.
2. [ ]  Establish an FTP tunnel to bypass firewall restrictions.
3. [ ]  Test connectivity through the tunnels.

#### Metasploit Templates

1. [ ]  Use Metasploit to generate obfuscated payloads.
2. [ ]  Deploy payloads and bypass antivirus detection.
3. [ ]  Monitor for successful evasion.

#### BITSAdmin

1. [ ]  Use BITSAdmin to download malicious files bypassing firewall checks.
2. [ ]  Verify file download and execution.

---

## Lab 3: Analyze and Evade Honeypots

### **Lab Scenario**

Honeypots are traps designed to detect unauthorized access. This lab focuses on identifying and evading honeypots deployed in a network.

### **Lab Objectives**

- Identify honeypots using fingerprinting techniques.
- Evade honeypots with cloaking methods.

### **Lab Environment**

- **Virtual Machines**: Windows 11, Parrot Security
- **Tools**: Nmap, Honeypot Detection Tools
- **Permissions**: Administrator access
- **Internet Connection**: Required

### **Checklist**

#### Honeypot Detection

1. [ ]  Scan the target network for unusual responses using Nmap scripts.
2. [ ]  Analyze banners and headers for honeypot indications.

#### Evading Honeypots

1. [ ]  Implement timing and payload changes to bypass honeypot detection.
2. [ ]  Use decoy traffic to confuse honeypot systems.
3. [ ]  Document all evasion attempts and results.

---
---

# Step-by-Step