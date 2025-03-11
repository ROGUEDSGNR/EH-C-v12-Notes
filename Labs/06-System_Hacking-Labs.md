# Lab Tasks Checklist: System Hacking

## Lab 1: Gain Access to the System

### **Lab Scenario**

Leverage the information gathered in earlier phases to gain unauthorized access to the target system using various techniques such as password cracking, vulnerability exploitation, and social engineering.

### **Lab Objectives**

- Perform active online attacks to crack passwords using Responder.
- Audit system passwords using LOphtCrack.
- Exploit client-side vulnerabilities to establish remote sessions.
- Gain remote system access using tools like Armitage and Ninja Jonin.
- Perform buffer overflow attacks to access remote systems.

### **Lab Environment**

- **Virtual Machines**: Windows 11, Windows Server 2022, Parrot Security, Ubuntu
- **Tools**: Responder, LOphtCrack, Armitage, Ninja Jonin
- **Permissions**: Administrator privileges
- **Internet Connection**: Required

### **Checklist**

- [ ]  Set up all virtual machines as per lab requirements.
- [ ]  Run Responder to capture NTLM hashes.
- [ ]  Audit passwords with LOphtCrack for weak credentials.
- [ ]  Search and download exploits from Exploit DB or VulDB.
- [ ]  Use Metasploit to exploit vulnerabilities and establish VNC sessions.
- [ ]  Gain remote access using Armitage or Ninja Jonin.
- [ ]  Perform and analyze buffer overflow attacks.
- [ ]  Document all findings for review.

---

## Lab 2: Perform Privilege Escalation

### **Lab Scenario**

Exploit vulnerabilities and misconfigurations to elevate privileges from a regular user to an administrator or system-level access.

### **Lab Objectives**

- Use privilege escalation tools and exploit client-side vulnerabilities.
- Hack Windows systems using Metasploit and gather hash dumps with Mimikatz.
- Escalate privileges by exploiting Linux misconfigurations or vulnerabilities.

### **Lab Environment**

- **Virtual Machines**: Windows 11, Parrot Security, Ubuntu
- **Tools**: Metasploit, Mimikatz, pkexec, Linux tools for misconfigured NFS
- **Permissions**: Administrator privileges

### **Checklist**

- [ ]  Identify privilege escalation opportunities using Metasploit.
- [ ]  Run Mimikatz to dump credentials and hashes.
- [ ]  Exploit Linux misconfigured NFS for privilege escalation.
- [ ]  Bypass UAC and escalate privileges on Windows systems.
- [ ]  Document escalated privileges and exploited vulnerabilities.

---

## Lab 3: Maintain Remote Access and Hide Malicious Activities

### **Lab Scenario**

Establish persistence and stealth on compromised systems using tools and techniques to avoid detection.

### **Lab Objectives**

- Monitor systems using spyware tools like Power Spy or Spytech SpyAgent.
- Hide malicious files using NTFS streams and steganography.
- Use covert channels like Covert_TCP to maintain communication.

### **Lab Environment**

- **Virtual Machines**: Windows 11, Windows Server 2022, Parrot Security
- **Tools**: SpyAgent, NTFS Streams, OpenStego, Covert_TCP
- **Permissions**: Administrator privileges

### **Checklist**

- [ ]  Use Power Spy to monitor user activities.
- [ ]  Hide files using NTFS Streams.
- [ ]  Perform steganography to conceal data using OpenStego.
- [ ]  Establish covert channels with Covert_TCP.
- [ ]  Document actions and ensure stealth techniques are effective.

---

## Lab 4: Clear Logs to Hide Evidence of Compromise

### **Lab Scenario**

Cover tracks by erasing logs and system artifacts to avoid detection by system administrators or forensic investigators.

### **Lab Objectives**

- Clear audit logs using tools like Auditpol.
- Use Cleaner utilities to erase traces from Windows systems.
- Clear Linux logs via BASH commands.

### **Lab Environment**

- **Virtual Machines**: Windows 11, Ubuntu
- **Tools**: Auditpol, Cleaner, BASH
- **Permissions**: Administrator privileges

### **Checklist**

- [ ]  Use Auditpol to manage and clear audit policies.
- [ ]  Clear event logs from Windows systems.
- [ ]  Execute BASH commands to clear Linux system logs.
- [ ]  Test log-clearing effectiveness.
- [ ]  Document cleared evidence and remaining artifacts.

---
---

# Step-by-Step