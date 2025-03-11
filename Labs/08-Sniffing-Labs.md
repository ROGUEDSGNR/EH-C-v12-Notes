# Lab Tasks Checklist: Sniffing

## Lab 1: Perform Active Sniffing

### **Lab Scenario**

Perform active sniffing on a switched network using various techniques like MAC flooding, ARP poisoning, and DHCP starvation attacks to capture sensitive data packets.

### **Lab Objectives**

- Conduct MAC flooding to overload switch CAM tables.
- Execute a DHCP starvation attack to deny IP addresses to valid users.
- Perform ARP poisoning to redirect traffic.
- Launch a Man-in-the-Middle (MITM) attack using Cain & Abel.

### **Lab Environment**

- **Virtual Machines**: Windows 11, Windows Server 2022, Parrot Security, Ubuntu
- **Tools**: macof, Yersinia, arpspoof, Cain & Abel
- **Permissions**: Administrator access

### **Checklist**

#### MAC Flooding (macof)

- [ ]  Turn on Windows 11 and Parrot Security virtual machines.
- [ ]  Launch Wireshark to capture packets on Parrot Security.
- [ ]  Use `macof -i eth0` to flood the CAM table with fake MAC entries.
- [ ]  Verify packet flooding in Wireshark.

#### DHCP Starvation (Yersinia)

- [ ]  Open Yersinia on Parrot Security in interactive mode.
- [ ]  Perform a DHCP starvation attack by sending DHCP requests.
- [ ]  Observe the captured DHCP packets in Wireshark.

#### ARP Poisoning (arpspoof)

- [ ]  Run arpspoof on Parrot Security to poison ARP caches.
- [ ]  Capture and analyze ARP packets in Wireshark.
- [ ]  Verify MAC address duplication for target IP.

#### MITM Attack (Cain & Abel)

- [ ]  Launch Cain & Abel on Windows Server 2019.
- [ ]  Configure the ethernet interface for ARP poisoning.
- [ ]  Capture network traffic and extract sensitive information.
- [ ]  Document usernames and passwords intercepted.

---

## Lab 2: Perform Passive Sniffing

### **Lab Scenario**

Monitor and capture network traffic on a hub-based network without injecting packets, using tools to analyze and interpret the data.

### **Lab Objectives**

- Use Wireshark to capture and analyze unencrypted network traffic.
- Collect sensitive data such as usernames and passwords.

### **Lab Environment**

- **Virtual Machines**: Windows 11, Parrot Security
- **Tools**: Wireshark
- **Permissions**: Administrator access

### **Checklist**

- [ ]  Set the NIC to promiscuous mode on Parrot Security.
- [ ]  Start packet capture on the target interface using Wireshark.
- [ ]  Analyze protocols like HTTP, FTP, and SMTP for sensitive data.
- [ ]  Document all findings, including captured usernames and passwords.

---

## Lab 3: Detect Network Sniffing

### **Lab Scenario**

Identify network sniffing attempts on a switched LAN by detecting ARP poisoning, promiscuous mode, and other indicators of sniffing.

### **Lab Objectives**

- Detect ARP poisoning and promiscuous mode.
- Use Capsa Network Analyzer to monitor network activity.

### **Lab Environment**

- **Virtual Machines**: Windows 11, Parrot Security
- **Tools**: Capsa Network Analyzer, Wireshark
- **Permissions**: Administrator access

### **Checklist**

- [ ]  Use Capsa Network Analyzer to monitor ARP spoofing attacks.
- [ ]  Detect promiscuous mode by analyzing network response times.
- [ ]  Validate findings with Wireshark packet captures.

---
---

# Step-by-Step