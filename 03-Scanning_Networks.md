# Scanning Networks | Attack Phase 2

> #TLDR
 >Scanning involves gathering detailed information about a target through advanced and aggressive reconnaissance techniques. Network scanning refers to a set of procedures used to identify hosts, ports, and services within a network. It is also employed to discover active machines and identify the operating systems running on target machines. This phase is crucial for intelligence gathering, as it allows an attacker to create a profile of the target organization. During scanning, the attacker seeks to obtain information such as accessible IP addresses, the target’s operating system and system architecture, and the ports and services running on each computer.
> 
> The primary purpose of scanning is to discover exploitable communication channels, probe as many listeners as possible, and track those that are responsive or useful to the attacker’s needs. In this phase, the attacker attempts to find various entry points into the target system and uncover additional details to identify any configuration weaknesses. The information gathered during scanning is then used to develop an attack strategy.

---

# Info Obtained in Network Scanning 
###### #Objectives

- **Discovering Live Hosts, IP Addresses, and Open Ports**: 
	Identify live hosts within the network, their IP addresses, and the open ports on these hosts. Using the open ports, the attacker determines the best way to gain access to the system.

- **Fingerprinting OS and System Architecture**:
	Identify the operating system and system architecture of the target, known as fingerprinting. This allows an attacker to formulate an attack strategy based on the vulnerabilities of the detected OS.

- **Identifying Running Services**:
	Discover the services running or listening on the target system. This gives the attacker an indication of potential vulnerabilities associated with those services that can be exploited to gain access.

- **Identifying Specific Applications or Versions**:
	Determine the specific applications or versions of services running on the target system.

- **Identify Vulnerabilities in Network Systems**:
	Detect weaknesses in any of the network systems. This information allows an attacker to compromise the target system or network through various exploits.

---

# Types of Scanning

- **Port Scanning**:
    - Lists the open ports and services.
    - Involves sending a sequence of messages to the target computer's TCP and UDP ports to check the services running or in a listening state.
    - Provides information about the operating system and applications in use.
    - Can reveal active services that might allow unauthorized access or exploit vulnerabilities.

- **Network Scanning**:
    - Lists active hosts and IP addresses.
    - Identifies active hosts on a network to either attack them or assess network security.

- **Vulnerability Scanning**:
    - Identifies known weaknesses.
    - Uses a scanning engine and a catalog of common files with known vulnerabilities and exploits.
    - Checks for backup files, directory traversal exploits, and other vulnerabilities.
    - Ensures server safety by analyzing the exploit list and server responses.
    - Targets vulnerabilities that can often be fixed with updated security patches and a clean web document structure.

---
# TCP Communication Flags

The TCP header contains several flags that control data transmission across a TCP connection. Six TCP control flags manage the connection between hosts and provide instructions to the system. Four of these flags (SYN, ACK, FIN, and RST) are responsible for the establishment, maintenance, and termination of a connection. The remaining two flags (PSH and URG) provide additional instructions to the system. Each flag is 1 bit in size, making the TCP Flags section 6 bits in total. When a flag value is set to "1," that flag is activated.

![[Pasted image 20240704103804.png]]

# TCP/IP Communication

SYN --- SYN/ACK --- ACK --- OPEN/FIN/RST

TCP is connection-oriented, meaning it prioritizes establishing a connection before transferring data between applications. This connection establishment is achieved through a three-way handshake.

A TCP session begins using the three-way handshake mechanism:
- To initiate a TCP connection, the source (10.0.0.X:21) sends a SYN packet to the destination (10.0.0.Y:21).
- Upon receiving the SYN packet, the destination responds with a SYN/ACK packet back to the source.
- The ACK packet confirms the arrival of the initial SYN packet to the source.
- Finally, the source sends an ACK packet in response to the SYN/ACK packet from the destination.
- This completes the "OPEN" connection, allowing communication between the source and destination, which continues until one of them sends a "FIN" (Finish) or "RST" (Reset) packet to close the connection.

---

# Phase 1 Host Discovery

Scanning involves gathering information about systems that are "alive" and responding on the network. Host discovery is the primary task in the network scanning process. To perform a complete scan and identify open ports and services, it is necessary to check for live systems. Host discovery provides an accurate status of the systems in the network, allowing an attacker to avoid scanning every port on every system within a list of IP addresses to determine if the target host is up. 

Host discovery is the first step in network scanning. This section highlights methods for checking for live systems in a network using various ping scan techniques. It also discusses how to perform a ping sweep to detect live hosts/systems, along with various ping sweep tools.

![[Pasted image 20240704195640.png]]
## Host Discovery Scanning

 -  **ARP Ping Scan**
 -  **UDP Ping Scan**
 -  **ICMP Ping Scan**
	 - ICMP ECHO Ping
	 - ICMP ECHO Ping Sweep
		- ICMP Timestamp Ping
	- ICMP Address Mask Ping
- **TCP Ping Scan**
	- TCP SYN Ping 
	- TCP ACK Ping
- **IP Protocol Scan**

Host discovery techniques can be used to identify active/live hosts within a network. As an ethical hacker, it is crucial to understand the various types of host discovery methods. 

Here are some common host discovery techniques:

| Scanning Technique          | Nmap Commands                            | Request                                                              | Response                                                                                                          | Advantages                                                                                                                                              |
| --------------------------- | ---------------------------------------- | -------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ARP Ping Scan               | `nmap -sn -PR <Target IP Address>`       | ARP request probe                                                    | ARP response - Host is active <br>No response - Host is inactive                                                  | - More efficient and accurate than other host discovery techniques <br> - Useful for system discovery, especially for large address spaces              |
| UDP Ping Scan               | `nmap -sn -PU <Target IP Address>`       | UDP request                                                          | UDP response - Host is active <br>Error messages (host/network unreachable or TTL exceeded) - Host is inactive    | - Detects systems behind firewalls with strict TCP filtering                                                                                            |
| ICMP ECHO Ping Scan         | `nmap -sn -PE <Target IP Address>`       | ICMP ECHO request                                                    | ICMP ECHO reply - Host is active <br>No response - Host is inactive                                               | - Useful for locating active devices or checking if ICMP messages pass through a firewall <br>**Disadvantage:** Does not work on Windows-based networks |
| ICMP ECHO Ping Sweep        | `nmap -sn -PE <Target IP Address Range>` | ICMP ECHO requests to multiple hosts                                 | ICMP ECHO reply - Host is active <br>No response - Host is inactive                                               | - Determines live hosts from a range of IP addresses <br> - Useful for inventory of live systems <br>**Disadvantage:** Oldest and slowest method        |
| ICMP Timestamp Ping Scan    | `nmap -sn -PP <Target IP Address>`       | ICMP timestamp request                                               | Timestamp reply to each timestamp request <br>Response may depend on time value configuration by the target admin | - Alternative to conventional ICMP ECHO ping scan <br>- Determines if the target host is live, even if ICMP ECHO pings are blocked                      |
| ICMP Address Mask Ping Scan | `nmap -sn -PM <Target IP Address>`       | ICMP address mask request                                            | Address mask response from destination host, may depend on subnet value configuration by the target admin         | - Alternative to conventional ICMP ECHO ping scan <br>- Determines if the target host is live, even if ICMP ECHO pings are blocked                      |
| TCP SYN Ping Scan           | `nmap -sn -PS <Target IP Address>`       | Empty TCP SYN request                                                | ACK response - Host is active <br>No response - Host is inactive                                                  | - Useful to determine if the host is active without creating any connection <br>- Leaves no traces for detection                                        |
| TCP ACK Ping Scan           | `nmap -sn -PA <Target IP Address>`       | Empty TCP ACK request                                                | RST response - Host is active <br>No response - Host is inactive                                                  | - Maximizes the chances of bypassing the firewall                                                                                                       |
| IP Protocol Ping Scan       | `nmap -sn -PO <Target IP Address>`       | IP ping requests using different IP protocols (ICMP, IGMP, TCP, UDP) | Any response - Host is active <br>No response - Host is inactive                                                  | - Sends different packets using different IP protocols in the hope of receiving a response indicating that a host is online                             |
> [!NOTE]
> that <font color="#adff23">we're not scanning for ports and services yet</font>, thus the use of Nmap option `-sn`. 
> 
> Ports/Services/etc will be scanned once we stipulate the *live* hosts we want to attack (in the next phase).

---

# Phase 2 Port/Service Scanning Techniques

![[Pasted image 20240709163816.png]]

### Port Scanning Techniques

Port scanning techniques can be categorized based on the type of protocol used for communication within the network. Here are the different categories and methods:

#### <span style="background:#d4b106"> TCP Scanning </span>

1. **Open TCP Scanning Methods**
   - **TCP Connect/Full-open Scan**

2. **Stealth TCP Scanning Methods**
   - **Half-open Scan**
   - **Inverse TCP Flag Scan**
     - Xmas Scan
     - FIN Scan
     - NULL Scan
     - Maimon Scan
   - **ACK Flag Probe Scan**
     - TTL-Based Scan
     - Window-Based Scan

3. **Third Party and Spoofed TCP Scanning Methods**
   - **IDLE/IP ID Header Scan**
#### <span style="background:#d4b106"> UDP Scanning </span>

- **UDP Scanning**

#### <span style="background:#d4b106"> SCTP Scanning </span>

1. **SCTP INIT Scanning**
2. **SCTP COOKIE/ECHO Scanning**

#### <span style="background:#d4b106"> SSDP Scanning </span>

- **SSDP and List Scanning**

#### <span style="background:#d4b106"> IPv6 Scanning </span>

- **IPv6 Scanning**

> [!Resources]
> # [Reserved Ports Table](obsidian://open?vault=SkyNetDSKT&file=CEH%20v12%20Notes%202024%2F03-Scanning_Networks)

### Scanning Techniques Table

> [!NOTE]
> The<font color="#adff23"> ↪ </font>symbol indicates EH|C scope. Nothing more.


| Scanning Technique                                                                                       | Nmap Command                                             | Request                                                      | Response                                                                                                                                                                                                       | Advantages                                                                                                                                                                                                                                                                       | Disadvantages                                                                                                                                                                                                                                                                                     |
| -------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- | ------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| <font color="#adff23">↪</font> TCP Connect/Full-Open Scan                                                | `nmap -sT -v <Target IP Address>`                        | SYN packets                                                  | SYN+ACK packet response - Port is open<br> <br>RST packet response - Port is closed                                                                                                                            | <font color="#adff23">Does not require super-user privileges</font>                                                                                                                                                                                                              | <font color="#ffc000">⚠️</font>☠️🚨<br><font color="#ff0000">Easily detectable and filterable<br><br>The logs in the target system disclose the connection</font><br><br>                                                                                                                         |
| <font color="#adff23">↪</font> Stealth Scan (Half-Open Scan)                                             | `nmap -sS -v <Target IP Address>`                        | Single SYN packet                                            | SYN+ACK packet response - Port is open <br><br>RST packet response - Port is closed                                                                                                                            | <font color="#adff23">Bypasses firewall rules and logging mechanisms</font>                                                                                                                                                                                                      | <font color="#ffc000">⚠️</font><br><font color="#de7802">Will be detected by IDS nowadays but won't get logged</font>                                                                                                                                                                             |
| <font color="#adff23">↪</font> Inverse TCP Flag Scan                                                     | `nmap -(sF, -sN, -sX) -v<Target IP Address>"`            | Probe packet <br>- FIN<br>- URG<br>- PSH<br>- NULL           | No response - Port is open <br><br>RST packet response - Port is closed                                                                                                                                        | Avoids many IDS and logging systems;<br><br><font color="#adff23">Highly stealthy</font>                                                                                                                                                                                         | <font color="#de7802">Requires raw access to network sockets and super-user privileges</font><br><br><font color="#de7802">Not effective against Microsoft Windows hosts, in particular</font><br><br>                                                                                            |
| <font color="#adff23">↪</font> Xmas Scan                                                                 | `nmap -sX -v <Target IP Address>`                        | Probe packet<br>(FIN + URG + PSH)                            | No response - Port is open <br><br>RST packet response - Port is closed                                                                                                                                        | <font color="#adff23">Avoids IDS and the TCP three-way handshake</font>                                                                                                                                                                                                          | <font color="#ffff00">Works only when systems are compliant with the RFC 793-based TCP/IP implementation</font> <br> <br><font color="#ffff00">Works on the Unix platform only</font><br> <br><font color="#DE7802">Does not work against any current version of Microsoft Windows</font><br><br> |
| <font color="#adff23">↪</font> FIN Scan                                                                  | `nmap -sF -v <Target IP Address>`                        | Probe packet (FIN)                                           | No response - Port is open <br><br>RST packet response - Port is closed                                                                                                                                        | Probe packets enabled with TCP flags can pass through filters undetected, depending on the security mechanisms installed                                                                                                                                                         | <font color="#ffff00">Works only when systems are compliant with the RFC 793-based TCP/IP implementation</font><br><br><font color="#DE7802">Does not work against any current version of Microsoft Windows</font>                                                                                |
| <font color="#adff23">↪</font> NULL Scan                                                                 | `nmap -sN -v <Target IP Address>`                        | Probe packet (NULL)                                          | No response - Port is open <br><br>RST packet response - Port is closed                                                                                                                                        | Probe packets enabled with TCP flags can pass through filters undetected, depending on the security mechanisms installed                                                                                                                                                         | <font color="#ffff00">Works only when systems are compliant with the RFC 793-based TCP/IP implementation</font><br><br><font color="#DE7802">Does not work against any current version of Microsoft Windows</font>                                                                                |
| <font color="#adff23">↪</font> TCP Maimon Scan                                                           | `nmap -sM -v <Target IP Address>`                        | Probe packet (FIN/ACK)                                       | No response - Port is open <br><br>ICMP unreachable error response - Port is filtered <br><br>RST packet response - Port is closed                                                                             | Probe packets enabled with TCP flags can pass through filters undetected, depending on the security mechanisms installed                                                                                                                                                         | <font color="#ffff00">Works only when systems are compliant with the RFC 793-based TCP/IP implementation</font> <br><br><font color="#DE7802">Does not work against any current version of Microsoft Windows</font>                                                                               |
| <font color="#adff23">↪</font> ACK Flag Probe Scan<br><br>(to potentialy map out firewall rule sets)<br> | `nmap -sA -v <Target IP Address>`                        | ACK probe packets                                            | No response - Port is filtered (stateful firewall is present)<br><br>RST packet response - Port is not filtered (no firewall is present)                                                                       | Can evade IDS in most cases<br><br>Helps in checking the filtering systems of target networks                                                                                                                                                                                    | 🐌<br>Extremely slow and can exploit only older OSes with vulnerable BSD-derived TCP/IP stacks                                                                                                                                                                                                    |
| <font color="#adff23">↪</font> TTL-Based ACK Flag Probe Scan                                             | `nmap -sA -ttl 100 -v <Target IP Address>`               | ACK probe packets (several thousands) to different TCP ports | RST packet response - Port is open (TTL value on a port < 64)<br><br>RST packet response - Port is closed (TTL value on a port ≥ 64)                                                                           | Can evade IDS in most cases<br><br>Helps in checking the filtering systems of target networks                                                                                                                                                                                    | 🐌<br>Extremely slow and can exploit only older OSes with vulnerable BSD-derived TCP/IP stacks                                                                                                                                                                                                    |
| <font color="#adff23">↪</font> Window-Based ACK Flag Probe Scan                                          | `nmap -sA -sW -v <Target IP Address>`                    | ACK probe packets (several thousands) to different TCP ports | RST packet response - Port is open (WINDOW value on a port is non-zero)<br><br>ICMP unreachable error response - Port is filtered<br><br>RST packet response - Port is closed (WINDOW value on a port is zero) | Can evade IDS in most cases<br><br>Helps in checking the filtering systems of target networks                                                                                                                                                                                    | 🐌<br>Extremely slow and can exploit only older OSes with vulnerable BSD-derived TCP/IP stacks                                                                                                                                                                                                    |
| <font color="#adff23">↪</font> IDLE/IPID Header Scan                                                     | `nmap -Pn -p- -sI <Zombie Hostname> <Target IP Address>` | SYN packet                                                   | SYN+ACK packet response - Port is open<br><br>RST packet response - Port is closed                                                                                                                             | Offers the complete blind scanning of a remote host                                                                                                                                                                                                                              | Requires the identification of sequence numbers of the zombie host                                                                                                                                                                                                                                |
| <font color="#adff23">↪</font> UDP Scan                                                                  | `nmap -sU -v <Target IP Address>`                        | UDP packet                                                   | No response - Port is open<br><br>ICMP unreachable error response - Port is closed                                                                                                                             | Less informal with regard to an open port because there is no overhead of a TCP handshake <br><br>Microsoft-based OSes do not usually implement any ICMP rate limiting; hence, <font color="#adff23">this scan operates very efficiently on Windows-based devices</font><br><br> | Slow because it limits the ICMP error message rate as a form of compensation to machines that apply RFC 1812 section 4.3.2.8 <br><br>A remote host will require access to the raw ICMP socket to distinguish closed ports from unreachable ports <br><br>Requires privileged access<br>           |
| SCTP INIT Scan                                                                                           | `nmap -sY -v <Target IP Address>`                        | INIT chunk                                                   | INIT+ACK chunk - Port is open <br> ICMP unreachable exception - Port is filtered <br> ABORT chunk - Port is closed                                                                                             | An INIT scan is performed quickly by scanning thousands of ports per second on a fast network not obstructed by a firewall, offering a strong sense of security <br> Can clearly differentiate between various ports such as open, closed, and filtered states                   |                                                                                                                                                                                                                                                                                                   |
| SCTP COOKIE ECHO Scan                                                                                    | `nmap -sZ -v <Target IP Address>`                        | COOKIE ECHO chunk                                            | No response - Port is open <br> ABORT chunk - Port is closed                                                                                                                                                   | The COOKIE ECHO chunk is not blocked by non-stateful firewall rule sets <br> Only an advanced IDS can detect an SCTP COOKIE ECHO scan                                                                                                                                            | Cannot differentiate clearly between open and filtered ports, showing the output as open filtered in both cases                                                                                                                                                                                   |

## Banner grabbing/OS Discovery using #Nmap :

```bash
-sV: detects service versions.
```

Banner grabbing, or OS fingerprinting, is a method used to determine the OS that is running on a remote target system.

There are two types of OS discovery or banner grabbing techniques:

- Active Banner Grabbing Specially crafted packets are sent to the remote OS, and the responses are noted, which are then compared with a database to determine the OS. Responses from different OSes vary, because of differences in the TCP/IP stack implementation.

- Passive Banner Grabbing This depends on the differential implementation of the stack and the various ways an OS responds to packets. Passive banner grabbing includes banner grabbing from error messages, sniffing the network traffic, and banner grabbing from page extensions.

> [!NOTE] COUNTER MEASURE
> Supressing banner through the config file mitigates the attack possibility

### Operating System Time To Live and TCP Window Size

Identify the target system’s OS with Time-to-Live (TTL):

| Operating System | Time To Live | TCP Window Size            |
| ---------------- | ------------ | -------------------------- |
| Linux            | 64           | 5840                       |
| FreeBSD          | 64           | 65535                      |
| OpenBSD          | 255          | 16384                      |
| Windows          | 128          | 65,535 bytes to 1 Gigabyte |
| Cisco Routers    | 255          | 4128                       |
| Solaris          | 255          | 8760                       |
| AIX              | 255          | 16384                      |

`nmap --script smb-os-discovery.nse <Target IP Address>`
> --script: specifies the customized script and smb-os-discovery.nse: attempts to determine the OS, computer name, domain, workgroup, and current time over the SMB protocol (ports 445 or 139).

---

# Scanning Beyond IDS and Firewall (PART 1)
[PART 2 | Deep Dive into Evasion](#) - not getting caught plays a big part into attack methodologies

An Intrusion Detection System (IDS) and firewall are security mechanisms designed to prevent unauthorized access to a network. However, both IDSs and firewalls have limitations. While they aim to block malicious traffic from entering the network, certain techniques can be used to send intended packets to the target and evade these defenses.

### Techniques to Evade IDS/Firewall

- **Packet Fragmentation**: Sending fragmented probe packets to the target, which reassembles them after receiving all fragments.
- **Source Routing**: Specifying the routing path for malformed packets to reach the target.
- **Source Port Manipulation**: Using common source ports to disguise the actual source port and evade detection.
- **IP Address Decoy**: Generating or manually specifying decoy IP addresses to mask the actual IP address.
- **IP Address Spoofing**: Changing source IP addresses to make the attack appear to come from a different source.
- **Creating Custom Packets**: Sending custom packets to scan the target beyond the firewall.
- **Randomizing Host Order**: Scanning hosts in a random order to bypass firewall rules.
- **Sending Bad Checksums**: Sending packets with invalid checksums to confuse the target's IDS/firewall.
- **Proxy Servers**: Using a chain of proxy servers to hide the scan's source and evade restrictions.
- **Anonymizers**: Utilizing anonymizers to bypass internet censors and IDS/firewall rules.

### Nmap Commands to Evade IDS/Firewall

 1. **Packet Fragmentation**
   ```bash
   nmap -f <Target IP Address>
   ```
   - **-f** switch splits the IP packet into tiny fragment packets.
     > Packet fragmentation involves dividing a probe packet into several smaller fragments. When these packets reach the target, IDSs and firewalls behind the target generally queue and process them one by one. Due to the increased CPU and network resource consumption, many IDSs are configured to skip fragmented packets during port scans, allowing the scan to bypass detection.

 2. **Source Port Manipulation**
   ```bash
   nmap -g 80 <Target IP Address>
   ```
   - **-g** or **--source-port** option manipulates the source port.
     > Source port manipulation involves changing the actual source port number to a common one, such as HTTP (80), DNS, or FTP. This technique can be useful when firewalls are configured to allow packets from well-known ports, helping to disguise the scan as legitimate traffic and evade detection.

 3. **Using Maximum Transmission Unit (MTU)**
   ```bash
   nmap -mtu 8 <Target IP Address>
   ```
   - **-mtu** specifies the Maximum Transmission Unit (MTU).
     > By specifying a smaller MTU (e.g., 8 bytes), this technique sends smaller packets instead of one large packet. This can help evade filtering and detection mechanisms that expect standard-sized packets, making it harder for IDSs and firewalls to detect the scan.

 4. **IP Address Decoy**
   ```bash
   nmap -D RND:10 <Target IP Address>
   ```
   - **-D** performs a decoy scan, **RND** generates random non-reserved IP addresses.
     > The IP address decoy technique generates or manually specifies multiple decoy IP addresses along with the real IP address. This makes it difficult for IDSs and firewalls to identify which IP address is actually performing the scan. By using this command, Nmap automatically generates a random number of decoys and randomly positions the real IP address among the decoy IP addresses.

 5. **MAC Address Spoofing**
   ```bash
   nmap -sT -Pn --spoof-mac 0 <Target IP Address>
   ```
   - **--spoof-mac 0** randomizes the MAC address, **-sT** performs a TCP connect/full open scan, **-Pn** skips host discovery.
     > MAC address spoofing involves changing the MAC address to that of a legitimate user on the network. This technique allows the attacker to send request packets to the target while pretending to be a legitimate host, thus bypassing MAC-based filtering and detection mechanisms.

 6. **Randomizing Host Order**
   ```bash
   nmap -T5 --randomize-hosts <Target IP Address>
   ```
   - **--randomize-hosts** option randomizes the order of hosts being scanned.
     > This technique scans the target hosts in a random order, making it harder for IDSs and firewalls to detect a pattern in the scan and identify it as malicious activity.

 7. **Sending Bad Checksums**
   ```bash
   nmap --badsum <Target IP Address>
   ```
   - **--badsum** sends packets with incorrect checksums.
     > Sending packets with bad or bogus TCP/UDP checksums confuses the target's IDS/firewall, which may not be configured to process such packets, allowing the scan to bypass detection.

 8. **Using Proxy Servers**
   ```bash
   nmap --proxies <proxy list> <Target IP Address>
   ```
   - **--proxies** option routes the scan through multiple proxy servers.
     > Using a chain of proxy servers hides the actual source of the scan, making it difficult for IDSs and firewalls to trace the scan back to the attacker. This technique helps evade IP-based restrictions and detection mechanisms.

 9. **Anonymizers**
   ```bash
   nmap --proxy <anonymizer proxy> <Target IP Address>
   ```
   - **--proxy** option uses an anonymizer service.
     > Anonymizers allow attackers to bypass internet censors and evade IDS and firewall rules by masking the origin of the traffic. This technique leverages anonymizer services to hide the attacker's true identity and location.

---


---

# #Tools 

##### #Nmap // #Hping3 // #Metasploit 

Host Discovery using #Nmap : `nmap -sn -PR <Target IP Address> `

### Host Discovery

> [! Syntax logic]
> Scan type --> Lower case 's' and capital 'first letter' of scan type
> Discovery type --> Capital 'P' and capital 'first letter' of scan type or couple variations of that

| -sn: disables port scan

P (Ping type)
 >R (ARP)
> U (UDP)
> E (ICMP Echo)
> P (ICMP Timestamp)
> M (ICMP Address Mask)
> S (TCP SYN Ping)
> A (TCP ACK Ping)
> O (IP Ping)

- ICMP Address Mask Ping Scan: This technique is an alternative for the traditional ICMP ECHO ping scan, which are used to determine whether the target host is live specifically when administrators block the ICMP ECHO pings.
```bash
  nmap -sn -PM <Target IP Address>
```

- TCP SYN Ping Scan: This technique sends empty TCP SYN packets to the target host, ACK response means that the host is active.
```bash
  nmap -sn -PS <Target IP Address>
```

- TCP ACK Ping Scan: This technique sends empty TCP ACK packets to the target host; an RST response means that the host is active.
```bash
  nmap -sn -PA <Target IP Address>
```

- IP Protocol Ping Scan: This technique sends different probe packets of different IP protocols to the target host, any response from any probe indicates that a host is active.
```bash
  nmap -sn -PO <Target IP Address>
```

### Service Discovery

```bash
   nmap -sS -v <Target IP Address>
```
- -sS: performs the stealth scan/TCP half-open scan and
- -v: enables the verbose output (include all hosts and ports in the output).
     The stealth scan involves resetting the TCP connection between the client and server abruptly before completion of three-way handshake signals, and hence leaving the connection half-open. This scanning technique can be used to bypass firewall rules, logging mechanisms, and hide under network traffic.

```bash
nmap -sX -v <Target IP Address>
```
- -sX: performs the Xmas scan
     Xmas scan sends a TCP frame to a target system with FIN, URG, and PUSH flags set. If the target has opened the port, then you will receive no response from the target system. If the target has closed the port, then you will receive a target system reply with an RST.

- -sM: performs the TCP Maimon scan
     In the TCP Maimon scan, a FIN/ACK probe is sent to the target; if there is no response, then the port is Open|Filtered, but if the RST packet is sent as a response, then the port is closed.

-  -sA: performs the ACK flag probe scan
     The ACK flag probe scan sends an ACK probe packet with a random sequence number; no response implies that the port is filtered (stateful firewall is present), and an RST response means that the port is not filtered.

- -sU: performs the UDP scan
     The UDP scan uses UDP protocol instead of the TCP. There is no three-way handshake for the UDP scan. It sends UDP packets to the target host; no response means that the port is open. If the port is closed, an ICMP port unreachable message is received.

> [!🚨🚨🚨]
> **<font color="#ff4023">You should not use -A against target networks without permission.</font>**
> 
> -A: enables aggressive scan.
> The aggressive scan option supports OS detection (-O), version scanning (-sV), script scanning (-sC), and traceroute (--traceroute).
> 
>   🚨🚨🚨

> [!Other tools]
> `unicornscan <Target IP Address> -Iv`
> > In this command, -I specifies an immediate mode and -v specifies a verbose mode.

> [!Resources]
> # [Nmap Ultimate Cheatsheet](obsidian://open?vault=SkyNetDSKT&file=CEH%20v12%20Notes%202024%2FResources%2FNmap_Ultimate_Cheatsheet)


Create Custom UDP and TCP Packets using Hping3 to Scan beyond the IDS/Firewall
> Hping3 is a scriptable program that uses the TCL language, whereby packets can be received and sent via a binary or string representation describing the packets.
> 

---

### #Hping3 

```bash
hping3 <Target IP Address> --udp --rand-source --data 500
```
- Here, --udp specifies sending the UDP packets to the target host, --rand-source enables the random source mode and --data specifies the packet body size.

```bash
hping3 -S <Target IP Address> -p 80 -c 5
```
- Here, -S specifies the TCP SYN request on the target machine, -p specifies assigning the port to send the traffic, and -c is the count of the packets sent to the target machine.

```bash
hping3 <Target IP Address> --flood
```
- --flood: performs the TCP flooding.

---

### Scan a Target Network using #Metasploit:

> Metasploit Framework is a tool that provides information about security vulnerabilities in the target organization’s system, and aids in penetration testing and IDS signature development. It facilitates the tasks of attackers, exploit writers, and payload writers. A major advantage of the framework is the modular approach, that is, allowing the combination of any exploit with any payload.

```service postgresql start
msfdb init
msfconsole 

db_status 

nmap -Pn -sS -A -oX Test 10.10.1.0/24

db_import Test

hosts 

db_services 

use auxiliary/scanner/portscan/syn

set INTERFACE eth0
set PORTS 80
set RHOSTS 10.10.1.5-23
set THREADS 50

run


use auxiliary/scanner/portscan/tcp

set RHOSTS <Target IP Address>

run


use auxiliary/scanner/smb/smb_version

set RHOSTS 10.10.1.5-23

set THREADS 11

```

---

# [Network Scanning Countermeasures](obsidian://open?vault=SkyNetDSKT&file=CEH%20v12%20Notes%202024%2F03.1-Network_Scanning%20Countermeasures)




