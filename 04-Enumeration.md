# Enumeration

> #TLDR
> Enumeration is the process of extracting detailed information such as usernames, machine names, network resources, shares, and services from a system or network. During the enumeration phase, an attacker establishes active connections with the system and sends targeted queries to gather more information about the target. The information collected during enumeration is used to identify vulnerabilities in the system's security, which can then be exploited to compromise the target system. This process enables the attacker to perform password attacks and gain unauthorized access to information system resources. Enumeration techniques are especially effective in an intranet environment.

---
## What We Get From This Exercise 
Info Obtained in Enumeration
###### #Objectives #Enumeration

- Explain Enumeration Concepts
- Demonstrate Different Techniques for NetBI0S Enumeration
- Demonstrate Different Techniques for SNMP Enumeration
- Use Different Techniques for LDAP Enumeration
- Use Different Techniques for NTP and NFS Enumeration
- Demonstrate Different Techniques for SMTP and DNS Enumeration
- Demonstrate IPSec, VoIP, RPC, Unix/Linux, Telnet FTP, TFTP, SMB, IPv6, and BGP Enumeration
- Explain Enumeration Countermeasures

Enumeration allows the attacker to collect the following information:
- Network resources
- Network shares
- Routing tables
- Audit and service settings 
- NMP and FQDN details
- Machine names
- Users and groups
- Applications and banners 

---

## Table of Contents

1. [Techniques for Enumeration](#techniques-for-enumeration)
	1. [Extract Usernames Using Email IDs](#extract-usernames-using-email-ids)
	2. [Extract Information Using Default Passwords](#extract-information-using-default-passwords)
	3. [Brute Force Active Directory](#brute-force-active-directory)
	4. [Extract Information Using DNS Zone Transfer](#extract-information-using-dns-zone-transfer)
	5. [Extract User Groups from Windows](#extract-user-groups-from-windows)
	6. [Extract Usernames Using SNMP](#extract-usernames-using-snmp)
2. [Services and Ports to Enumerate](#services-and-ports-to-enumerate)
	1. [Ports and Protocols](#ports-and-protocols)
	2. [TCP](#tcp)
	3. [UDP](#udp)
	4. [TCP/UDP 53: DNS Zone Transfer](#tcpudp-53-dns-zone-transfer)
	5. [TCP/UDP 135: Microsoft RPC Endpoint Mapper](#tcpudp-135-microsoft-rpc-endpoint-mapper)
	6. [UDP 137: NetBIOS Name Service (NBNS)](#udp-137-netbios-name-service-nbns)
	7. [TCP 139: NetBIOS Session Service (SMB over NetBIOS)](#tcp-139-netbios-session-service-smb-over-netbios)
	8. [TCP/UDP 445: SMB over TCP (Direct Host)](#tcpudp-445-smb-over-tcp-direct-host)
	9. [UDP 161: Simple Network Management Protocol (SNMP)](#udp-161-simple-network-management-protocol-snmp)
	10. [TCP/UDP 389: Lightweight Directory Access Protocol (LDAP)](#tcpudp-389-lightweight-directory-access-protocol-ldap)
	11. [TCP 2049: Network File System (NFS)](#tcp-2049-network-file-system-nfs)
	12. [TCP 25: Simple Mail Transfer Protocol (SMTP)](#tcp-25-simple-mail-transfer-protocol-smtp)
	13. [TCP/UDP 162: SNMP Trap](#tcpudp-162-snmp-trap)
	14. [UDP 500: ISAKMP/Internet Key Exchange (IKE)](#udp-500-isakmpinternet-key-exchange-ike)
	15. [TCP 22: Secure Shell (SSH)](#tcp-22-secure-shell-ssh)
	16. [TCP/UDP 3268: Global Catalog Service](#tcpudp-3268-global-catalog-service)
	17. [TCP/UDP 5060, 5061: Session Initiation Protocol (SIP)](#tcpudp-5060-5061-session-initiation-protocol-sip)
	18. [TCP 20/21: File Transfer Protocol (FTP)](#tcp-2021-file-transfer-protocol-ftp)
	19. [TCP 23: Telnet](#tcp-23-telnet)
	20. [UDP 69: Trivial File Transfer Protocol (TFTP)](#udp-69-trivial-file-transfer-protocol-tftp)
	21. [TCP 179: Border Gateway Protocol (BGP)](#tcp-179-border-gateway-protocol-bgp)
3. [Tools for Enumeration](#tools-for-enumeration)
	1. [NetBIOS Enumeration](#netbios-enumeration)
	2. [Enumerating User Accounts](#enumerating-user-accounts)
	3. [SNMP Enumeration](#snmp-enumeration)
	4. [LDAP Enumeration](#ldap-enumeration)
	5. [NTP Enumeration](#ntp-enumeration)
	6. [SMTP Enumeration](#smtp-enumeration)
	7. [DNS Enumeration](#dns-enumeration)
	8. [SMB Enumeration](#smb-enumeration)
	9. [RIP Enumeration](#rip-enumeration)
	10. [RPC Enumeration](#rpc-enumeration)
4. [Summary](#summary)

---

# Techniques for Enumeration

#### 1. Extract Usernames Using Email IDs
> Every email address follows the format “username@domainname,” where it contains two parts: a username and a domain name. This can be leveraged to identify usernames associated with an organization.

#### 2. Extract Information Using Default Passwords 
(Deep dive in module 6 - System Hacking)
> Many online resources provide lists of default passwords assigned by manufacturers to their products. Often, users do not change these default credentials. Attackers can exploit this by using these default usernames and passwords to gain access to target systems.

#### 3. Brute Force Active Directory
> Microsoft Active Directory can be vulnerable to username enumeration during user input verification due to a design flaw. If the “logon hours” feature is enabled, different error messages are returned for authentication attempts outside these hours. Attackers exploit this to enumerate valid usernames. Once valid usernames are identified, attackers can perform brute-force attacks to crack the corresponding passwords.

#### 4. Extract Information Using DNS Zone Transfer
> DNS zone transfer is used by network administrators to replicate DNS data across multiple DNS servers or back up DNS files. This involves executing a zone-transfer request to the name server. If improperly configured, the DNS server will permit zone transfers, converting all DNS names and IP addresses to ASCII text. This can reveal lists of all named hosts, sub-zones, and related IP addresses. DNS zone transfer can be performed using `nslookup` and `dig` commands.
```
dig @ns1.certifiedhacker.com certifiedhacker.com AXFR
```
- This command asks the specified nameserver (in this case, `ns1.certifiedhacker.com`) to perform a zone transfer (`AXFR`) for the domain `certifiedhacker.com`.

#### 5. Extract User Groups from Windows
> To extract user groups from Windows, an attacker must have a registered user ID in Active Directory. Using this ID, the attacker can extract information about groups the user is a member of through the Windows interface or command-line methods.

#### 6. Extract Usernames Using SNMP
> Attackers can use the Simple Network Management Protocol (SNMP) to guess read-only or read-write community strings and extract usernames. This is done using the SNMP application programming interface (API) to query SNMP-enabled devices.

---

# Services and Ports to Enumerate

### Ports and Protocols
###### <span style="background:#adff23;font-weight:bold"> Detailed descriptions follow below the table </span> -- expand items to see more

| **Port**   | **Protocol**      | **Service**                      | **Enumeration Purpose**                                                                 |
|------------|-------------------|-----------------------------------|-----------------------------------------------------------------------------------------|
| 21         | FTP               | File Transfer Protocol           | Enumerating FTP users, directories, and files.                                          |
| 22         | SSH               | Secure Shell                     | Identifying SSH versions and brute-forcing credentials.                                |
| 23         | Telnet            | Telnet                           | Retrieving banner information and brute-forcing credentials.                           |
| 25         | SMTP              | Simple Mail Transfer Protocol    | Extracting user accounts via VRFY, EXPN, and RCPT TO commands.                        |
| 53         | DNS               | Domain Name System               | Performing zone transfers and gathering DNS records.                                   |
| 69         | TFTP              | Trivial File Transfer Protocol   | Accessing configuration files and sensitive information.                               |
| 80/8080    | HTTP/HTTP Proxy   | Hypertext Transfer Protocol      | Enumerating web directories, applications, and vulnerabilities.                       |
| 110        | POP3              | Post Office Protocol             | Enumerating user accounts and brute-forcing email credentials.                        |
| 135        | RPC/DCOM          | Remote Procedure Call            | Gathering information on services running on Windows.                                 |
| 137        | UDP               | NetBIOS/WINS                     | Enumerating NetBIOS names, shares, and associated services on Windows systems.        |
| 139        | NetBIOS           | NetBIOS Session Service          | Enumerating shares, sessions, and user accounts on Windows systems.                  |
| 143        | IMAP              | Internet Message Access Protocol | Enumerating mailboxes and brute-forcing credentials.                                  |
| 161/162    | SNMP              | Simple Network Management Protocol | Enumerating network devices, configurations, and community strings.               |
| 179        | BGP               | Border Gateway Protocol          | Enumerating routing information, AS numbers, and potential misconfigurations in BGP setups. |
| 389        | LDAP              | Lightweight Directory Access Protocol | Extracting user and group information from directories.                             |
| 443        | HTTPS             | Secure HTTP                      | Enumerating secure web services and identifying misconfigurations.                   |
| 445        | SMB/CIFS          | Server Message Block/Common Internet File System | Enumerating shared resources and user accounts on Windows systems.      |
| 500        | IKE               | Internet Key Exchange            | Enumerating VPNs, identifying key exchange mechanisms, and targeting IPSec tunnels.   |
| 512/513/514| TCP/UDP           | Linux R services                 | Identifying and enumerating older remote execution services on Unix/Linux systems.    |
| 1433       | MSSQL             | Microsoft SQL Server             | Extracting database information and brute-forcing credentials.                        |
| 1521       | Oracle TNS        | Oracle Database                  | Enumerating Oracle database instances and user accounts.                              |
| 3306       | MySQL             | MySQL Database                   | Enumerating database information and user accounts.                                   |
| 3389       | RDP               | Remote Desktop Protocol          | Enumerating Windows RDP services and attempting brute force.                          |
| 5900       | VNC               | Virtual Network Computing        | Identifying and gaining access to VNC servers.                                        |
| 8080       | HTTP Proxy        | Web Proxy                        | Enumerating proxy services and testing for proxy misconfigurations.                  |

**Note:** This list is not exhaustive but includes commonly targeted ports/services for enumeration.


---

Transmission Control Protocol (TCP) and User Datagram Protocol (UDP) manage data communications between terminals in a network.

#### TCP
TCP is a connection-oriented protocol capable of carrying messages or emails over the Internet. It provides a reliable multi-process communication service in a multi-network environment. The features and functions of TCP include:
- Supports acknowledgement for receiving data through a sliding window acknowledgement system.
- Offers automatic retransmission of lost or unacknowledged data.
- Allows addressing and multiplexing of data.
- A connection can be established, managed, or terminated.
- Offers quality-of-service transmission.
- Provides congestion management and flow control.

#### UDP
UDP is a connectionless protocol that carries short messages over a computer network. It provides unreliable service. The applications of UDP include:
- Audio streaming
- Videoconferencing and teleconferencing

##### Services and TCP/UDP Ports That Can Be Enumerated Include the Following:

#### TCP/UDP 53: DNS Zone Transfer
The DNS resolution process establishes communication between DNS clients and DNS servers. DNS clients send DNS messages to DNS servers listening on UDP port 53. If the DNS message size exceeds the default size of UDP (512 octets), the response contains only the data that UDP can accommodate, and the DNS server sets a flag to indicate the truncated response. The DNS client can then resend the request via TCP over port 53. In this approach, UDP is the default protocol for DNS servers, while TCP is used as a failover solution for lengthy queries. Malware such as ADM worm and Bonk Trojan use port 53 to exploit DNS server vulnerabilities.

#### TCP/UDP 135: Microsoft RPC Endpoint Mapper
RPC is a protocol used by a client system to request a service from a server. An endpoint is the protocol port on which the server listens for the client’s RPCs. The RPC Endpoint Mapper enables RPC clients to determine the port number currently assigned to a specific RPC service. A flaw in RPC that exchanges messages over TCP/IP can cause failure if malformed messages are incorrectly handled. This vulnerability could allow an attacker to send RPC messages to the RPC Endpoint Mapper process on a server to launch a denial-of-service (DoS) attack.

#### UDP 137: NetBIOS Name Service (NBNS)
NBNS, also known as the Windows Internet Name Service (WINS), provides a name-resolution service for computers running NetBIOS. NetBIOS name servers maintain a database of NetBIOS names for hosts and the corresponding IP addresses. NBNS aims to match IP addresses with NetBIOS names and queries. Attackers often target the name service first, typically using UDP 137 as its transport protocol.

#### TCP 139: NetBIOS Session Service (SMB over NetBIOS)
TCP 139 is well-known for transferring files over a network and is used for null-session establishment and file and printer sharing. Restricting access to TCP 139 is crucial for system administrators, as an improperly configured port can allow unauthorized access to critical system files or the entire file system.

#### TCP/UDP 445: SMB over TCP (Direct Host)
Windows supports file and printer sharing traffic using the SMB protocol directly hosted on TCP. In earlier OSs, SMB traffic required the NetBIOS over TCP (NBT) protocol to work on TCP/IP transport. Directly hosted SMB traffic uses port 445 (TCP and UDP) instead of NetBIOS.

#### UDP 161: Simple Network Management Protocol (SNMP)
SNMP is widely used in network management systems to monitor network-attached devices such as routers, switches, firewalls, printers, and servers. It consists of a manager and agents. The agent receives requests on port 161 from managers and responds on port 162.

#### TCP/UDP 389: Lightweight Directory Access Protocol (LDAP)
LDAP is a protocol for accessing and maintaining distributed directory information services over an IP network. By default, LDAP uses TCP or UDP as its transport protocol over port 389.

#### TCP 2049: Network File System (NFS)
The NFS protocol is used to mount file systems on a remote host over a network, allowing users to interact with the file systems as if they were mounted locally. NFS servers listen to client systems on TCP port 2049. Improperly configured NFS services can be exploited by attackers to gain control over a remote system, perform privilege escalation, inject backdoors, or install malware.

#### TCP 25: Simple Mail Transfer Protocol (SMTP)
SMTP is a TCP/IP mail delivery protocol that transfers email across the Internet and local networks. It runs on the connection-oriented service provided by TCP and uses port 25. SMTP commands and their respective syntaxes include:

| Command   | Syntax                     |
| --------- | -------------------------- |
| Hello     | HELO `<sending-host>`      |
| From      | MAIL FROM:`<from-address>` |
| Recipient | RCPT TO:`<to-address>`     |
| Data      | DATA                       |
| Reset     | RESET                      |
| Verify    | VRFY `<string>`            |
| Expand    | EXPN `<string>`            |
| Help      | HELP `[string]`            |
| Quit      | QUIT                       |

#### TCP/UDP 162: SNMP Trap
An SNMP trap uses TCP/UDP port 162 to send notifications, such as optional variable bindings and the sysUpTime value, from an agent to a manager.

#### UDP 500: Internet Security Association and Key Management Protocol (ISAKMP)/Internet Key Exchange (IKE)
ISAKMP/IKE is a protocol used to set up a security association (SA) in the IPsec protocol suite. It uses UDP port 500 to establish, negotiate, modify, and delete SAs and cryptographic keys in a virtual private network (VPN) environment.

#### TCP 22: Secure Shell (SSH)
SSH is a command-level protocol mainly used for securely managing various networked devices. It is an alternative to the unsecure Telnet protocol. SSH uses the client/server communication model, with the SSH server listening on TCP port 22. Attackers may exploit the SSH protocol by brute-forcing SSH login credentials.

#### TCP/UDP 3268: Global Catalog Service
Microsoft’s Global Catalog server, a domain controller that stores extra information, uses port 3268. Its database contains rows for every object in the entire organization. LDAP in the Global Catalog server uses port 3268. This service listens to port 3268 through a TCP connection, and administrators use port 3268 for troubleshooting issues in the Global Catalog by connecting to it using LDP.

#### TCP/UDP 5060, 5061: Session Initiation Protocol (SIP)
SIP is a protocol used in Internet telephony for voice and video calls. It typically uses TCP/UDP port 5060 (non-encrypted signaling traffic) or 5061 (encrypted traffic with TLS) for SIP to servers and other endpoints.

#### TCP 20/21: File Transfer Protocol (FTP)
FTP is a connection-oriented protocol used for transferring files over the Internet and private networks. FTP is controlled on TCP port 21, and for data transmission, it uses TCP port 20 or dynamic port numbers depending on the server configuration. Attackers may perform enumeration on FTP to find information such as the software version and existing vulnerabilities.

#### TCP 23: Telnet
The Telnet protocol is used for managing various networked devices remotely. It is an unsecure protocol because it transmits login credentials in cleartext. The Telnet server listens to its clients on port 23. Attackers can exploit the Telnet protocol for banner grabbing, brute-forcing login credentials, port-forwarding attacks, etc.

#### UDP 69: Trivial File Transfer Protocol (TFTP)
TFTP is a connectionless protocol used for transferring files over the Internet. TFTP relies on UDP and does not guarantee proper file transmission. It is mainly used to update or upgrade software and firmware on remote networked devices. TFTP uses UDP port 69 for transferring files to a remote host. Attackers may exploit TFTP to install malicious software or firmware on remote devices.

#### TCP 179: Border Gateway Protocol (BGP)
BGP is widely used by Internet service providers (ISPs) to maintain routing tables and efficiently process Internet traffic. BGP routers establish sessions on TCP port 179. Misconfiguration of BGP may lead to various attacks such as dictionary attacks, resource-exhaustion attacks, flooding attacks, and hijacking attacks.

---

# **Tools for Enumeration**
#### 1. NetBIOS Enumeration
   - **Description**: NetBIOS enumeration is used to gather information from Windows-based systems such as shared resources, user accounts, and network configurations.
   - **Tools**: `nbtstat`, nb`NetBIOS Enumerator`, `nmap` (through `--script nbstat`)
   - **Commands**:
     ```bash
     nbtstat -A <Target IP Address>  # Query by IP address
     nbtstat -a <hostname>           # Query by hostname
     nbtstat -c                      # Display NetBIOS name cache
     ```

><span style="background:#adff23;font-weight:bold"> Attackers use NetBIOS enumeration to obtain: </span>
>- The list of computers that belong to a domain
>- The list of shares on the individual hosts in the network
>- Policies and passwords

##### NBTStat Switches

| Switch                       | Name                           | Function                                                                                                                                      |
| ---------------------------- | ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| **-a <_NetBIOS name_** **>** | Adapter status by NetBIOS name | Returns the NetBIOS name table and media access control (MAC) address of the address card for the specified computer name.                    |
| **-A <_IP address_** **>**   | Adapter status by IP address   | Lists the same information as **-a** when given the target's IP address.                                                                      |
| **-c**                       | Cache                          | Lists the contents of the NetBIOS name cache.                                                                                                 |
| **-n**                       | Names                          | Displays the names registered locally by NetBIOS applications such as the server and redirector.                                              |
| **-r**                       | Resolved                       | Displays a count of all names resolved by broadcast or WINS server.                                                                           |
| **-R**                       | Reload                         | Purges the name cache and reloads all PRE-entries from LMHosts.                                                                               |
| **-RR**                      | Release Refresh                | Sends name release packets to the WINS server and starts a refresh, reregistering all names with the name server.                             |
| **-s**                       | Sessions by NetBIOS names      | Lists the NetBIOS sessions table converting destination IP addresses to computer NetBIOS names.                                               |
| **-S**                       | Sessions by IP address         | Lists the current NetBIOS sessions and their status, with the IP addresses.                                                                   |
| **[_Number_** **]**          | Interval                       | Redisplays selected statistics at intervals specified in seconds, pausing between each display. Press CTRL+C to stop redisplaying statistics. |
| **-?**                       | Help                           | Displays this list.                                                                                                                           |
### NetBIOS Name List

| Name          | NetBIOS Code | Type   | Information Obtained                                                                      |
| ------------- | ------------ | ------ | ----------------------------------------------------------------------------------------- |
| `<host name>` | `<00>`       | UNIQUE | Hostname                                                                                  |
| `<domain>`    | `<00>`       | GROUP  | Domain name                                                                               |
| `<host name>` | `<03>`       | UNIQUE | Messenger service running for the computer                                                |
| `<username>`  | `<03>`       | UNIQUE | Messenger service running for the logged-in user                                          |
| `<host name>` | `<20>`       | UNIQUE | Server service running                                                                    |
| `<domain>`    | `<1D>`       | GROUP  | Master browser name for the subnet                                                        |
| `<domain>`    | `<1B>`       | UNIQUE | Domain master browser name, identifies the primary domain controller (PDC) for the domain |

---

#### 2. Enumerating User Accounts ///

---
#### 3. SNMP Enumeration
   - **Description**: Simple Network Management Protocol (SNMP) enumeration is used to extract information from network devices like routers and switches.
   - **Tools**: `snmpwalk`, `snmp-check`
   - **Commands**:
     ```bash
     snmpwalk -v 2c -c public <Target IP Address>
     snmp-check <Target IP Address> -c public
     ```

#### 4. LDAP Enumeration
   - **Description**: Lightweight Directory Access Protocol (LDAP) enumeration is used to gather information from directory services such as Active Directory.
   - **Tools**: `ldapsearch`, `Softerra LDAP Administrator`
   - **Commands**:
     ```bash
     ldapsearch -x -h <Target IP Address> -b "dc=example,dc=com"
     ```

#### 5. NTP Enumeration
   - **Description**: Network Time Protocol (NTP) enumeration is used to query NTP servers for detailed information.
   - **Tools**: `ntpdc`, `ntpq`
   - **Commands**:
     ```bash
     ntpdc -c monlist <Target IP Address>
     ntpq -c readlist <Target IP Address>
     ```

#### 6. SMTP Enumeration
   - **Description**: Simple Mail Transfer Protocol (SMTP) enumeration is used to extract information from mail servers, such as user accounts and server configurations.
   - **Tools**: `telnet`, `Metasploit Framework`
   - **Commands**:
     ```bash
     telnet mail.example.com 25
     ehlo example.com
     vrfy user
     expn user
     ```

#### 7. DNS Enumeration
   - **Description**: Domain Name System (DNS) enumeration is used to gather information about DNS servers, including subdomains and DNS records.
   - **Tools**: `dnsenum`, `dnsrecon`
   - **Commands**:
     ```bash
     dnsenum example.com
     dnsrecon -d example.com
     ```

#### 8. SMB Enumeration
   - **Description**: Server Message Block (SMB) enumeration is used to gather information from SMB protocol used by Windows systems.
   - **Tools**: `enum4linux`, `smbclient`
   - **Commands**:
     ```bash
     enum4linux -a <Target IP Address>
     smbclient -L \\\\<Target IP Address>\\
     ```

#### 9. RIP Enumeration
   - **Description**: Routing Information Protocol (RIP) enumeration is used to gather routing information from RIP-enabled devices.
   - **Tools**: `zebra`, `routed`
   - **Commands**:   
   
```bash
	zebra -d
	routed -d
```

#### 10. RPC Enumeration
   - **Description**: Remote Procedure Call (RPC) enumeration is used to extract information from RPC services.
   - **Tools**: `rpcinfo`, `showmount`
   - **Commands**:
     ```bash
     rpcinfo -p <Target IP Address>
     showmount -e <Target IP Address>
     ```

---

### Techniques for Enumeration

#### NetBIOS Enumeration
> NetBIOS stands for Network Basic Input Output System, used by Windows for file and printer sharing. A NetBIOS name is a unique 16-character ASCII string assigned to Windows systems to identify the network device over TCP/IP. The first 15 characters are used for the device name, and the 16th is reserved for the service or name record type.

```bash
nbtstat -a [IP address of the remote machine]
```
- Displays the NetBIOS name table of a remote computer.

```bash
nbtstat -c
```
- Lists the contents of the NetBIOS name cache of the remote computer.

```bash
nmap -sV -v --script nbstat.nse <Target IP Address>
```
- Detects the service versions, enables verbose output, and performs NetBIOS enumeration.

```bash
nmap -sU -p 137 --script nbstat.nse <Target IP Address>
```
- Performs a UDP scan on port 137 and runs the nbstat.nse script.

#### SNMP Enumeration
> SNMP (Simple Network Management Protocol) is an application layer protocol running on UDP (User Datagram Protocol) that manages routers, hubs, and switches on an IP network. It uses two components: the SNMP agent on the device and the SNMP management station for communication.

SNMP uses port 161:

```bash
nmap -sU -p 161 <Target IP Address>
```
- Performs a UDP scan on port 161.

```bash
snmp-check <Target IP Address>
```

**SnmpWalk**:
> SnmpWalk is a command-line tool that scans numerous SNMP nodes instantly, identifying variables available for accessing the target network.

```bash
snmpwalk -v1 -c public <Target IP Address>
```
- `-v`: specifies the SNMP version (1 or 2c or 3), `-c`: sets a community string.

```bash
snmpwalk -v2c -c public <Target IP Address>
```
- `-v`: specifies the SNMP version (here, 2c is selected), `-c`: sets a community string.

```bash
nmap -sU -p 161 --script=snmp-sysdescr <Target IP Address>
```
- `-sU`: specifies a UDP scan, `-p`: specifies the port to be scanned, `--script`: executes a given script.

```bash
nmap -sU -p 161 --script=snmp-processes <Target IP Address>
```

```bash
nmap -sU -p 161 --script=snmp-win32-software <Target IP Address>
```

```bash
nmap -sU -p 161 --script=snmp-interfaces <Target IP Address>
```

#### LDAP Enumeration
> LDAP (Lightweight Directory Access Protocol) is an Internet protocol for accessing distributed directory services over a network. LDAP uses DNS for quick lookups and fast resolution of queries. Clients connect to a Directory System Agent (DSA) on TCP port 389, sending operation requests and receiving responses. BER (Basic Encoding Rules) is used for communication between the client and server.

```bash
nmap -sU -p 389 <Target IP Address>
```

```bash
nmap -p 389 --script ldap-brute --script-args ldap.base='"cn=users,dc=CEH,dc=com"' <Target IP Address>
```

```bash
ldapsearch
```
- `ldapsearch` is a shell-accessible interface to the `ldap_search_ext(3)` library call. It opens a connection to an LDAP server, binds the connection, and performs a search using specified parameters.

```bash
ldapsearch -h <Target IP Address> -x -s base namingcontexts
```
- `-x`: specifies simple authentication, `-h`: specifies the host, `-s`: specifies the scope.

```bash
ldapsearch -h <Target IP Address> -x -b "DC=CEH,DC=com"
```
- `-x`: specifies simple authentication, `-h`: specifies the host, `-b`: specifies the base DN for search.

```bash
ldapsearch -x -h <Target IP Address> -b "DC=CEH,DC=com" "objectclass=*"
```
- `-x`: specifies simple authentication, `-h`: specifies the host, `-b`: specifies the base DN for search.

#### NFS Enumeration
> NFS (Network File System) allows users to access, view, store, and update files over a remote server. This remote data can be accessed by the client computer similarly to local files.

```bash
nmap -p 2049 <Target IP Address>
```

Can also use tools like [SuperEnum](https://github.com/p4pentest/SuperEnum) and [RPCScan](https://github.com/hegusung/RPCScan).

#### DNS Enumeration
> DNS enumeration techniques gather information about DNS servers and network infrastructure of the target organization.

```bash
dig ns [Target Domain]
```
- `ns` returns name servers in the result.

```bash
dig @[NameServer] [Target Domain] axfr
```
- Retrieves zone information if the DNS zone is not properly configured.

**DNSSEC Zone Walking**:
> DNSSEC zone walking enumerates internal records of the target DNS server if the DNS zone is not properly configured.

```bash
./dnsrecon.py -d [Target domain] -z
```
- `-d`: specifies the target domain, `-z`: specifies that the DNSSEC zone walk be performed with standard enumeration.

```bash
nmap --script=broadcast-dns-service-discovery [Target Domain]
```

```bash
nmap -T4 -p 53 --script dns-brute [Target Domain]
```
- `-T4`: specifies the timing template, `-p`: specifies the target port.

```bash
nmap --script dns-srv-enum --script-args "dns-srv-enum.domain='[Target Domain]'"
```

#### SMTP Enumeration
> SMTP (Simple Mail Transfer Protocol) is a standard for email transmission, often used with POP3 and IMAP. SMTP uses mail exchange (MX) servers to direct mail via DNS and typically runs on TCP ports 25, 2525, or 587.

```bash
nmap -p 25 --script=smtp-enum-users <Target IP Address>
```

```bash
nmap -p 25 --script=smtp-open-relay <Target IP Address>
```

```bash
nmap -p 25 --script=smtp-commands <Target IP Address>
```

#### RPC Enumeration
> Enumerating RPC endpoints helps identify vulnerable services on service ports.

#### SMB Enumeration
> Enumerating SMB services enables gathering information such as OS details and versions of services running.

#### FTP Enumeration
> Enumerating FTP services provides information about port 21 and any running FTP services, which can be used for attacks such as FTP bounce, FTP brute force, and packet sniffing.

#### Enumerate Information from Windows and Samba Hosts using Enum4linux
> `Enum4linux` is a tool for enumerating information from Windows and Samba systems, including share enumeration, password policy retrieval, remote OS identification, and user listing.

```bash
enum4linux -u martin -p apple -n <Target IP Address>
```

```bash
enum4linux -u martin -p apple -U <Target IP Address>
```
- `-u`: specifies the username to use, `-p`: specifies the password, `-U`: retrieves the user list.
- `-P`: retrieves the password policy information.
- `-o`: retrieves the OS information.
- `-G`: retrieves group and member list.
- `-S`: retrieves share list.

---

## Summary 

This chapter explored various techniques and tools for enumeration, an essential phase in ethical hacking and penetration testing. 

Enumeration allows security professionals to extract critical information about target systems, networks, and users. Key techniques discussed include username extraction, DNS zone transfers, Active Directory brute-forcing, and leveraging SNMP to uncover usernames and groups within networks.

We covered an extensive list of services and ports commonly targeted for enumeration, with a focus on protocols like DNS, SMB, LDAP, and FTP. 

For each, we detailed how attackers might exploit vulnerabilities associated with these services to gain insight into network structures, user details, and more. 

The tools section introduced specific commands and utilities for each protocol and service, providing actionable steps for identifying and gathering information on a system’s resources and potential weaknesses. 

Ultimately, this chapter serves as a comprehensive guide to the art of enumeration, equipping security practitioners with the knowledge to methodically and effectively enumerate information, laying the groundwork for further penetration testing activities.

---

##### [Enumeration Countermeasures ↗](04.1-Enumeration_Countermeasures.md)

