# Hacking Web Servers

> #TLDR
> Understanding web server security is essential for protecting online assets. This note covers key concepts, common attacks, methodologies, and tools related to hacking web servers, offering a guide to better secure your server infrastructure.

---
## What We Get From This Exercise
###### #Objectives #hacking-web-servers

- Comprehensive understanding of web server operations.
- Insight into common vulnerabilities and attack vectors.
- Methods to implement defensive countermeasures.
- Hands-on examples and tools for web server security.

---

## Table of Contents

1. [Web Server Concepts](#web-server-concepts)
2. [Components of a Web Server](#components-of-a-web-server)
3. [Web Server Security Issues](#web-server-security-issues)
4. [Common Web Server Attacks](#common-web-server-attacks)
	1. [DNS Server Hijacking](#dns-server-hijacking)
	2. [Directory Traversal Attack](#directory-traversal-attack)
	3. [Website Defacement](#website-defacement)
	4. [HTTP Response Splitting Attack](#http-response-splitting-attack)
	5. [SSH Brute Force Attack](#ssh-brute-force-attack)
5. [Web Server Attack Methodology](#web-server-attack-methodology)
	1. [Information Gathering](#information-gathering)
	2. [Footprinting](#footprinting)
	3. [Vulnerability Scanning](#vulnerability-scanning)
6. [Featured Hacking Tools](#featured-hacking-tools)
7. [Featured Defence Tools](#featured-defence-tools)

---

## **Web Server Concepts**
A web server processes and delivers web pages to users via HTTP. Proper configuration and regular updates are crucial to maintaining security.

### Code Example
A basic HTTP server setup:
```python
from http.server import HTTPServer, SimpleHTTPRequestHandler

server = HTTPServer(('localhost', 8080), SimpleHTTPRequestHandler)
print("Server started on http://localhost:8080")
server.serve_forever()
```

---

## **Components of a Web Server**

| Component            | Description                                                              |
|----------------------|--------------------------------------------------------------------------|
| Document Root        | Stores HTML files for web page responses.                               |
| Server Root          | Holds configuration, error, executable, and log files.                  |
| Virtual Hosting      | Enables hosting of multiple domains on a single server.                 |
| Web Proxy            | Sits between the client and server to prevent IP blocking and anonymity.|

---

## Web Server Security Issues

| **Stack Level** | **Layer**               | **Description**                                                       |
| --------------- | ----------------------- | --------------------------------------------------------------------- |
| **Stack 7**     | Custom Web Applications | Custom applications specific to business needs, prone to logic flaws. |
| **Stack 6**     | Third-party Components  | Includes open source and commercial components.                       |
| **Stack 5**     | Web Server              | Servers like Apache and Microsoft IIS that host web applications.     |
| **Stack 4**     | Database                | Databases such as Oracle, MySQL, and MS SQL used for data storage.    |
| **Stack 3**     | Operating System        | OS platforms including Windows, Linux, and macOS.                     |
| **Stack 2**     | Network                 | Networking devices like routers and switches.                         |
| **Stack 1**     | Security                | Core security infrastructure including IPS/IDS.                       |

Web servers are prone to various vulnerabilities, including software bugs and misconfigurations. Common security oversights include:
- Failing to update the server software.
- Default or weak credentials.
- Enabling unnecessary services.

| **Reasons for Web Server Compromise**                             | **Details**                                                   |
| ----------------------------------------------------------------- | ------------------------------------------------------------- |
| **Improper file and directory permissions**                       | Files and directories not securely restricted.                |
| **Server installation with default settings**                     | Default settings left unchanged, introducing vulnerabilities. |
| **Enabling of unnecessary services**                              | Services like content management and remote admin enabled.    |
| **Security conflicts with business ease-of-use**                  | Conflicts between security and usability requirements.        |
| **Lack of proper security policies, procedures, and maintenance** | Absence of structured security practices.                     |
| **Improper authentication with external systems**                 | Weak or insufficient authentication protocols.                |
| **Default accounts with default or no passwords**                 | Accounts left unsecured with default credentials.             |
| **Unnecessary default, backup, or sample files**                  | Files that provide extra attack vectors if left accessible.   |
| **Misconfigurations in web server, OS, and networks**             | Incorrect settings that weaken security defenses.             |
| **Bugs in server software, OS, and web applications**             | Software vulnerabilities left unpatched or unfixed.           |
| **Misconfigured SSL certificates and encryption settings**        | Weak or improperly configured SSL/TLS settings.               |
| **Administrative or debugging functions enabled**                 | Unnecessary functions that expose sensitive information.      |
| **Use of self-signed and default certificates**                   | Certificates that don’t guarantee authenticity.               |
| **Not using a dedicated server for web services**                 | Shared environments increasing exposure to threats.           |

### Impact of Attacks
- Compromise of user accounts.
- Website defacement.
- Data tampering and theft.
- Reputational damage.


| **Web Server Misconfiguration**                  | **Examples**                                                      |
|--------------------------------------------------|-------------------------------------------------------------------|
| Verbose Debug/Error Messages                     | Allows viewing server status and error messages.                  |
| Anonymous or Default Users/Passwords             | Default or anonymous access increases vulnerability.              |
| Sample Configuration and Script Files            | Presence of sample files can expose sensitive information.        |
| Remote Administration Functions                  | Remote functions open the server to unauthorized access.          |
| Unnecessary Services Enabled                     | Extra services increase the attack surface of the server.         |
| Misconfigured/Default SSL Certificates           | Weak or default SSL settings reduce encryption strength.          |

### Configuration File Examples

| **File**       | **Purpose**                                      | **Configuration**                                   |
|----------------|--------------------------------------------------|----------------------------------------------------|
| `httpd.conf`   | Configures Apache server status page visibility. | `<Location /server-status> SetHandler server-status </Location>` |
| `php.ini`      | Manages error display and logging in PHP.        | `display_error = On log_errors = On error_log = syslog ignore_repeated_errors = Off` |


---

## Common Web Server Attacks

### DNS Server Hijacking
An attacker redirects users to a malicious server by manipulating DNS settings.

---

### Directory Traversal Attack
Exploits directory traversal vulnerabilities to access restricted areas of the server.

---

#### Example URL Exploit
(dated)
```
http://targetserver.com/scripts/..%5c..%5cWindows/System32/cmd.exe?/c+dir+c:\
```


---

### Website Defacement
Altering the visual appearance of a website to convey false or harmful information. Either through "physically" changing the source code or by DNS poisoning.

---

### HTTP Response Splitting Attack
By injecting header data, the attacker causes the server to respond with two separate responses.

| **Step** | **Description**                                                                                                         |
|----------|-------------------------------------------------------------------------------------------------------------------------|
| 1        | HTTP response-splitting attack involves adding header response data into the input field to split the response in two.  |
| 2        | The attacker controls the first response to redirect the user to a malicious website, while other responses are discarded.|
#### Example Server Code

```java
String author = request.getParameter(AUTHOR_PARAM);
Cookie cookie = new Cookie("author", author);
cookie.setMaxAge(cookieExpiration);
response.addCookie(cookie);
```
#### Attack Example

| **Input**                                       | **Server Response**                                                                                                                                     |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Input = Jason`                                 | HTTP/1.1 200 OK <br> Set-Cookie: author=Jason                                                                                                           |
| `Input = JasonTheHacker\r\nHTTP/1.1 200 OK\r\n` | **First Response (Controlled by Attacker):** <br> Set-Cookie: author=JasonTheHacker <br> HTTP/1.1 200 OK <br> **Second Response:** <br> HTTP/1.1 200 OK |

---

### Web Cache Poisoning Attack

| **Step** | **Description**                                                                                 |
| -------- | ----------------------------------------------------------------------------------------------- |
| 1        | Attacker sends a request to remove the page from the cache.                                     |
| 2        | Server clears the cache and responds normally for `certifiedhacker.com`.                        |
| 3        | Attacker sends a malicious request that generates two responses (malicious and original).       |
| 4        | Server processes the request, causing both the malicious and legitimate responses to be cached. |
| 5        | Attacker sends a separate request for `certifiedhacker.com`, triggering the poisoned cache.     |
| 6        | Server cache now holds the attacker's page as the cached response for `certifiedhacker.com`.    |

### Web Cache Poisoning Attack Summary

- **Definition**: Web cache poisoning targets the reliability of a web cache by replacing cached content with malicious content.
- **Impact**: Users may unknowingly receive poisoned content instead of legitimate data when accessing the cached URL.
- **Objective**: The attacker tricks the server into storing malicious content in the cache, which will be served to users until the cache is cleared.

### Example Malicious Request by Attacker

```http
GET /certifiedhacker.com/index.html HTTP/1.1
Pragma: no-cache
Host: certifiedhacker.com
Accept-Charset: iso-8859-1, utf-8
```

### SSH Brute Force Attack

Utilizes brute force to guess SSH login credentials, potentially gaining unauthorized access.

| **Step** | **Description**                                                                                                      |
|----------|----------------------------------------------------------------------------------------------------------------------|
| 1        | SSH protocols create an encrypted SSH tunnel between two hosts to transfer unencrypted data over an insecure network. |
| 2        | Attackers can brute-force SSH login credentials to gain unauthorized access to an SSH tunnel.                        |
| 3        | SSH tunnels can be used to transmit malware and other exploits to victims without being detected.                    |

---

### SSH Brute Force Attack Summary

- **Definition**: A brute force attack on SSH aims to guess login credentials to establish unauthorized SSH connections.
- **Impact**: Once accessed, SSH tunnels can be used to transfer malicious payloads, compromising other connected servers.
- **Targets**: Common targets include mail servers, application servers, and file servers connected to the SSH server.

User → Internet → SSH Server → Web Server
				            ↳ Mail Server
				            ↳ Application Server
				            ↳ File Server


1. **User** 
   - Connects to the **Internet**
2. **Internet** 
   - Data is routed to the **SSH Server**
3. **SSH Server** 
   - Manages secure connections and forwards legitimate data to **Web Server**
4. **Web Server** 
   - Connects to various internal servers:
     - **Mail Server**
     - **Application Server**
	 - **File Server**

#### Attack Path

- **Attacker**
  - Launches a **Brute-Force Attack** on **SSH Server** to gain unauthorized access.
	  ↳ **After Accessing SSH Server**, the attacker can infiltrate:
		  - **Web Server**
		  - **Mail Server**
		  - **Application Server**
		  - **File Server**

**Note**: Once the attacker gains access to the SSH Server, they can use it as a gateway to compromise other connected internal servers.

---

### Web Server Password Cracking

An attacker tries to exploit weaknesses to hack **well-chosen passwords**.
> Common passwords found include: `password`, `root`, `administrator`, `admin`, `demo`, `test`, `guest`, `qwerty`, pet names, etc.

#tools #hydra #brutus

---
#### Attacker Main Targets
- **SMTP servers**
- **Web shares**
- **SSH tunnels**
- **Web form authentication**
- **FTP servers**

#### Methods Used by Attackers
- **Social Engineering**
- **Spoofing**
- **Phishing**
- Trojan Horse or virus
- Wiretapping
- Keystroke logging

#### Attack Process
- Attackers usually begin with **password cracking** to prove they are valid users to the web server.

#### Cracking Techniques
- Passwords can be cracked:
	  - **Manually** by guessing.
	  - Using dictionary, brute force, or hybrid attacks.
	  - With **automated tools** like THC Hydra and Ncrack.


---

## Web Server Attack Methodology

## **1. Information Gathering**
   - Collecting information about the target server, such as IP addresses, domain names, and publicly available data. 

    (whois, news, bulletin boards, robots.txt, etc)

## **2. Web Server Footprinting**
   - Identifying the server’s structure, technology stack, and configurations to find potential vulnerabilities.

#### #Nmap Commands and NSE (Nmap Scripting Engine) Scripts for Web Server Information Gathering

1. **Discover virtual domains with `hostmap`:**
   ```bash
   nmap --script hostmap <host>
   ```

2. **Detect a server vulnerable to the TRACE method:**
   ```bash
   nmap --script http-trace -p80 localhost
   ```

3. **Harvest email addresses using `http-google-email`:**
   ```bash
   nmap --script http-google-email <host>
   ```

4. **Enumerate users with `http-userdir-enum`:**
   ```bash
   nmap -p80 --script http-userdir-enum localhost
   ```

5. **Detect if HTTP TRACE is enabled:**
   ```bash
   nmap -p80 --script http-trace <host>
   ```

6. **Check for a Web Application Firewall (WAF) or Intrusion Prevention System (IPS):**
   ```bash
   nmap -p80 --script http-waf-detect --script-args="http-waf-detect.uri=/testphp.vulnweb.com/artists.php,http-waf-detect.detectBodyChanges" www.modsecurity.org
   ```

7. **Enumerate common web applications:**
   ```bash
   nmap --script http-enum -p80 <host>
   ```

8. **Retrieve the `robots.txt` file:**
   ```bash
   nmap -p80 --script http-robots.txt <host>
   ```

#### Additional #Nmap Commands for Web Server Analysis

- **Service and OS version detection on a specific target:**
  ```bash
  nmap -sV -O -p80 <target IP>
  ```

- **Scan for common web applications on a specific target:**
  ```bash
  nmap -sV --script http-enum <target IP>
  ```

- **Attempt to login via Microsoft FrontPage on port 80:**
  ```bash
  nmap <target IP> -p80 --script=http-frontpage-login
  ```

- **Look for password files exposed on the server:**
  ```bash
  nmap --script http-passwd <target IP>
  ```

## **3. Website Mirroring**
   - Creating a copy of the target website for offline analysis to identify vulnerabilities and structure.

## **4. Vulnerability Scanning**
   - Using automated tools to scan for known vulnerabilities in the web server and applications.
	   - (dirhunt, dirbuster, etc)

`Dirbuster` is a tool used to brute-force directories and file names on web servers. Here’s a common example of how to use `Dirbuster` to find hidden directories and files on a target web server.

#### Example: Using #Dirbuster to Discover Hidden Directories

Suppose you want to scan a website (`http://example.com`) for hidden directories. Here's how you could do it with Dirbuster:

1. **Launch Dirbuster:**
   If you have Dirbuster installed, you can launch it via the command line:
   ```bash
   dirbuster
   ```

2. **Set Target URL:**
   In the Dirbuster GUI, enter the target URL:
   ```
   http://example.com
   ```

3. **Configure Wordlist:**
   Choose a wordlist to use for brute-forcing. Dirbuster includes several wordlists in `/usr/share/dirbuster/wordlists/` if you're using Kali Linux. For example, you could select:
   ```
   /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
   ```

4. **Configure Options (Optional):**
   - **Threads**: Increase the number of threads to speed up the scan. For example, setting threads to 50 can make the scan faster (but it may increase load on the server).
   - **File Extensions**: You can add file extensions to search for specific types of files, like `.php`, `.html`, `.txt`, etc.

5. **Run the Scan:**
   Click **Start** to begin the scan. Dirbuster will begin brute-forcing directories and files on the target server.

#### Sample Output
As Dirbuster runs, it will display the results in real-time, listing any discovered directories or files that are accessible on the web server. For example:

```
/admin
/login
/uploads
/backup.zip
/config.php
```

#### Example Command-Line Usage
If you prefer command-line, here’s how to use `Dirbuster` with a wordlist in headless mode:

```bash
dirbuster -u http://example.com -l /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 50
```

- `-u` specifies the target URL.
- `-l` specifies the path to the wordlist.
- `-t` sets the number of threads.

#### Explanation
Dirbuster will try each word in the specified wordlist as a directory or file name on the target URL. If it finds a match, it will display it in the output, allowing you to see hidden or sensitive directories that may not be linked publicly.

#### Practical Use Case
Dirbuster is often used in penetration testing to find unlisted or sensitive directories like `/admin`, `/backup`, `/test`, or files like `config.php` that may contain valuable information or allow further access.

## **5. Session Hijacking**
   - Taking over a user session by stealing or predicting session tokens to gain unauthorized access. *Refer to Module 11: Session Hijacking*
   
	`Burp Suite`

	JHijack
	Ettercap
	CookieCatcher
	Cookie Cadger

## **6. Web Server Passwords Hacking**
   - Attempting to crack or guess passwords to gain access to restricted areas of the server.

	Hashcat (https://hashcat.net)
	THC Hydra
	Ncrack (https://nmop.org)
	Rainbow crack (https://project-rainbowcrock.com)
	Wfuzz (http://www.edge-security.com)
	Wireshark (https;//www.wireshark.org)


---

## Featured Hacking Tools
- **Nmap**: Network scanning and discovery tool.
- **THC Hydra**: Brute force tool for password cracking.
- **Metasploit**: Comprehensive exploitation framework.

### #Metasploit

**Source**: [Metasploit Website](https://www.metasploit.com)

The **Metasploit Framework** is a powerful toolkit used for penetration testing, exploit development, and security research. It contains hundreds of remote exploits for various platforms, allowing security professionals to automate attacks on web servers by exploiting known vulnerabilities and leveraging weak credentials across services like Telnet, SSH, HTTP, and SNMP.

#### Key Features of Metasploit for Web Server Attacks

An attacker may utilize the following Metasploit features to compromise web servers:

- **Closed-loop vulnerability validation** – Verifies vulnerabilities to confirm successful exploitation.
- **Phishing simulations** – Tests users' susceptibility to phishing attacks.
- **Social engineering** – Uses techniques to manipulate users for information or access.
- **Manual brute forcing** – Attempts to guess passwords for access to services.
- **Manual exploitation** – Manually deploys exploits to attack specific vulnerabilities.
- **Defense evasion** – Avoids detection by security systems like firewalls and intrusion detection/prevention systems.

#### Benefits of Metasploit for Penetration Testers

Metasploit enables penetration testers to:

- **Automate repetitive tasks** and leverage multi-level attacks for faster penetration testing.
- **Evaluate the security of web applications**, networks, endpoints, and email users.
- **Tunnel traffic through compromised hosts**, allowing pivoting deeper into the network.
- **Generate customized reports**, including executive summaries, audit findings, and technical details.

#### Metasploit Framework Architecture

| **Category**                   | **Components / Description**                                                                               |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------- |
| **Libraries**                  | - Rex <br> - Framework-Core <br> - Framework-Base                                                          |
| **Connections**                | - Custom plug-ins interact with Libraries and Framework-Core <br> - Protocol Tools interact with Libraries |
| **Interfaces**                 | - msfconsole <br> - msfcli <br> - msfweb <br> - msfwx <br> - msfapi                                        |
| **Security Tools Integration** | - Web Services connect Interfaces with Modules                                                             |
| **Modules**                    | - Exploits <br> - Payloads <br> - Encoders <br> - NOP Generators <br> - Auxiliary                          |

![Apache Architecture](Images/Pasted%20image%2020241114162329.png)

The Metasploit Framework is an open-source exploitation framework designed for rapid development and reuse of security tools. Its modular architecture includes components for:

- **Exploit development** – Allows easy creation of new exploits by reusing code.
- **Payloads and encoders** – Provides standardized components for delivering and obfuscating payloads.
- **NOP generators and reconnaissance tools** – Supports preparation and information gathering.
- **Core framework** – Manages essential interactions with exploit modules, sessions, and plugins.

### Metasploit Modules

Metasploit provides several key modules, each with specific functions for penetration testing and exploitation. Here’s a breakdown of the primary modules:
#### 1. **Metasploit Exploit Module**

The **Exploit Module** is a fundamental part of Metasploit. It allows users to target various platforms with single exploits and provides basic meta-information fields to configure attacks. Using the **Mixins** feature, users can dynamically modify exploit behavior, perform brute-force attacks, and execute passive exploits.

### **Steps to Use an Exploit Module:**

1. Configure an active exploit.
2. Verify exploit options.
3. Select a target.
4. Choose a payload.
5. Launch the exploit.

#### 2. **Metasploit Payload Module**

A **payload** is delivered as part of an exploit to execute specific actions on the target system. Metasploit offers three types of payloads:

- **Singles**: Standalone and self-contained, performing a single action.
- **Stagers**: Set up a network connection between the attacker and victim.
- **Stages**: Downloaded and executed by stager modules, enabling more complex actions.

The **Payload Module** can handle tasks such as uploading and downloading files, taking screenshots, and collecting password hashes. It establishes a communication channel between the Metasploit framework and the victim’s host, allowing remote control of the target’s screen, mouse, and keyboard.

**Example Command to Generate Payloads:**
```bash
msf > use payload_name
msf payload(payload_name) > generate -t c -f payload.c
```

#### 3. **Metasploit Auxiliary Module**

**Auxiliary Modules** perform additional functions that do not involve exploitation. These modules can be used for actions such as port scanning, denial-of-service (DoS) attacks, and fuzzing. Auxiliary modules are stored in the `modules/auxiliary/` directory and can be listed using the `show auxiliary` command in Metasploit.

**Common Auxiliary Module Functions:**
- Scanning (e.g., port scanning)
- DoS attacks
- Fuzzing for vulnerabilities

**Example Commands:**
```bash
msf > show auxiliary       # List all auxiliary modules
msf > use auxiliary/scanner/portscan/tcp
msf auxiliary(portscan/tcp) > run
```

**Basic Structure of an Auxiliary Module:**
```ruby
require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  # Auxiliary module code here
end
```

---

#### 4. **Metasploit NOPS Module**

**NOP (No Operation) Modules** generate a "NOP sled," which fills buffer space and ensures reliable execution of payloads. The `generate` command can create NOP sleds of specified sizes in various formats.

**Options for NOP Generation:**
- `-b <opt>`: Characters to avoid (e.g., `'\x00\xff'`)
- `-h`: Display help information
- `-s <opt>`: Registers to save
- `-t <opt>`: Output type (e.g., Ruby, Perl, C, raw)

**Example Commands:**
```bash
msf > use x86/opty2
msf nop(opty2) > generate -h               # Display help for generate command
msf nop(opty2) > generate -t c 50          # Generate a 50-byte NOP sled in C format
```

**Example 50-byte NOP Sled Output:**
```c
unsigned char buf[] = 
"\xf5\x3d\x05\x15\xf8\x67\xba\x7d\x08\xd6\x66\x9f\xb8\x2d\xb6"
"\x24\xbe\xb1\x3f\x43\x1d\x93\xb2\x37\x35\x84\xd5\x14\x40\xb4"
"\xb3\x41\xb9\x48\x04\x99\x46\xa9\xb0\xb7\x2f\xfd\x96\x4a\x98"
"\x92\xb5\xd4\x4f\x91";
```

---

Each of these modules provides essential functionalities for penetration testing and exploitation, allowing users to customize and execute attacks based on their needs. Metasploit’s modular design facilitates code reuse, making it a versatile and efficient tool for security testing.

The framework is built to support vulnerability research, exploit development, and the creation of custom security tools, making it an essential platform for security professionals. Its modular design promotes code reuse, simplifying the process of building new exploits and security testing tools.

### **Other tools:**

- **Immunity** CANVAS (https://www.immunityinc.com)
- **HULK DoS**
- **MPack**
- **w3af**
- **Arachni** (https://www .arachni-scanner.com)
- **WebSurgery** (https://sunrisetech.gr)
- **Mitmprox** (https:j /mitmproxy.org)
- **Webalizer** (https://webalizer.net)

---

## **Featured Defence Tools**
- **Fail2Ban**: Protects against brute force attacks.
- **ModSecurity**: Web application firewall for filtering and monitoring.
- **OpenVAS**: Open-source vulnerability scanning tool.

#### Web application security scanners: 

- Syhunt Hybrid (https://www.syhunt.com)
- N-Stalker X (https://www.nstalker.com)
- lnvicti (https://www.invicti.com)
- Burp Suite (https://www.portswigger.net)
- Wapiti (https://wapiti-scanner.github.io)
- WebScarab (https://www.owasp.org)
- WPSec (https://wpsec.com)
- Tinfoil Security (https://www.tinfoilsecurity.com)
- Skipfish (https://code.google.com)
- Detectify (https://detectify.com)
- Fortify on Demand (https://www.microfocus.com)
- OWASP Zed Attack Proxy (ZAP) (https://www.zoproxy.org)
- SonarQube (https://www.sonarqube .org)
- Arachni (https://www.arachni-scanner.com)
- w3af (https://w3aforg)
- Grabber (http://rgaucher.info)
- Vega (https://subgroph.com)

#### Security scanners:

- Qualys Community Edition Source (https://www.qualys.com)
- Observatory (https://observatory.mozilla.org)
- Word Press Security Scan (https://hackertarget.com)
- Web Vulnerability Scanner (https://pentest-too/s.com)
- Nikto2 (https://cirt.net)
- lmmuniWeb (https://www.immuniweb.com)

#### Malware infection monitoring tools:

- Sucuri SiteCheck (https://sucuri.net)
- Sitelock Malware Removal (https://www.sitelock.com)
- Quttera (https://quttera.com)
- Web Inspector(https://www.webinspector.com)
- SiteGuarding (https://www.siteguarding.com)

#### Web Server Security Tools

Fortify Weblnspect (https://www.microfocus.com)
Acunetix Web Vulnerability Scanner (https://www.acunetix.com)
NetlQ Secure Configuration Manager (https://www.netiq.com)
SAINT Security Suite (https://www.carson-saint.com)
Sophos Intercept X for Server (https://www.sophos.com)
UpGuard (https://www.upguard.com)

##### [Hacking Web Servers Countermeasures ↗](13.1-Hacking_Web_Servers_Countermeasures.md)

---

## Summary
Web server security encompasses a broad range of practices and tools designed to protect against various types of attacks. Regularly updating configurations, monitoring for vulnerabilities, and implementing robust defenses are crucial for maintaining server integrity.