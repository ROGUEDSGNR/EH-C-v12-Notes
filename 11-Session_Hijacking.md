# **Session Hijacking**

> #TLDR
> Session hijacking is a cybersecurity threat where an attacker takes over an active session between a user and a server, impersonating the legitimate user and gaining unauthorized access to resources. Understanding and mitigating session hijacking is essential for securing user sessions on web applications.

---

## **What We Get From This Exercise**
###### #Objectives #Session-Hijacking

- Gain a deep understanding of session hijacking concepts.
- Learn to identify vulnerabilities in session management.
- Understand application-level and network-level hijacking methods.
- Familiarize with tools used for hijacking and countering such attacks.
- Practice real-world scenarios to reinforce defensive strategies.

---

## **Table of Contents**

1. [Session Hijacking Concepts](#session-hijacking-concepts)
	1. [What is Session Hijacking?](#what-is-session-hijacking)
	2. [Packet Analysis of a Local Session Hijack](#packet-analysis-of-a-local-session-hijack)
2. [Application-Level Session Hijacking](#application-level-session-hijacking)
	1. [Methods to Compromise Session Tokens](#methods-to-compromise-session-tokens)
		1. [Session sniffing](#session-sniffing)
		2. [Predictable session token](#predictable-session-token)
		3. [Man-in-the-middle attack](#man-in-the-middle-attack)
		4. [Man-in-the-browser attack](#man-in-the-browser-attack)
		5. [Cross-site scripting (XSS) attack](#cross-site-scripting-xss-attack)
		6. [Cross-site request forgery attack](#cross-site-request-forgery-attack)
		7. [Session replay attack](#session-replay-attack)
		8. [Session fixation attack](#session-fixation-attack)
		9. [CRIME attack](#crime-attack)
		10. [Forbidden attack](#forbidden-attack)
		11. [Session donation attack](#session-donation-attack)
		12. [PetitPotam hijacking](#petitpotam-hijacking)
3. [Network-Level Session Hijacking](#network-level-session-hijacking)
	1. [Techniques](#techniques)
		1. [Blind hijacking](#blind-hijacking)
		2. [RST hijacking](#rst-hijacking)
		3. [UDP hijacking](#udp-hijacking)
		4. [Packet sniffer](#packet-sniffer)
		5. [TCP/IP hijacking](#tcpip-hijacking)
		6. [IP spoofing: Source routed packets](#ip-spoofing-source-routed-packets)
4. [Session Hijacking Tools](#session-hijacking-tools)
5. [Session Hijacking Countermeasures](#session-hijacking-countermeasures)
	1. [Session Hijacking Detection Methods](#session-hijacking-detection-methods)
		1. [Manual Method](#manual-method)
		2. [Automatic Method](#automatic-method)
  1. [Session Hijacking Prevention Tools](#session-hijacking-prevention-tools)

---

## **Session Hijacking Concepts**

### What is Session Hijacking?
Session hijacking occurs when an attacker intercepts and takes control of a valid session between a client and server. This process allows the attacker to impersonate the user and access resources without authentication.

#### Use Case
If an attacker can intercept a session ID from a user's connection to a vulnerable application, they can impersonate the user. For example, an attacker on the same network as a user might capture session cookies and reuse them to access the application.

#### Code Snippet (Python - Example of Session Hijacking Detection)
```python
import requests

def monitor_session(session_url, session_id):
    headers = {'Authorization': f'Session {session_id}'}
    response = requests.get(session_url, headers=headers)
    if response.status_code == 401:
        print("Possible session hijack detected!")
    else:
        print("Session is secure.")

# Example usage
monitor_session("http://example.com/api/user", "fake_session_id")
```

### Packet Analysis of a Local Session Hijack
Packet analysis allows attackers to exploit and control sessions by examining and manipulating packet data.

| **Packet Type** | **Sequence** | **Description**               |
|-----------------|--------------|-------------------------------|
| SYN             | 1200         | Initial handshake request     |
| ACK             | 1501         | Acknowledgment by server      |
| DATA            | 128          | Data transmitted by user      |

---

## **Application-Level Session Hijacking**

### Methods to Compromise Session Tokens

#### Session sniffing
Session sniffing captures session tokens from network traffic using tools like Wireshark.

```bash
# Wireshark filter to capture HTTP session tokens
http.cookie contains "sessionid="
```

#### Predictable session token
Weak session-token generation algorithms create predictable patterns, which attackers can exploit to guess valid session tokens.

#### Man-in-the-middle attack
In MITM attacks, attackers intercept and potentially alter communication between client and server.

```bash
# Bettercap command to launch a basic MITM attack
bettercap -X -T <target_ip> --sniffer-output session_data.pcap
```

#### Man-in-the-browser attack
A Trojan intercepts browser communications, typically targeting financial transactions.

#### Cross-site scripting (XSS) attack
XSS injects malicious scripts into web pages, often to capture session cookies.

```html
<!-- Example of a simple XSS payload -->
<script>alert(document.cookie);</script>
```

#### Cross-site request forgery attack
CSRF tricks the user's browser into making requests on behalf of the attacker.

#### Session replay attack
The attacker reuses a captured session token to access resources as the legitimate user.

#### Session fixation attack
The attacker tricks the user into logging in with a session ID they control.

#### CRIME attack
CRIME exploits compression vulnerabilities to intercept sensitive data, such as session tokens.

#### Forbidden attack
An advanced bypass of authorization controls, often by exploiting session tokens.

#### Session donation attack
In this technique, the attacker provides a session ID to the user to trick them into performing actions.

#### PetitPotam hijacking
This attack exploits authentication mechanisms, redirecting session tokens to the attacker.

---

## **Network-Level Session Hijacking**

### Techniques

#### Blind hijacking
The attacker injects data into a session without being able to view responses, often by guessing sequence numbers.

#### RST hijacking
RST hijacking uses reset (RST) packets to disrupt ongoing sessions.

#### UDP hijacking
UDP sessions are vulnerable to hijacking due to the connectionless nature of the protocol.

#### Packet sniffer
Packet sniffers, such as Wireshark, capture and analyse traffic for vulnerabilities.

#### TCP/IP hijacking
TCP/IP hijacking takes control of TCP sessions by manipulating packet data.

#### IP spoofing: Source routed packets
The attacker sends packets with a forged IP address, redirecting responses.

---

## **Session Hijacking Tools**

| **Tool**                | **Description**                                 |
| ----------------------- | ----------------------------------------------- |
| **Hetty**               | A web crawler for finding vulnerabilities.      |
| **Bettercap**           | A powerful network attack tool for MITM.        |
| **OWASP ZAP**           | Security testing tool with session management.  |
| **Burp Suite**          | Web security tool for penetration testing.      |
| **Jnetool Toolkit**     | Assists with session hijacking techniques.      |
| **WebSploit Framework** | A framework for various network attacks.        |
| **sslstrip**            | Hijacks HTTPS connections, downgrading to HTTP. |
| **JHijack**             | Dedicated hijacking tool for targeted attacks.  |
| **FaceNiff**            | Hijacks WiFi sessions (Android).                |
| **DroidSniff**          | Another Android tool for WiFi session hijacking |
| **Wireshark**           | Network analyser for packet capture.            |
| **USM Anywhere**        | Offers session monitoring and detection.        |

---

## Session Hijacking Countermeasures

### Session Hijacking Detection Methods

#### Manual Method
The manual method involves direct observation of session anomalies and unusual user behaviour, usually through log analysis and network packet inspection.

- **Log Analysis**: Inspect server and application logs for signs of session reuse, unusual IP changes during sessions, or multiple logins with the same session ID. Suspicious activities can include:
  - Rapidly changing IP addresses in short timeframes.
  - Sessions with abnormally long durations or unexpected idle times.

- **Network Packet Analysis**: Tools like **Wireshark** or **tcpdump** are used to capture and analyse network traffic for hijacking indicators, such as duplicate sessions or unexpected session tokens.

```bash
# Using tcpdump to capture HTTP traffic on port 80
sudo tcpdump -i eth0 'tcp port 80' -w http_capture.pcap
```

#### Automatic Method
Automated solutions use monitoring systems and behavioural analytics to detect suspicious session activities in real time.

1. **Intrusion Detection Systems (IDS)**: IDS tools like **Snort** and **Suricata** can detect and alert on abnormal traffic patterns associated with session hijacking.

   ```bash
# Example Snort rule for detecting session hijacking attempts
alert tcp any any -> any 80 (msg:"Session Hijacking Attempt Detected"; content:"Set-Cookie"; nocase; pcre:"/session_id/"; sid:1000001;)
   ```

2. **behavioural Analysis**: Advanced security solutions apply machine learning to analyse user behaviour and flag anomalies. For example:
   - **Splunk**: Logs session behaviours and applies machine learning to detect unusual patterns.
   - **Darktrace**: Uses AI to build behavioural profiles of users and detects deviations from established norms.

3. **Session Timeout Policies**: Automate session expiration to reduce the impact of hijacked sessions by implementing session lifetimes based on inactivity. Most web application frameworks offer configuration settings for session expiration.

---

### Session Hijacking Prevention Tools

| **Tool**                   | **Description**                                                                                                                          |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| **CxSAST**                 | A static analysis tool for identifying vulnerabilities in code, including weak session management practices.                             |
| **Fiddler**                | Acts as a proxy to analyse and secure session data in web applications, particularly helpful for monitoring cookies and session tokens.  |
| **OWASP Dependency-Check** | Scans for outdated dependencies with vulnerabilities related to session management.                                                      |
| **ModSecurity (WAF)**      | A web application firewall that can help detect and block session hijacking attempts by inspecting HTTP traffic.                         |
| **Burp Suite**             | Provides extensive options to test session management and security measures in web applications.                                         |
| **Security Headers**       | Use HTTP headers to secure sessions: `Set-Cookie`, `SameSite`, `HttpOnly`, and `Secure` attributes reduce the risk of session hijacking. |

---

### Example Configurations and Techniques

#### Secure Session Cookie Attributes
Setting secure attributes on cookies helps prevent session tokens from being intercepted or misused.

- **HttpOnly**: Prevents JavaScript access to cookies, reducing XSS risks.
- **Secure**: Ensures cookies are sent over HTTPS only, preventing interception on HTTP connections.
- **SameSite**: Controls cross-site request behaviours, reducing CSRF vulnerabilities.

```http
Set-Cookie: sessionID=abc123; HttpOnly; Secure; SameSite=Strict
```

#### Multi-Factor Authentication (MFA)
MFA adds a second layer of security to authentication, making it difficult for attackers to hijack sessions even if they have valid session IDs.

- **Example**: Google Authenticator or Authy can be used for one-time passwords (OTPs) that expire after a short period.

#### TLS/SSL Encryption
Encrypting data in transit prevents eavesdropping and session interception.

- **Command to Generate SSL Certificate**:
   ```bash
openssl req -newkey rsa:2048 -nodes -keyout mydomain.key -x509 -days 365 -out mydomain.crt
   ```

#### Session ID Regeneration
Regenerate session IDs upon login and periodically to reduce the chance of session fixation and replay attacks.

- **Example in PHP**:
```php
session_start();
session_regenerate_id(true); // Regenerate session ID
   ```

#### Limiting Session Lifetime and Expiry
Configure sessions to expire after a specified duration of inactivity to limit the window for attackers.

- **Example in Express.js**:
   ```javascript
app.use(session({
   secret: 'mySecret',
   cookie: { maxAge: 60000 }, // Session expires after 1 minute
   resave: false,
   saveUninitialized: true
}));
   ```

#### Detection and Blocking Tools

1. **Suricata Rule for Suspicious Traffic**:
   - Detect anomalies such as frequent IP changes for the same session ID:
     ```yaml
     alert http any any -> any any (msg:"Session Hijacking - Multiple IP for Single Session"; flow:from_server,established; content:"Set-Cookie"; pcre:"/session_id/"; threshold: type threshold, track by_dst, count 5, seconds 30; sid:100002;)
     ```

2. **ModSecurity WAF Rules**:
   - Example rule to block requests from suspicious user-agents or IP addresses, indicating hijacking:
     ```apache
     SecRule REQUEST_HEADERS:User-Agent "evil-hijacker" "id:100001,phase:1,deny,status:403,msg:'Suspicious User Agent'"
     ```

3. **Use of Security Information and Event Management (SIEM)**:
   - **Splunk** and **QRadar**: Track and analyse session-related logs in real time. Anomalies like unusual IP or device changes can trigger alerts.

---

### Other Countermeasures

#### Content Security Policy (CSP)
Use CSP to restrict the sources from which content is loaded, reducing the risk of XSS attacks that can steal session cookies.

- **Example CSP Header**:

```text
Content-Security-Policy: default-src 'self'; script-src 'self'
```

#### Cross-Origin Resource Sharing (CORS)
CORS policies limit which domains can make requests to your server, reducing the risk of CSRF attacks.

- **Example in Express.js**:
   ```javascript
const cors = require('cors');
app.use(cors({ origin: 'https://trusteddomain.com' }));
   ```

#### Implementing Session Locking
Lock sessions to a specific IP address or device, rejecting any request for the session from a new source.

#### DNS Security Extensions (DNSSEC)
DNSSEC can be used to prevent DNS hijacking attacks that may lead to session hijacking by redirecting users to malicious websites.

---

### Summary of Key Commands and Tools

| **Method**                    | **Tool**            | **Command/Code**                                                     |
|-------------------------------|---------------------|----------------------------------------------------------------------|
| **Manual Detection**          | Wireshark/tcpdump   | `tcpdump -i eth0 'tcp port 80' -w capture.pcap`                      |
| **Automatic Detection**       | Snort/Suricata      | Snort rule for session hijacking detection                           |
| **Session Expiry**            | Express.js          | `app.use(session({ cookie: { maxAge: 60000 } }))`                    |
| **Cookie Security**           | Secure attributes   | `Set-Cookie: sessionID=abc123; HttpOnly; Secure; SameSite=Strict`    |
| **WAF Rule Blocking**         | ModSecurity         | `SecRule REQUEST_HEADERS:User-Agent "evil-hijacker" ...`             |
| **Encryption**                | OpenSSL             | `openssl req -newkey rsa:2048 -nodes -keyout mydomain.key ...`       |
| **Session ID Regeneration**   | PHP                 | `session_regenerate_id(true);`                                       |
| **CSP**                       | CSP Header          | `Content-Security-Policy: default-src 'self'; script-src 'self'`      |
| **CORS Policy**               | Express.js + CORS   | `app.use(cors({ origin: 'https://trusteddomain.com' }));`            |

---

These countermeasures help secure sessions against hijacking by ensuring only authorized users can access valid sessions and by actively monitoring for unusual session behaviour.

---

## **Featured Hacking Tools**

- **Bettercap**: Used for conducting MITM attacks by capturing network traffic in real time.
- **sslstrip**: Intercepts HTTPs traffic and downgrades it to HTTP, exposing sensitive data.
- **FaceNiff**: Effective for session hijacking on WiFi networks, often used on Android.

## **Featured Defence Tools**

- **Wireshark**: Network analyser with session-monitoring capabilities.
- **Burp Suite**: Offers robust session management and testing features to detect vulnerabilities.
- **Fiddler**: Helps identify session vulnerabilities and provides detailed session logging.

---

## **Summary**
Session hijacking is a critical security threat, particularly in web applications where user sessions are valuable targets. By understanding the methods attackers use, such as application-level and network-level attacks, cybersecurity professionals can better safeguard systems. Using a combination of tools like Wireshark for monitoring and Burp Suite for testing, one can detect and mitigate these threats effectively, ensuring session security remains intact.
