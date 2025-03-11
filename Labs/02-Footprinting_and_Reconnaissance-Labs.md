# Lab Tasks Checklist: Footprinting and Reconnaissance

## Lab 1: Perform Footprinting Through Search Engines

### **Lab Scenario**

As an ethical hacker, gather information about a target organization using search engines. This can include advanced Google searches, video searches, and other resources to extract critical organizational data.

### **Lab Objectives**

- Use advanced Google hacking techniques to gather data.
- Collect information from video search engines.
- Extract data from FTP search engines.
- Identify Internet of Things (IoT) vulnerabilities via search engines.

### **Lab Environment**

- Windows 11 virtual machine
- Web browsers with an Internet connection
- Administrator privileges to run the tools

### **Checklist**

- [ ]  Set up the Windows 11 virtual machine.
- [ ]  Perform advanced Google searches using operators like `intitle:`, `filetype:`, etc.
- [ ]  Use video search engines (e.g., YouTube Metadata tool) to gather organizational data.
- [ ]  Query FTP search engines for publicly accessible files and documents.
- [ ]  Investigate IoT vulnerabilities using search engines like Shodan or Censys.

---

## Lab 2: Perform Footprinting Through Web Services

### **Lab Scenario**

Extract critical information such as domains, subdomains, emails, and infrastructure details using various online web services.

### **Lab Objectives**

- Discover the company's domains and subdomains.
- Collect personal information via people search services.
- Compile an email list using tools like theHarvester.
- Perform deep and dark web searches for sensitive data.

### **Lab Environment**

- Windows 11 virtual machine
- Parrot Security virtual machine
- Web browsers with an Internet connection
- Administrator privileges to run the tools

### **Checklist**

- [ ]  Identify domains and subdomains using tools like Netcraft.
- [ ]  Gather personal information from PeekYou or other people search services.
- [ ]  Use theHarvester to extract emails and subdomains.
- [ ]  Conduct deep and dark web searches using Tor Browser.

---

## Lab 3: Perform Footprinting Through Social Networking Sites

### **Lab Scenario**

Gather personal and professional data from employees using social networking sites. This information can support social engineering and advanced attack strategies.

### **Lab Objectives**

- Extract employee details from LinkedIn using theHarvester.
- Search for individuals across social networking platforms with Sherlock.
- Use Followerwonk to analyze social network connections.

### **Lab Environment**

- Windows 11 virtual machine
- Parrot Security virtual machine
- Web browsers with an Internet connection
- Administrator privileges to run the tools

### **Checklist**

- [ ]  Use LinkedIn to identify key employees and their positions.
- [ ]  Employ Sherlock to gather data from other social networks.
- [ ]  Analyze followers and connections with Followerwonk.

---

## Lab 4: Perform Website Footprinting

### **Lab Scenario**

Explore a target organization’s website to gather detailed insights into its infrastructure, technology stack, and subdomains.

### **Lab Objectives**

- Gather details about the target website using tools like Ping, Photon, or GRecon.
- Extract company data using Web Data Extractor.
- Mirror the target website for offline analysis with HTTrack.
- Generate a word list for brute-force attacks using CeWL.

### **Lab Environment**

- Windows 11 virtual machine
- Web browsers with an Internet connection
- Administrator privileges to run the tools

### **Checklist**

- [ ]  Collect website information using command-line utilities and online tools.
- [ ]  Use HTTrack to mirror the website.
- [ ]  Create a word list using CeWL for potential attacks.

---

## Lab 5: Perform Email Footprinting

### **Lab Scenario**

Analyze email headers and trace email sources to collect information about the target organization.

### **Lab Objectives**

- Trace emails to uncover IP addresses, domains, and server details.

### **Lab Environment**

- Windows 11 virtual machine
- Web browsers with an Internet connection
- Administrator privileges to run the tools

### **Checklist**

- [ ]  Trace emails using tools like eMailTrackerPro.
- [ ]  Document findings from email header analysis.

---

## Lab 6: Perform Whois Footprinting

### **Lab Scenario**

Extract detailed Whois information to learn more about the domain ownership and related technical details.

### **Lab Objectives**

- Perform Whois lookups using tools like DomainTools.

### **Lab Environment**

- Windows 11 virtual machine
- Web browsers with an Internet connection

### **Checklist**

- [ ]  Run Whois queries for target domains.
- [ ]  Analyze the results to identify ownership and technical details.

---

## Lab 7: Perform DNS Footprinting

### **Lab Scenario**

Collect DNS records and identify subdomains to understand the target's network structure.

### **Lab Objectives**

- Use DNS utilities like `nslookup` to extract DNS information.
- Perform reverse DNS lookups.

### **Lab Environment**

- Windows 11 virtual machine
- Web browsers with an Internet connection

### **Checklist**

- [ ]  Query DNS records using `nslookup`.
- [ ]  Perform reverse lookups to identify linked domains.

---
---
# Step-by-Step

# **Lab 1: Perform Footprinting Using Tools**

## **Task 1: Gather Information Using Whois**

1. **Log in to the Windows 11 VM.**
    
    - Start the virtual machine and log in using administrative credentials.
2. **Navigate to Whois Lookup.**
    
    - Open a browser and visit [Whois.com](https://www.whois.com/whois/).
3. **Perform a Whois lookup.**
    
    - Enter the target domain name (e.g., `example.com`) in the search bar and click **Lookup**.
4. **Analyze the output.**
    
    - Note:
        - Domain registrar details.
        - Registrant name and organization.
        - Registration and expiration dates.
        - Name servers.
    - Identify any exposed email addresses or contact details.
5. **Document findings.**
    
    - Save the results to a text file or take screenshots for your report.

---

## **Task 2: Perform DNS Queries Using nslookup**

1. **Open the Command Prompt.**
    
    - Press `Win + R`, type `cmd`, and hit Enter.
2. **Perform a standard query.**
    
    - Enter the following:
        
        ```bash
        nslookup example.com
        ```
        
    - Record the IP address and DNS server details.
3. **Query for specific record types.**
    
    - MX (Mail Exchange):
        
        ```bash
        nslookup -type=mx example.com
        ```
        
    - NS (Name Server):
        
        ```bash
        nslookup -type=ns example.com
        ```
        
    - Document all returned information.

---

## **Task 3: Perform Zone Transfers Using dig**

1. **Open a terminal on Parrot Security.**
    
    - Log in as root.
2. **Identify the target domain’s DNS server.**
    
    - Execute:
        
        ```bash
        dig example.com ns
        ```
        
3. **Attempt a zone transfer.**
    
    - Use the DNS server’s IP to perform the transfer:
        
        ```bash
        dig axfr @<DNS_server_IP> example.com
        ```
        
    - Record any returned data, such as subdomains or IP mappings.

---

## **Task 4: Discover Subdomains Using Sublist3r**

1. **Launch Sublist3r.**
    
    - Navigate to its installation directory and open a terminal.
2. **Run Sublist3r for subdomain enumeration.**
    
    - Execute:
        
        ```bash
        python3 sublist3r.py -d example.com
        ```
        
3. **Document discovered subdomains.**
    
    - Save the results to a file or directly copy them into your notes.

---

## **Task 5: Collect Email Addresses Using theHarvester**

1. **Open theHarvester on Parrot Security.**
    
    - Ensure you are in theHarvester’s directory.
2. **Run theHarvester.**
    
    - Execute:
        
        ```bash
        theHarvester -d example.com -b google
        ```
        
    - Replace `example.com` with the target domain.
3. **Review and document email addresses.**
    
    - Note any discovered emails, along with associated metadata.

---

## **Task 6: Perform OSINT Using Maltego**

1. **Launch Maltego.**
    
    - Open the application on Parrot Security and log in to your account.
2. **Create a new graph.**
    
    - Add the target entity (e.g., domain or IP) as the initial node.
3. **Run transforms.**
    
    - Right-click the node and select **Run Transforms**.
    - Choose transforms like DNS lookup, email enumeration, or social media search.
4. **Analyze and document findings.**
    
    - Save the graph and list any valuable relationships or entities.

---

# **Lab 2: Perform Reconnaissance Using Google Hacking Techniques**

## **Task 1: Use Google Dorks to Locate Sensitive Information**

1. **Open a browser.**
    
    - Navigate to [Google.com](https://www.google.com/).
2. **Run Google dork queries.**
    
    - Example queries:
        - Find login pages: `intitle:"Login Page" site:example.com`
        - Expose directories: `intitle:index.of site:example.com`
        - Search for sensitive files: `site:example.com filetype:pdf`
3. **Analyze and document results.**
    
    - Record URLs that lead to sensitive data.

---

## **Task 2: Search for Publicly Available Data**

1. **Locate email addresses.**
    
    - Use:
        
        ```text
        "email" site:example.com
        ```
        
2. **Search for exposed configuration files.**
    
    - Example query:
        
        ```text
        inurl:config site:example.com
        ```
        
3. **Record findings.**
    
    - Save URLs, email addresses, or exposed file paths for later analysis.

---

# **Lab 3: Perform Social Media Reconnaissance**

## **Task 1: Gather Information from LinkedIn**

1. **Open LinkedIn in a browser.**
    
    - Log in to your account.
2. **Search for the target company or employees.**
    
    - Use the search bar to find profiles related to the organization.
3. **Analyze profiles.**
    
    - Look for:
        - Job titles and roles.
        - Connections to other companies.
        - Posted documents or links.
4. **Document findings.**
    
    - Note useful details such as employee email patterns.

---

## **Task 2: Collect Data from Facebook and Twitter**

1. **Open Facebook and Twitter.**
    
    - Use search tools to find the target organization or employees.
2. **Analyze posts and shared content.**
    
    - Look for:
        - Event announcements.
        - Locations or pictures revealing sensitive data.
3. **Document key findings.**
    
    - Record exposed data for further use.

---

# **Lab 4: Use Shodan for Reconnaissance**

## **Task 1: Search for IoT Devices**

1. **Log in to Shodan.io.**
    
    - Create an account if needed.
2. **Search for exposed IoT devices.**
    
    - Use queries like:
        
        ```text
        port:22
        ```
        
        or
        
        ```text
        http.title:"Webcam"
        ```
        
3. **Analyze results.**
    
    - Record IP addresses and device types.

---

## **Task 2: Discover Misconfigured Services**

1. **Search for services running on default ports.**
    
    - Example query:
        
        ```text
        port:3306
        ```
        
        (MySQL servers)
2. **Document misconfigured services.**
    
    - Note vulnerabilities or access points.

---
# **Lab 5: Perform Footprinting Using Tools**

## **Task 1: Enumerate Target with FOCA**

1. **Launch FOCA on Windows 11.**
    
    - Open the application from the start menu or desktop.
2. **Add the target domain.**
    
    - Enter the domain name (e.g., `example.com`) in the target field.
3. **Run metadata analysis.**
    
    - FOCA will analyze publicly available documents and extract metadata.
4. **Document findings.**
    
    - Note details like usernames, email addresses, software versions, and other metadata from the documents.

---

## **Task 2: Collect Open-Source Intelligence (OSINT) with Recon-ng**

1. **Launch Recon-ng on Parrot Security.**
    
    - Open a terminal and type:
        
        ```bash
        recon-ng
        ```
        
2. **Set the target domain.**
    
    - Run:
        
        ```bash
        workspaces create example
        add domains example.com
        ```
        
3. **Run reconnaissance modules.**
    
    - Use modules like:
        
        ```bash
        marketplace install whois_pocs
        marketplace install bing_domain_web
        ```
        
    - Execute them:
        
        ```bash
        run whois_pocs
        run bing_domain_web
        ```
        
4. **Document collected information.**
    
    - Save output related to subdomains, emails, or associated entities.

---

# **Lab 6: Perform Network Reconnaissance**

## **Task 1: Identify Open Ports Using Nmap**

1. **Open a terminal on Parrot Security.**
    
    - Ensure the network is set up to access the target system.
2. **Perform a quick scan.**
    
    - Run:
        
        ```bash
        nmap -sS <target_IP>
        ```
        
3. **Conduct a service and version scan.**
    
    - Run:
        
        ```bash
        nmap -sV -p 1-65535 <target_IP>
        ```
        
4. **Document findings.**
    
    - Note open ports, running services, and versions.

---

## **Task 2: Analyze Network Traffic Using Wireshark**

1. **Launch Wireshark on Parrot Security.**
    
    - Select the active network interface.
2. **Start packet capture.**
    
    - Apply filters for protocols such as:
        
        ```text
        tcp
        ```
        
        or
        
        ```text
        http
        ```
        
3. **Analyze traffic.**
    
    - Look for interesting packets, such as login credentials or sensitive data.
4. **Document captured data.**
    
    - Save the capture as a `.pcap` file for further analysis.

---

# **Lab 7: Perform Website Reconnaissance**

## **Task 1: Crawl a Website Using Burp Suite**

1. **Launch Burp Suite on Parrot Security.**
    
    - Open the application and configure the proxy settings.
2. **Set up the browser to use Burp Suite’s proxy.**
    
    - Configure the browser’s proxy to:
        - Address: `127.0.0.1`
        - Port: `8080`
3. **Crawl the target website.**
    
    - Browse through the website while Burp Suite logs the traffic.
4. **Analyze captured data.**
    
    - Review HTTP requests and responses for parameters or vulnerabilities.

---

## **Task 2: Perform Directory Brute-Forcing Using Dirb**

1. **Run Dirb on Parrot Security.**
    
    - Execute:
        
        ```bash
        dirb http://example.com /path/to/wordlist.txt
        ```
        
2. **Review results.**
    
    - Note discovered directories and their HTTP status codes.
3. **Document findings.**
    
    - Save the output for further analysis.

---

# **Lab 8: Perform Reconnaissance with Active Tools**

## **Task 1: Use Nikto to Scan for Vulnerabilities**

1. **Launch Nikto on Parrot Security.**
    
    - Open a terminal and type:
        
        ```bash
        nikto -h http://example.com
        ```
        
2. **Analyze the output.**
    
    - Look for vulnerabilities like outdated software versions, default credentials, or open directories.
3. **Document findings.**
    
    - Save the results to a text file.

---

## **Task 2: Run OpenVAS for Vulnerability Scanning**

1. **Launch OpenVAS on Parrot Security.**
    
    - Open the Greenbone Vulnerability Manager (GVM).
2. **Create a new scan.**
    
    - Add the target IP or domain and start the scan.
3. **Review the vulnerability report.**
    
    - Identify critical vulnerabilities and prioritize them for exploitation.
4. **Document findings.**
    
    - Save the scan report for future reference.

---

# **Lab 9: Automate Reconnaissance Tasks**

## **Task 1: Use Metasploit for Automated Reconnaissance**

1. **Launch Metasploit on Parrot Security.**
    
    - Open a terminal and run:
        
        ```bash
        msfconsole
        ```
        
2. **Set the target host.**
    
    - Run:
        
        ```bash
        use auxiliary/scanner/http/title
        set RHOSTS example.com
        run
        ```
        
3. **Analyze the results.**
    
    - Note server information, web application details, and headers.

---

## **Task 2: Use SpiderFoot for Comprehensive Recon**

1. **Launch SpiderFoot on Parrot Security.**
    
    - Open the application from the menu.
2. **Create a new scan.**
    
    - Input the target domain and configure the modules.
3. **Run the scan.**
    
    - Let SpiderFoot collect information like subdomains, emails, and network associations.
4. **Review the report.**
    
    - Analyze collected data for actionable intelligence.

---

This concludes the step-by-step instructions for all **9 Labs** in the **"02-Footprinting and Reconnaissance"** document. Let me know if you need further assistance or additional details!