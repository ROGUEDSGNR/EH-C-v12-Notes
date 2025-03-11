# Lab Tasks Checklist: Hacking Web Servers

## Lab 1: Footprint the Web Server

### **Lab Scenario**

Footprinting a web server involves collecting as much information as possible about the target web server to identify vulnerabilities and misconfigurations that attackers can exploit.

### **Lab Objectives**

- Perform information gathering using tools like Ghost Eye, Skipfish, httprecon, and ID Serve.
- Use Netcat and Telnet for banner grabbing.
- Enumerate web server information using Nmap Scripting Engine (NSE).
- Perform web server fingerprinting with Uniscan.

### **Lab Environment**

- **Virtual Machines**: Windows 11, Windows Server 2022, Windows Server 2019, Parrot Security
- **Tools**: Ghost Eye, Skipfish, httprecon, ID Serve, Netcat, Telnet, Nmap, Uniscan
- **Permissions**: Administrator access
- **Internet Connection**: Required

### **Checklist**

#### Ghost Eye

1. [ ]  Turn on the Parrot Security VM and log in as root.
2. [ ]  Navigate to the Ghost Eye directory and install dependencies: `pip3 install -r requirements.txt`.
3. [ ]  Launch Ghost Eye: `python3 ghost_eye.py`.
4. [ ]  Perform:
    - [ ]  Whois Lookup.
    - [ ]  DNS Lookup.
    - [ ]  Clickjacking Test.

#### Skipfish

1. [ ]  Open the Parrot Security VM.
2. [ ]  Run Skipfish: `skipfish -o /output_dir -S /dict_file http://<target_IP>:8080`.
3. [ ]  Analyze the generated `index.html` report.

#### httprecon

1. [ ]  Launch httprecon on Windows 11.
2. [ ]  Input target website URL and port.
3. [ ]  Click "Analyze" to perform the scan and observe server details.

#### ID Serve

1. [ ]  Open ID Serve on Windows 11.
2. [ ]  Input the target URL and query the server.
3. [ ]  Analyze the returned HTTP header and server details.

#### Netcat and Telnet

1. [ ]  Use Netcat for banner grabbing: `nc -vv <target_domain> 80`.
2. [ ]  Use Telnet for similar purposes: `telnet <target_domain> 80`.

#### Nmap Scripting Engine (NSE)

1. [ ]  Use NSE for enumeration:
    - [ ]  Enumerate directories: `nmap -sV --script=http-enum <target_website>`.
    - [ ]  Detect vulnerabilities: `nmap -p80 --script=http-waf-detect <target_website>`.

#### Uniscan

1. [ ]  Run directory scans: `uniscan -u <target_URL> -q`.
2. [ ]  Perform dynamic tests: `uniscan -u <target_URL> -d`.

---

## Lab 2: Perform a Web Server Attack

### **Lab Scenario**

After gathering information about a target web server, perform attacks to identify potential vulnerabilities and test security mechanisms.

### **Lab Objectives**

- Crack FTP credentials using a dictionary attack with THC Hydra.

### **Lab Environment**

- **Virtual Machines**: Windows 11, Parrot Security
- **Tools**: THC Hydra, Nmap
- **Permissions**: Administrator access

### **Checklist**

#### Crack FTP Credentials Using THC Hydra

1. [ ]  Turn on Windows 11 and Parrot Security VMs.
2. [ ]  Scan the target with Nmap: `nmap -p21 <target_IP>`.
3. [ ]  Attempt FTP login manually to confirm credential requirements.
4. [ ]  Perform a dictionary attack with Hydra:
    
    ```bash
    hydra -L /path/to/Usernames.txt -P /path/to/Passwords.txt ftp://<target_IP>
    ```
    
5. [ ]  Use cracked credentials to log in to the FTP server and perform actions like creating a directory.

---
---

# Step-by-Step

