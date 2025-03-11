# Lab Tasks Checklist: Enumeration

## Lab 1: Perform NetBIOS Enumeration

### **Lab Scenario**

As an ethical hacker, use NetBIOS enumeration to gather critical information such as machine names, user groups, and shared resources.

### **Lab Objectives**

- Extract NetBIOS details using Windows command-line tools.
- Use NetBIOS Enumerator and NSE scripts to gather data.

### **Lab Environment**

- **Virtual Machines**: Windows 11, Windows Server 2022, Windows Server 2019, Parrot Security
- **Tools**: NetBIOS Enumerator, nmap NSE scripts
- **Internet Connection**: Required
- **Permissions**: Administrator

### **Checklist**

- [ ]  Run `nbtstat` and `net use` commands to extract NetBIOS details.
- [ ]  Use NetBIOS Enumerator to scan a range of IP addresses for NetBIOS information.
- [ ]  Execute the NSE `nbstat` script with Nmap to identify NetBIOS details like MAC addresses and logged-in users.
- [ ]  Document all findings.

---

## Lab 2: Perform SNMP Enumeration

### **Lab Scenario**

Gather information about network resources, routing tables, and device statistics via SNMP enumeration.

### **Lab Objectives**

- Perform SNMP enumeration using tools like snmp-check, SnmpWalk, SoftPerfect Network Scanner, and Nmap.

### **Lab Environment**

- **Virtual Machines**: Windows 11, Windows Server 2022, Ubuntu, Parrot Security
- **Tools**: snmp-check, SnmpWalk, SoftPerfect Network Scanner
- **Internet Connection**: Required
- **Permissions**: Administrator

### **Checklist**

- [ ]  Verify SNMP port 161 is open using Nmap.
- [ ]  Run `snmp-check` to extract sensitive information.
- [ ]  Use SoftPerfect Network Scanner to analyze active hosts and their SNMP configurations.
- [ ]  Utilize SnmpWalk for advanced SNMP enumeration.
- [ ]  Run Nmap scripts like `snmp-sysdescr` and `snmp-processes` to gather detailed SNMP data.
- [ ]  Document all findings.

---

## Lab 3: Perform LDAP Enumeration

### **Lab Scenario**

Explore directory services using LDAP enumeration to extract usernames, departmental details, and other directory information.

### **Lab Objectives**

- Perform LDAP enumeration with AD Explorer, Python, and ldapsearch.
- Automate LDAP brute-force attacks using Nmap scripts.

### **Lab Environment**

- **Virtual Machines**: Windows 11, Windows Server 2022, Parrot Security
- **Tools**: AD Explorer, ldapsearch, Nmap NSE scripts
- **Internet Connection**: Required
- **Permissions**: Administrator

### **Checklist**

- [ ]  Connect to an LDAP server using AD Explorer and extract user details.
- [ ]  Use Nmap’s `ldap-brute` script to perform authentication brute-forcing.
- [ ]  Execute Python scripts for manual LDAP enumeration.
- [ ]  Run `ldapsearch` to query the directory for user and object details.
- [ ]  Document findings and analyze security risks.

---

## Lab 4: Perform NFS Enumeration

### **Lab Scenario**

Identify exported directories, shared files, and connected clients through NFS enumeration to uncover potential vulnerabilities.

### **Lab Objectives**

- Perform NFS enumeration using RPCScan and SuperEnum.

### **Lab Environment**

- **Virtual Machines**: Windows Server 2019, Parrot Security
- **Tools**: RPCScan, SuperEnum
- **Internet Connection**: Required
- **Permissions**: Administrator

### **Checklist**

- [ ]  Enable NFS services on the target machine.
- [ ]  Use RPCScan to identify exported directories and mount points.
- [ ]  Perform recursive enumeration with SuperEnum.
- [ ]  Document findings and identify exploitable configurations.

---
---

# Step-by-Step