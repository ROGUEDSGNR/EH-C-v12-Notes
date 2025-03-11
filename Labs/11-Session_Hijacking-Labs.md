# Lab Tasks Checklist: Session Hijacking

## Lab 1: Perform Session Hijacking

### **Lab Scenario**

Session hijacking exploits weaknesses in session token generation and security controls, allowing attackers to take over valid user sessions to perform unauthorized actions.

### **Lab Objectives**

- Hijack a session using Zed Attack Proxy (ZAP).
- Intercept HTTP traffic using bettercap.
- Intercept HTTP traffic using Hetty.

### **Lab Environment**

- **Virtual Machines**: Windows 11, Windows Server 2022, Windows Server 2019, Parrot Security
- **Tools**: ZAP, bettercap, Hetty
- **Permissions**: Administrator access
- **Internet Connection**: Required

---

### **Checklist for Session Hijacking Using ZAP**

1. [ ]  Set up Windows 11 and Windows Server 2019 virtual machines.
2. [ ]  Configure proxy settings on the victim machine (Windows 11) to route traffic through the attacker's machine.
3. [ ]  Launch ZAP on Windows Server 2019 and configure it as a proxy.
4. [ ]  Enable the `Break` functionality in ZAP to intercept requests.
5. [ ]  Visit a target website (e.g., `www.moviescope.com`) on the victim's browser.
6. [ ]  Modify intercepted requests in ZAP to redirect traffic to a malicious website.
7. [ ]  Verify that the victim sees the malicious website content while accessing the original URL.
8. [ ]  Restore the proxy settings on the victim machine to default.
9. [ ]  Document the hijacking process and results.

---

### **Checklist for Intercepting HTTP Traffic Using bettercap**

1. [ ]  Launch Parrot Security VM and log in as the attacker.
2. [ ]  Open a terminal and switch to root using `sudo su`.
3. [ ]  Set the network interface with `bettercap -iface eth0`.
4. [ ]  Enable network probing with `net.probe on`.
5. [ ]  Enable network reconnaissance with `net.recon on`.
6. [ ]  Enable SSL stripping with `set http.proxy.sslstrip true`.
7. [ ]  Spoof ARP for the victim's IP address with `set arp.spoof.targets <victim_IP>` and `arp.spoof on`.
8. [ ]  Start sniffing traffic with `net.sniff on`.
9. [ ]  Log in to an HTTP-based website on the victim machine (Windows 11).
10. [ ]  Observe intercepted credentials and traffic in bettercap.
11. [ ]  Terminate bettercap after testing.

---

### **Checklist for Intercepting HTTP Traffic Using Hetty**

1. [ ]  Launch Windows 11 (attacker) and Windows Server 2022 (victim) virtual machines.
2. [ ]  Open Hetty on the attacker machine and initialize it.
3. [ ]  Configure proxy settings on the victim machine to route traffic through Hetty.
4. [ ]  Create a new project in Hetty and enable proxy logging.
5. [ ]  Visit the target website (`www.moviescope.com`) on the victim machine.
6. [ ]  Log in with sample credentials on the target website.
7. [ ]  Observe and capture POST requests containing sensitive data in Hetty logs.
8. [ ]  Restore proxy settings on the victim machine to default.
9. [ ]  Document the results of the interception.

---

## Lab 2: Detect Session Hijacking

### **Lab Scenario**

Session hijacking detection is crucial for identifying potential risks of data theft or fraud. Tools like Wireshark allow for real-time analysis of hijacking attempts.

### **Lab Objectives**

- Detect session hijacking attempts using Wireshark.

### **Lab Environment**

- **Virtual Machines**: Windows 11, Parrot Security
- **Tools**: Wireshark
- **Permissions**: Administrator access
- **Internet Connection**: Required

---

### **Checklist for Detecting Session Hijacking Using Wireshark**

1. [ ]  Launch Windows 11 and Parrot Security virtual machines.
2. [ ]  Open Wireshark on the victim machine (Windows 11) and start capturing network traffic on the primary interface.
3. [ ]  Launch bettercap on the attacker machine (Parrot Security) to simulate a session hijacking attack.
4. [ ]  Enable ARP spoofing, SSL stripping, and network sniffing in bettercap.
5. [ ]  Observe ARP broadcasts and other suspicious traffic patterns in Wireshark.
6. [ ]  Analyze captured packets to identify session hijacking attempts.
7. [ ]  Document findings and provide recommendations for mitigation.

---
---

# Step-by-Step

