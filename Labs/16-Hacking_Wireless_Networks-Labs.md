# Lab Tasks Checklist: Hacking Wireless Networks

## Lab 1: Footprint a Wireless Network

### **Lab Scenario**

Footprinting involves discovering and analyzing wireless networks to detect vulnerabilities and prepare for further assessments.

### **Lab Objectives**

- Discover Wi-Fi networks in range using NetSurveyor.
- Identify SSIDs and analyze network data.

### **Lab Environment**

- **Virtual Machines**: Windows 11
- **Tools**: NetSurveyor
- **Devices**: Linksys 802.11 g WLAN adapter
- **Permissions**: Administrator access
- **Internet Connection**: Required

### **Checklist**

- [ ]  Connect the Linksys 802.11 g WLAN adapter to the Windows 11 virtual machine.
- [ ]  Navigate to `E:\CEH-Tools\CEHv12 Module 16 Hacking Wireless Networks\Wi-Fi Discovery Tools\NetSurveyor` and install NetSurveyor.
- [ ]  Launch NetSurveyor and scan for nearby Wi-Fi networks.
- [ ]  Analyze discovered networks, including SSID, channel, beacon strength, and security type.
- [ ]  Save the results as a PDF report.

---

## Lab 2: Perform Wireless Traffic Analysis

### **Lab Scenario**

Wireless traffic analysis helps identify vulnerabilities and monitor active devices in a network by capturing and analyzing packets.

### **Lab Objectives**

- Identify wireless networks and sniff packets using Wash and Wireshark.

### **Lab Environment**

- **Virtual Machines**: Parrot Security
- **Tools**: Wash, Wireshark
- **Devices**: Linksys 802.11 g WLAN adapter
- **Permissions**: Administrator access

### **Checklist**

- [ ]  Start the Parrot Security virtual machine and log in.
- [ ]  Connect the Linksys 802.11 g WLAN adapter to Parrot Security.
- [ ]  Use `wash` to identify WPS-enabled devices in the network.
- [ ]  Launch Wireshark, select the wireless interface, and start capturing traffic.
- [ ]  Analyze captured packets for SSID, encryption type, and other critical information.

---

## Lab 3: Perform Wireless Attacks

### **Lab Scenario**

Wireless attacks assess network security by exploiting vulnerabilities in encryption, authentication, or configuration.

### **Lab Objectives**

- Crack WEP, WPA, and WPA2 encryption.
- Create a rogue access point to capture sensitive data.

### **Lab Environment**

- **Virtual Machines**: Parrot Security, Windows 11
- **Tools**: Aircrack-ng, Wifiphisher, Fern Wifi Cracker
- **Devices**: Linksys 802.11 g WLAN adapter
- **Permissions**: Administrator access

### **Checklist**

#### WEP Network with Aircrack-ng

- [ ]  Put the wireless interface into monitor mode using `airmon-ng`.
- [ ]  Use `airodump-ng` to capture packets from the target WEP network.
- [ ]  Run `aircrack-ng` on the captured file to crack the WEP key.

#### WPA Network with Fern Wifi Cracker

- [ ]  Launch Fern Wifi Cracker and scan for WPA-enabled networks.
- [ ]  Select a target network and provide a dictionary for brute-forcing.
- [ ]  Start the attack and capture the WPA passphrase.

#### Rogue Access Point with Wifiphisher

- [ ]  Use `wifiphisher` to create a rogue access point.
- [ ]  Wait for the victim to connect and enter credentials on a phishing page.
- [ ]  Document the captured credentials.

---
---

# Step-by-Step

