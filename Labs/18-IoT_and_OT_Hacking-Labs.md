# Lab Tasks Checklist: IoT and OT Hacking

## Lab 1: Perform Footprinting Using Various Techniques

### **Lab Scenario**

Footprinting is the first step in IoT and OT device hacking. It involves gathering information about the target devices, such as IP addresses, open ports, protocols, and geolocation, to identify vulnerabilities.

### **Lab Objectives**

- Gather information using Whois, advanced Google hacking, and Shodan.
- Focus on the MQTT protocol for IoT footprinting.

### **Lab Environment**

- **Virtual Machines**: Windows 11
- **Tools**: Web browsers, Whois, Shodan
- **Permissions**: Administrator access

### **Checklist**

- [ ]  Launch the Windows 11 VM and log in with `Admin` credentials.
- [ ]  Open a browser and visit [Whois Lookup](https://www.whois.com/whois/).
    - [ ]  Perform a domain lookup for `www.oasis-open.org`.
    - [ ]  Document retrieved domain and registrant details.
- [ ]  Navigate to [Exploit DB Google Hacking Database](https://www.exploit-db.com/google-hacking-database).
    - [ ]  Search for SCADA-related Google dorks and document the results.
- [ ]  Use Shodan to search for MQTT-enabled devices:
    - [ ]  Log in to Shodan and query `port:1883`.
    - [ ]  Analyze IP addresses and related device information.
- [ ]  Document all collected information.

---

## Lab 2: Capture and Analyze IoT Device Traffic

### **Lab Scenario**

Analyze communication between IoT devices using tools like Wireshark to capture sensitive information, such as credentials and device identification numbers.

### **Lab Objectives**

- Set up IoT simulation using MQTT Broker.
- Capture and analyze traffic using Wireshark.

### **Lab Environment**

- **Virtual Machines**: Windows Server 2019, Windows Server 2022, Windows 11
- **Tools**: MQTT Broker, Bevywise IoT Simulator, Wireshark
- **Permissions**: Administrator access

### **Checklist**

#### MQTT Broker Setup

1. [ ]  On Windows Server 2019:
    - [ ]  Install MQTT Broker from `Bevywise_MQTTRoute_Win_64.exe`.
    - [ ]  Verify the service is running on port 1883.

#### IoT Simulator Setup

2. [ ]  On Windows Server 2022:
    - [ ]  Install Bevywise IoT Simulator and configure a new network (e.g., `CEH_FINANCE_NETWORK`).
    - [ ]  Add devices (e.g., `Temperature_Sensor` with ID `TS1`) to the network.
    - [ ]  Connect the network to the MQTT Broker.

#### Traffic Capture and Analysis

3. [ ]  On Windows 11:
    - [ ]  Launch Wireshark and select the network interface.
    - [ ]  Start packet capture and filter for `mqtt`.
4. [ ]  On Windows Server 2022:
    - [ ]  Send a command (e.g., `High_Tempe`) to the IoT device.
    - [ ]  Verify the command in the IoT Simulator logs.
5. [ ]  Analyze captured packets in Wireshark to identify MQTT messages.

---
---

# Step-by-Step

