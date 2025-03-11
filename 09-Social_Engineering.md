# Social Engineering

> #TLDR
> This module provides a detailed examination of social engineering techniques, phases, and countermeasures. It explains the psychological tactics behind social engineering, explores the various techniques used by attackers, and presents an array of preventive strategies. Each section is expanded with in-depth tools, code examples, commands, and security best practices.

---

## **What We Get From This Exercise**
###### #Objectives #MalwareThreats

- **Enhanced Understanding of Social Engineering Tactics**: By exploring various social engineering techniques, you will gain insight into how attackers exploit human psychology to bypass traditional security defenses.
- **Awareness of Phases in Social Engineering Attacks**: You’ll learn about the step-by-step process attackers use, from researching a target to exploiting relationships, giving a clear understanding of attack patterns.
- **Identification of Different Social Engineering Techniques**: This exercise covers a range of techniques including human-based, computer-based, and mobile-based attacks, enabling you to recognize various forms of social engineering attempts.
- **Insight into Insider Threats**: Understanding the types of insider threats will help you identify potential risks within an organization, and how certain behaviours can lead to data breaches.
- **Knowledge of Identity Theft Methods**: You will become familiar with common identity theft techniques such as dumpster diving, pretexting, and phishing, and how they compromise personal and organizational data.
- **Comprehensive Countermeasures**: Through this exercise, you’ll be equipped with effective countermeasures, from training and access control policies to enforcing physical security protocols, to prevent and mitigate social engineering attacks.
- **Hands-on Application with Tools and Code**: Using tools like SET, Gophish, and Beef, along with Python code snippets, you will be able to practically apply knowledge, simulate attacks, and understand detection methods in real-world scenarios.
- **Improved Security Awareness and Training Skills**: By learning these concepts, you will be better equipped to train employees, conduct awareness programs, and improve organizational resilience against social engineering threats.

---

# Table of Contents
1. [Social Engineering Concepts and Phases](#social-engineering-concepts-and-phases)
	1. [What is Social Engineering?](#what-is-social-engineering)
	2. [Why is Social Engineering Effective?](#why-is-social-engineering-effective)
	3. [Phases of a Social Engineering Attack](#phases-of-a-social-engineering-attack)
2. [Various Social Engineering Techniques](#various-social-engineering-techniques)
	1. [Human-based Social Engineering Techniques](#human-based-social-engineering-techniques)
	2. [Computer-based Social Engineering Techniques](#computer-based-social-engineering-techniques)
	3. [Mobile-based Social Engineering Techniques](#mobile-based-social-engineering-techniques)
3. [Insider Threats](#insider-threats)
	1. [Types of Insider Threats](#types-of-insider-threats)
4. [Identity Theft](#identity-theft)
	1. [Types of Identity Theft](#types-of-identity-theft)
	2. [Common Techniques for Identity Theft](#common-techniques-for-identity-theft)
5. [Countermeasures against Social Engineering](#countermeasures-against-social-engineering)

---

# Social Engineering Concepts and Phases

## What is Social Engineering?
Social engineering is a manipulation technique targeting human psychology, often bypassing traditional security defenses. It involves attackers persuading individuals to divulge confidential information or perform actions that compromise security.

**Relevant Tools and Examples:**
#SET
1. **SET (Social-Engineer Toolkit)**: An open-source tool often used to simulate social engineering attacks, such as spear-phishing, credential harvesting, and more.
    ```bash
    # Example usage to initiate a phishing campaign:
    sudo setoolkit
    ```

2. **Beef (Browser Exploitation Framework)**: Useful for delivering social engineering payloads through a browser.
    ```bash
    # To run a phishing scenario on Beef:
    sudo beef-xss
    ```

3. **Nmap Scripting Engine (NSE)**: Can be used to gather information to build a social engineering profile.
    ```bash
    # Example: Gathering employee information through public IPs
    nmap -sP <target-IP-range>
    ```

## Why is Social Engineering Effective?
The effectiveness of social engineering lies in exploiting inherent human traits, such as:
- **Trust and Authority**: People often comply with requests from perceived authority figures.
- **Scarcity and Urgency**: Attackers use urgency to rush decision-making.
- **Social Proof**: People are likely to act when they see others do the same.

**In-Depth Example**:
A scam email might claim an "urgent update" with a legitimate-looking URL and an official logo. It can induce a sense of urgency, prompting the user to overlook security red flags.

## Phases of a Social Engineering Attack

1. **Research the Target Company**  
   Techniques include scanning public social media profiles, gathering information from the company’s website, and reviewing recent job postings.

2. **Select a Target**  
   Identify employees in customer support, HR, or IT—roles that frequently engage with people and may inadvertently reveal useful information.

3. **Develop a Relationship**  
   Attackers can use fake personas over social media, email, or phone to establish rapport with targets.

4. **Exploit the Relationship**  
   Leveraging trust, attackers extract sensitive data, access passwords, or even direct actions like sharing internal files.

---

# Various Social Engineering Techniques

## Human-based Social Engineering Techniques
- **Impersonation**: Posing as an authority figure, employee, or contractor to gain access or information.
- **Vishing (Voice Phishing)**: Using phone calls with spoofed numbers to impersonate credible entities.
- **Eavesdropping**: Actively or passively listening to private conversations.
- **Shoulder Surfing**: Observing people entering sensitive information.

**Example Techniques**:
1. **Phone Spoofing with Twilio or SpoofCard**: Mask caller IDs to impersonate trusted contacts.
2. **Using Public Wi-Fi for Eavesdropping**: Tools like Wireshark can capture unencrypted data on public networks.
    ```bash
    # Basic Wireshark filter for capturing HTTP traffic:
    http
    ```

## Computer-based Social Engineering Techniques
- **Phishing**: Emails or fake websites prompt users to enter sensitive information.
- **Pop-up Window Attacks**: Malicious pop-ups that encourage users to click and download malware.
- **Scareware**: Fake virus warnings that prompt users to download "security" software.

**Phishing Example**:
Creating a phishing site using **SET**:
```bash
# Launch SET and select the Social-Engineering Attacks > Web Attack Vectors > Credential Harvester Attack Method
sudo setoolkit
```

**Advanced Tools**:
- **Gophish**: A phishing framework that enables large-scale, customizable campaigns.
    ```bash
    # Start Gophish server:
    ./gophish
    ```

## Mobile-based Social Engineering Techniques
- **SMiShing (SMS Phishing)**: Sending fraudulent SMS to harvest sensitive data.
- **Fake Apps**: Malicious apps that mimic legitimate ones, targeting mobile devices.

**Example Commands**:
1. **APKTool**: Used to analyse or repackage malicious Android apps.
    ```bash
    apktool d <malicious-app.apk> -o <output-directory>
    ```

---

# Insider Threats

## Types of Insider Threats
1. **Malicious Insider**: Employees intentionally exploit access for personal gain.
2. **Negligent Insider**: Poor data handling and policy adherence increase risks.
3. **Professional Insider**: Selling information to external entities for profit.
4. **Compromised Insider**: An outsider manipulates employees to gain access.

**Examples of Insider Threat Detection Tools**:
1. **Splunk**: Monitors user behaviour and detects unusual access patterns.
2. **Darktrace**: Uses machine learning to identify anomalous insider behaviour.
3. **UEBA (User and Entity Behaviour Analytics)**: Aids in spotting insider threats by analyzing deviations from normal user behaviour.

| Insider Type         | Description                             | Detection Methods                             |
| -------------------- | --------------------------------------- | --------------------------------------------- |
| Malicious Insider    | Intentional harm, such as data theft    | behaviour analytics and DLP tools              |
| Negligent Insider    | Careless handling of sensitive data     | Access controls, employee training            |
| Professional Insider | Selling information for personal gain   | Monitoring access logs and flagging anomalies |
| Compromised Insider  | External manipulation of internal users | Network activity monitoring                   |
| Accidental Insider   | Unintentional actions causing a breach  | Automated alerts, anomaly detection           |

---

# Identity Theft

## Types of Identity Theft
1. **Financial Identity Theft**: Misuse of financial information to conduct fraudulent transactions.
2. **Medical Identity Theft**: Using stolen medical records to claim health services.
3. **Social Security Identity Theft**: Stealing SSNs to access benefits or credit.

## Common Techniques for Identity Theft
- **Dumpster Diving**: Retrieving sensitive data from discarded documents.
- **Pretexting**: Pretending to need information to serve the target (e.g., tech support).
- **Phishing**: Commonly used for stealing credentials via fake websites or emails.

**Advanced Code Examples**:

```python
# Detect suspicious file names for credential harvesting (e.g., "login_data", "passwords")
import os
def scan_for_sensitive_files(directory):
    sensitive_keywords = ["password", "login", "credentials"]
    found_files = [f for f in os.listdir(directory) if any(keyword in f.lower() for keyword in sensitive_keywords)]
    return found_files

# Sample usage
print(scan_for_sensitive_files('/path/to/check'))
```

---

# Countermeasures against Social Engineering

## Training and Awareness
1. **Regular Security Training**: Teach employees to recognize phishing and social engineering attempts.
2. **Phishing Simulations**: Conduct regular simulated phishing attacks to measure and improve awareness.
   - Tools: **KnowBe4**, **Cofense PhishMe**

## Access Policies
- **Role-Based Access Control (RBAC)**: Limits access based on job function.
- **Least Privilege Principle**: Users only have access essential for their roles.
- **Password Policies**: Enforce complexity, expiration, and two-factor authentication.

**Code Example for Enforcing Password Complexity**:

```python
# Check if a password meets complexity requirements
import re

def is_strong_password(password):
    length = len(password) >= 12
    has_upper = re.search(r"[A-Z]", password)
    has_lower = re.search(r"[a-z]", password)
    has_digit = re.search(r"\d", password)
    has_special = re.search(r"[!@#$%^&*]", password)
    return all([length, has_upper, has_lower, has_digit, has_special])

# Usage example
password = "SecurePassword123!"
print(is_strong_password(password))  # Output: True
```

## Physical Security
1. **ID Verification Systems**: Biometric or RFID access cards prevent unauthorized entry.
2. **Monitoring Tools**: Use of surveillance and AI-driven monitoring for real-time threat alerts.
3. **Tailgating Prevention**: Security personnel training and badge protocols
