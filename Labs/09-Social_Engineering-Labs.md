# Lab Tasks Checklist: Social Engineering

## Lab 1: Perform Social Engineering Using Various Techniques

### **Lab Scenario**

Evaluate the security of an organization by using social engineering techniques to gather sensitive information such as credentials, usernames, passwords, and personal or organizational details.

### **Lab Objectives**

- Sniff credentials using the Social-Engineer Toolkit (SET).
- Create phishing campaigns to target user credentials.
- Clone websites to harvest sensitive information.

### **Lab Environment**

- **Virtual Machines**: Windows 11, Parrot Security
- **Tools**: Social-Engineer Toolkit (SET)
- **Permissions**: Administrator access
- **Internet Connection**: Required

### **Checklist**

- [ ]  Set up the Windows 11 and Parrot Security virtual machines.
- [ ]  Log in to Parrot Security and launch the SET toolkit.
- [ ]  Create a website clone using the `Credential Harvester` attack method in SET.
- [ ]  Configure the IP address for POST back and target URL for cloning.
- [ ]  Send the phishing email to the target user containing the malicious link.
- [ ]  Simulate victim interaction by opening the email and clicking the link on the Windows 11 VM.
- [ ]  Observe and document captured credentials on the Parrot Security machine.
- [ ]  Turn off all virtual machines and document findings.

---

## Lab 2: Detect a Phishing Attack

### **Lab Scenario**

Detect phishing attacks using tools like Netcraft and PhishTank to analyze websites for malicious activities and prevent potential fraud.

### **Lab Objectives**

- Identify phishing websites using the Netcraft browser extension.
- Verify phishing attempts with the PhishTank platform.

### **Lab Environment**

- **Virtual Machines**: Windows 11
- **Tools**: Netcraft Extension, PhishTank
- **Permissions**: Administrator access
- **Internet Connection**: Required

### **Checklist**

#### Netcraft Extension

- [ ]  Install the Netcraft extension in Mozilla Firefox on Windows 11.
- [ ]  Use the extension to analyze a target website and view its risk report.
- [ ]  Test the extension with a known phishing URL to observe blocking behavior.
- [ ]  Document findings and potential phishing indicators.

#### PhishTank

- [ ]  Access the PhishTank platform via a web browser.
- [ ]  Submit and verify a suspected phishing URL.
- [ ]  Review details and reports on known phishing websites.
- [ ]  Document findings and summarize potential threats.

---

## Lab 3: Audit Organization’s Security for Phishing Attacks

### **Lab Scenario**

Simulate phishing attacks using OhPhish to evaluate employee awareness and organizational security policies against phishing.

### **Lab Objectives**

- Launch phishing campaigns targeting employees using OhPhish.
- Analyze the results of phishing attempts and employee responses.

### **Lab Environment**

- **Virtual Machines**: Windows 11, Windows Server 2019
- **Tools**: OhPhish
- **Permissions**: Administrator access
- **Internet Connection**: Required

### **Checklist**

- [ ]  Activate the OhPhish account and log in.
- [ ]  Configure a phishing email campaign in the OhPhish dashboard.
- [ ]  Create an email template using a relevant scenario (e.g., COVID-19 work-from-home policy).
- [ ]  Import user details for the campaign.
- [ ]  Launch the phishing campaign and monitor responses.
- [ ]  Simulate victim interaction by opening the phishing email on Windows Server 2019.
- [ ]  Analyze the campaign report to identify the number of clicks and opened emails.
- [ ]  Document results and recommend mitigation strategies.

---
---

# Step-by-Step