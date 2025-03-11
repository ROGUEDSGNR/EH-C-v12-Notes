# Lab Tasks Checklist: Cryptography

## Lab 1: Encrypt Information Using Cryptographic Tools

### **Lab Scenario**

The integrity and confidentiality of sensitive data are critical for secure communication. As an ethical hacker, you should use cryptographic tools to encrypt data and ensure its protection.

### **Lab Objectives**

- Calculate one-way and MD5 hashes.
- Encrypt and decrypt files and text messages.
- Perform email and disk encryption.
- Conduct cryptanalysis using tools.

### **Lab Environment**

- **Virtual Machines**: Windows 11, Windows Server 2019
- **Tools**: HashCalc, MD5 Calculator, HashMyFiles, CryptoForge, VeraCrypt, BitLocker
- **Permissions**: Administrator access
- **Internet Connection**: Required

---

### **Checklist for Cryptography Tasks**

#### Task 1: Calculate One-Way Hashes Using HashCalc

1. [ ]  Log in to the Windows 11 VM.
2. [ ]  Launch `HashCalc` from the search menu.
3. [ ]  Create a new text file (`Test.txt`) on the desktop and add sample text (e.g., "Hello World").
4. [ ]  Select the file in HashCalc and calculate its hashes (MD5, SHA1, RIPEMD160).
5. [ ]  Modify the file and recalculate the hashes to observe changes.

#### Task 2: Calculate MD5 Hashes Using MD5 Calculator

1. [ ]  Open MD5 Calculator on the Windows 11 VM.
2. [ ]  Add `Test.txt` to the tool.
3. [ ]  Calculate and document the MD5 hash of the file.
4. [ ]  Modify the file contents, recalculate, and compare hash values.

#### Task 3: Calculate MD5 Hashes Using HashMyFiles

1. [ ]  Launch `HashMyFiles` on the Windows 11 VM.
2. [ ]  Select a directory or files to calculate MD5, SHA1, and CRC32 hashes.
3. [ ]  Verify file integrity by comparing hashes before and after modification.

#### Task 4: Perform File Encryption Using CryptoForge

1. [ ]  Install CryptoForge on both the Windows 11 and Server 2019 VMs.
2. [ ]  Encrypt a file (`Confidential.txt`) by selecting it and providing a passphrase.
3. [ ]  Decrypt the file on the Windows Server 2019 VM using the shared passphrase.
4. [ ]  Encrypt a text message and share it with another user.

#### Task 5: Perform Disk Encryption Using VeraCrypt

1. [ ]  Launch VeraCrypt and create a new encrypted volume.
2. [ ]  Select encryption algorithms and set a passphrase.
3. [ ]  Mount the encrypted volume, add files, and verify access.
4. [ ]  Dismount the volume and attempt to remount with the correct passphrase.

#### Task 6: Perform Disk Encryption Using BitLocker

1. [ ]  Enable BitLocker on a drive in the Windows 11 VM.
2. [ ]  Save the recovery key to a secure location.
3. [ ]  Verify that the drive requires the recovery key upon access.

#### Task 7: Perform Cryptanalysis Using CrypTool

1. [ ]  Launch CrypTool on the Windows 11 VM.
2. [ ]  Use CrypTool to analyze encrypted data and attempt decryption.
3. [ ]  Document findings and suggest improvements to the encryption process.

---

## Lab 2: Create a Self-Signed Certificate

### **Lab Scenario**

Self-signed certificates provide a secure way to encrypt communication for internal applications without requiring external Certificate Authority validation.

### **Lab Objectives**

- Generate a self-signed certificate.
- Configure and use the certificate for secure communication.

### **Checklist**

1. [ ]  Use OpenSSL or a similar tool to generate a private key and self-signed certificate.
2. [ ]  Export the certificate for use in applications.
3. [ ]  Verify the certificate by importing it into a browser or application.

---

## Lab 3: Perform Email Encryption

### **Lab Scenario**

Encrypting emails ensures secure communication by protecting sensitive information during transit.

### **Lab Objectives**

- Encrypt emails using Rmail.

### **Checklist**

1. [ ]  Install and configure Rmail on the Windows 11 VM.
2. [ ]  Compose an email and encrypt it using the recipient's public key.
3. [ ]  Send the encrypted email and confirm receipt by the recipient.

---

## Lab Analysis and Documentation

1. [ ]  Record all encryption and decryption results.
2. [ ]  Analyze the cryptographic strength of tools used.
3. [ ]  Suggest improvements to the encryption methods and tools.

---
---

# Step-by-Step

### **Task 1: Calculate One-Way Hashes Using HashCalc**

1. **Log in to the Windows 11 VM.**
    - Ensure your virtual machine is running and you are logged in with administrator credentials.
2. **Launch `HashCalc` from the search menu.**
       - Navigate to the installation directory or use the search bar to locate `HashCalc`.
    - Open the tool.
3. **Create a new text file (`Test.txt`) on the desktop and add sample text (e.g., "Hello World").**
    - Right-click on the desktop, select **New > Text Document**, and name the file `Test.txt`.
    - Double-click the file and add the text "Hello World."
4. **Select the file in HashCalc and calculate its hashes (MD5, SHA1, RIPEMD160).**
    - In `HashCalc`, click the file selector button to locate `Test.txt`.
    - Choose the hashing algorithms (e.g., MD5, SHA1, RIPEMD160) by checking the corresponding boxes.
    - Click **Calculate** and note the results.
5. **Modify the file and recalculate the hashes to observe changes.**
    - Open `Test.txt`, edit the text (e.g., add "123"), save it, and close.
    - Repeat the hashing process in `HashCalc` and compare the new hash values with the original.

---

### **Task 2: Calculate MD5 Hashes Using MD5 Calculator**

1. **Open MD5 Calculator on the Windows 11 VM.**
    - Locate the MD5 Calculator tool via the search menu or desktop shortcut and open it.
2. **Add `Test.txt` to the tool.**
    - Click the **Browse** button to select `Test.txt` from your desktop.
3. **Calculate and document the MD5 hash of the file.**
    - Click **Compute** or equivalent and note down the hash value.
4. **Modify the file contents, recalculate, and compare hash values.**
    - Edit `Test.txt` as in Task 1, save it, and recalculate the hash.
    - Compare the new hash with the previous hash to observe changes.

---

### **Task 3: Calculate MD5 Hashes Using HashMyFiles**

1. **Launch `HashMyFiles` on the Windows 11 VM.**
    - Open the application from the start menu or installation folder.
2. **Select a directory or files to calculate MD5, SHA1, and CRC32 hashes.**
    - Drag and drop `Test.txt` or a folder containing multiple files into the HashMyFiles window.
3. **Verify file integrity by comparing hashes before and after modification.**
    - Document the original hashes, modify the file contents, and recalculate the hashes to detect changes.

---

### **Task 4: Perform File Encryption Using CryptoForge**

1. **Install CryptoForge on both the Windows 11 and Server 2019 VMs.**
    - Download and install CryptoForge if not already installed.
2. **Encrypt a file (`Confidential.txt`) by selecting it and providing a passphrase.**
    - Right-click `Confidential.txt`, choose **CryptoForge > Encrypt**, and set a strong passphrase.
3. **Decrypt the file on the Windows Server 2019 VM using the shared passphrase.**
    - Transfer the encrypted file to the Server 2019 VM.
    - Right-click the file, choose **CryptoForge > Decrypt**, and enter the passphrase to restore the original content.
4. **Encrypt a text message and share it with another user.**
    - Use CryptoForge to encrypt plaintext, save it, and share the encrypted output with another user.

---

### **Task 5: Perform Disk Encryption Using VeraCrypt**

1. **Launch VeraCrypt and create a new encrypted volume.**
    - Open VeraCrypt, click **Create Volume**, and follow the wizard to create an encrypted file container.
2. **Select encryption algorithms and set a passphrase.**
    - Choose algorithms like AES, Serpent, or Twofish.
    - Set a strong passphrase for the volume.
3. **Mount the encrypted volume, add files, and verify access.**
    - Mount the volume by selecting the encrypted container and assigning it to a drive letter.
    - Add files to the mounted volume.
4. **Dismount the volume and attempt to remount with the correct passphrase.**
    - Close the container and verify access by remounting with the passphrase.

---

### **Task 6: Perform Disk Encryption Using BitLocker**

1. **Enable BitLocker on a drive in the Windows 11 VM.**
    - Navigate to **Control Panel > System and Security > BitLocker Drive Encryption**.
    - Select the drive to encrypt and enable BitLocker.
2. **Save the recovery key to a secure location.**
    - Save the recovery key to a file or print it for safekeeping.
3. **Verify that the drive requires the recovery key upon access.**
    - Restart the machine and attempt to access the encrypted drive, using the recovery key to unlock it.

---

### **Task 7: Perform Cryptanalysis Using CrypTool**

1. **Launch CrypTool on the Windows 11 VM.**
    - Open CrypTool from the start menu or desktop shortcut.
2. **Use CrypTool to analyze encrypted data and attempt decryption.**
    - Load an encrypted file or message into CrypTool.
    - Choose cryptanalysis tools like brute-force or frequency analysis to decrypt the content.
3. **Document findings and suggest improvements to the encryption process.**
    - Record successful decryptions and recommend better encryption practices if weaknesses are identified.
