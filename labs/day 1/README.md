# Network Reconnaissance - Day 1

## Overview
This document outlines the labs completed on 07/30/2025 during the hacking bootcamp, focusing on network reconnaissance techniques.

## Table of Contents
- [Lab 1: DNS Zone Transfer Attack](#lab-1-dns-zone-transfer-attack)
- [Lab 2: Domain Recon Passive](#lab-2-domain-recon-passive)
- [Lab 3: Domain Scan Active](#lab-3-domain-scan-active)
- [Lab 4: Port Scan Medium](#lab-4-port-scan-medium)

## Labs

### Lab 1: DNS Zone Transfer Attack
#### Objective
Extract DNS records by exploiting a misconfigured DNS server allowing zone transfers.

#### Vulnerabilities
- Misconfigured DNS: Servers allowing unauthorized zone transfers expose domain records.

#### Requirements
Target DNS server must allow zone transfers to unauthorized clients.

#### Steps
1. **Setup**
   - Identify the target DNS server.
   ```bash
   nslookup -type=NS <TARGET_DOMAIN>
   ```
2. **Reconnaissance**
   - Test for zone transfer capability.
   ```bash
   dig axfr <TARGET_DOMAIN> @<DNS_SERVER_IP>
   ```
3. **Exploitation**
   - Perform a zone transfer to extract DNS records.
   ```bash
   dig axfr <TARGET_DOMAIN> @<DNS_SERVER_IP> > records.txt
   ```

#### Why It Works
Misconfigured DNS servers allow unauthorized clients to download the entire zone file, revealing subdomains and IP addresses.

#### Alternatives
- Use host or nslookup for manual zone transfer attempts.

#### Resources
- [DNS Zone Transfer Guide: https://www.hacktricks.xyz/pentesting/pentesting-dns](https://www.hacktricks.xyz/pentesting/pentesting-dns)

#### Notes
- Check multiple name servers for permissive configurations.

---

### Lab 2: Domain Recon Passive
#### Objective
Gather information about a target domain using passive reconnaissance techniques.

#### Vulnerabilities
- Public Data Exposure: Domain information available through public sources.

#### Requirements
Target domain must have publicly accessible information.

#### Steps
1. **Setup**
   - Verify internet connectivity for passive reconnaissance.
   ```bash
   ping 8.8.8.8
   ```
2. **Reconnaissance**
   - Use theHarvester to collect domain-related data.
   ```bash
   theHarvester -d <TARGET_DOMAIN> -b google,shodan -l 100
   ```
3. **Exploitation**
   - Save collected data for further analysis.
   ```bash
   theHarvester -d <TARGET_DOMAIN> -b google,shodan -f recon.txt
   ```

#### Why It Works
Passive reconnaissance leverages public sources like search engines and Shodan to gather domain details without direct interaction.

#### Alternatives
- Use OSINT tools like Maltego for broader data collection.

#### Resources
- [theHarvester Documentation: https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester)

#### Notes
- Combine multiple data sources (e.g., Bing, LinkedIn) for comprehensive results.

---

### Lab 3: Domain Scan Active
#### Objective
Actively enumerate subdomains and services of a target domain.

#### Vulnerabilities
- Exposed Services: Active scanning reveals subdomains and open services.

#### Requirements
Target domain must have accessible subdomains and services.

#### Steps
1. **Setup**
   - Verify connectivity to the target domain.
   ```bash
   ping <TARGET_DOMAIN>
   ```
2. **Reconnaissance**
   - Enumerate subdomains using gobuster.
   ```bash
   gobuster dns -d <TARGET_DOMAIN> -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
   ```
3. **Exploitation**
   - Scan discovered subdomains for open services.
   ```bash
   nmap -sV -iL subdomains.txt
   ```

#### Why It Works
Active scanning identifies subdomains and services by directly querying the target, revealing potential attack vectors.

#### Alternatives
- Use Sublist3r or Amass for subdomain enumeration.

#### Resources
- [Gobuster Documentation: https://github.com/OJ/gobuster](https://github.com/OJ/gobuster)
- [SecLists: https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)

#### Notes
- Use a comprehensive wordlist for effective subdomain enumeration.

---

### Lab 4: Port Scan Medium
#### Objective
Identify open ports and services on a target network with a moderately aggressive scan.

#### Vulnerabilities
- Exposed Services: Open ports reveal services that may be vulnerable.

#### Requirements
Target network must have accessible hosts with open ports.

#### Steps
1. **Setup**
   - Verify connectivity to the target network.
   ```bash
   ping <TARGET_IP>
   ```
2. **Reconnaissance**
   - Perform a port scan with Nmap for common ports.
   ```bash
   nmap -sV -p 1-1000 <TARGET_IP>
   ```
3. **Exploitation**
   - Analyze open ports and services for vulnerabilities.
   ```bash
   nmap --script vuln -p 1-1000 <TARGET_IP>
   ```

#### Why It Works
Moderate port scanning identifies open services and potential vulnerabilities without triggering excessive alerts.

#### Alternatives
- Use masscan for faster port scanning.

#### Resources
- [Nmap Documentation: https://nmap.org/book/man.html](https://nmap.org/book/man.html)

#### Notes
- Adjust port range based on target environment to balance speed and thoroughness.

---