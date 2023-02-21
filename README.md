# penetration-test
# Rekall Penetration Test

Conducted inside a pentesting lab enviornemnt located in Windows Azure Lab Services.

Hyper-V VMs used:
- Kali
- Metasploitable2
- Windows 10
- WINDC01

## Objective
  - Find and exfiltrate any sensitive information within the domain
  - Escalate privliges
  - Compromise several machines
  
## Reconniassance
Check any passive data 
  - Nmap
  
## Identification of Vulnerabilities and Services
Gain perspective of the network from hackers point of view
  - Metasploit
  - John the Ripper/hashcat
  
## Vulnerability Exploitation
Exploitation is defined as any action performed that allows unauthorized access to the system or sensitive data

## Reporting
Written report of findings is the final deliverable to the customer

# Scope
Prior to any assessment activities, Rekall and the assessment team will identify targeted systems with a defined range or list of network IP addresses. The assessment team will work directly with the Rekall POC to determine which network ranges are in-scope for the scheduled assessment. 

It is Rekall’s responsibility to ensure that IP addresses identified as in-scope are actually controlled by Rekall and are hosted in Rekall-owned facilities (i.e., are not hosted by an external organization).

# Executive Summary of Findings

## Grading Methology

  - Critical: Immediate threat to key business processes
  - High: Indirect threat to key business processes/threat to secondary business processes
  - Medium: Indirect or partial threat to business processes
  - Low: No direct threat exists; vulnerability may be leveraged with other vulnerabilities
  - Informational: No threat; however, it is data that may be used in a future attack
  
## Summary of Strengths
  
  There was a severe lack of strengths, however, the process of discovering and mitigating the following vulnerabilities will enhance the security system

## Summary of Weaknesses

  - Struts VUlnerabilites
  - SSH Brute Force
  - Apache Shellshock Vulnerabilities
  - Apache Tomcat Bypass allowing Remote Control Execution
  - John the Ripper susceptible
  
## SSH Brute Force

The recon started with the OSINT Framework. The domain dossier within the Framework revealed admin name sshUser Alice.

![sshbruteforce](https://user-images.githubusercontent.com/109919882/220445945-74ad6464-84e6-4396-b73e-ad2173a3420b.png)

Rekall Corporation provided a series of IP addresses that was ran through an Nmap scan to decipher which IP addresses had active servers.

![nmap scan](https://user-images.githubusercontent.com/109919882/220446269-e250c9fa-7253-481d-861f-596870aef300.png)

Port 192.168.13.14 had port 22 open. Trial and error attempts to ssh into the server revealed the user was Alice and the password was Alice, as well.

![sshsudo](https://user-images.githubusercontent.com/109919882/220446836-415fc1c1-6d1d-4956-adca-ab98a91c24a7.png)

Using Alice's credentials, the sudo command easily allowed root access.

## Struts Vulnerabilities

![apache struts](https://user-images.githubusercontent.com/109919882/220447078-16acb60a-efe5-4988-91d4-07e7470f6901.png)

A Nessus scan was run against each active IP address in the initial Nmap scan to pinpoint other vulnerabilities for portential attacks.

The IP address 192.168.13.12 was found susceptible to Remote Code Execution. Msfconsole in Kali Linux exploited the vulnerability. The Strusts vulnerability allowed a meterpreter shell to open on the target computer. The root folder was able to be accessed via the vulnerability.

![msfconsolevulnerability](https://user-images.githubusercontent.com/109919882/220448000-ddb3c072-d8f6-4141-bd13-04f54b989c64.png)

## Remote Control Execution (RCE) via Apache Tomcat Bypass

![remoteaccess](https://user-images.githubusercontent.com/109919882/220448169-969db3fc-5f3f-4d4f-b1b4-ecd5efdedb86.png)

The tomcat_jsp_upload_bypass allowed a shell to be created that provided access to the server.

## Password Cracking via John the Ripper

![pentestjohn](https://user-images.githubusercontent.com/109919882/220448707-f50106af-2e9c-4ed5-ae20-ecc07072ef9d.png)

The hash for user pparker was exploited using John the Ripper. A nano text file was made containing the hash. The text file was uploaded to the command <pre><code>john</code></pre> which cracked the password for the account. The credentials were used to run root.

## Apache-Shellshock

The shellshock vulnerability allowed a meterpreter shell to open, targeting the shockme.cgi web page and gave access to the server. This exploit revealed sudoers file information that showed the users of the admin group. With access to the admin group credentials, root privileges were achived. Further scanning gave access to the /etc/passwd.

![apache shell shock](https://user-images.githubusercontent.com/109919882/220449861-4a43810f-1d07-4f98-8a19-d7df552d4b8b.png)

![etcpsswd](https://user-images.githubusercontent.com/109919882/220450047-02cd9bb2-4814-4f63-bcc7-a6a003fd2ed5.png)

# Summary Vulnerability Overview

| Vulnerability | Severity |
| ------------- | -------------|
| SSH Brute Force Attack | Critical |
| Struts | High |
| RCE Apache Tomcat Bypass | High |
| John the Ripper | High |
| Apache-Shellshock | High |

| Scan Type | Total |
| ------------- | ------------- |
| Hosts | 5 |
|Ports | 21, 22, 25, 79, 80, 106, 110 |

| Exploitation Risk | Total |
| ------------- | ------------- |
| Critical | 1 |
| High | 4 |
| Medium | 0 |
| Low | 0 |

# Vulnerability Findings

| Vulnerability 1 | Findings |
| ------------- | ------------- |
| Title | SSH Brute Force Attack |
| Type (Web app/Linux OS/Windows OS)| Linux/Windows |
| Risk Rating | Critical |
| Description | Allowed access to the domian dossier server of OSINT Framework tool via SSH |
| Remediation | Multifactor authentifiaction for SSH access. mLimiting login attempts to 5. Require password length greater than 8 and use of special characters |

| Vulnerability 2 | Findings |
| ------------- | ------------- |
| Title | Apache Struts |
| Type | Linux |
| Risk Rating | High |
| Description | Apache struts vulnerability that granted access to server through remote code execution |
| Remediation | Strong validation to protect against injection attacks. Patch and update Struts framework |

| Vulnerability 3 | Findings |
| ------------- | ------------- |
| Title | Apache-Shellshock |
| Type | Linux |
| Risk Rating | High |
| Description | Shellshock exploit on MSFconsole. Targeted URI /cgi-bin/shockme.cgi web page and opened a meterpreter shell |
| Remediation | Eliminate ability to run shell commands in HTTP headers. Update and patch Apache HTTP server |

| Vulnerability 4 | Findings |
| ------------- | ------------- |
| Title | Password Cracking via John the Ripper |
| Type | Linux |
| Risk Rating | High |
| Description | Accquired user's password hash and ran it through john command. Revealed username and password which was used to elevate privileges to root |
| Remediation | Encrypt password hashes. Salt and pepper hashes |

| Vulnerability 5 | Findings |
| ------------- | -------------| 
| Title | Apache Tomcat Bypass allowing Remote COntrol Execution |
| Type | Linux |
| Risk Rating | High |
| Description | Nmap scan revealed vulnerabilites in the server.m Implemented remote code execution to exploit server |
| Remediation | Stronger and encrypted passwords for Tomcat manager user accounts. Ensure lates security paches are applied to Apache Tomcat server |
