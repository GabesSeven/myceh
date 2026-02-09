#------------------------------#


# PART I - Challenge 1 💬ANSWER: henry.ns.cloudflare.com💬
#### EH Workstation-1: C:\Users\Admin\Documents\Dumpster.xlsx # Abrir ele com MS Excel
### INFO: IP Address → 173.245.59.176
### INFO: Hostname → henry.ns.cloudflare.com

# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***
dig -x 173.245.59.176 +short
# dig -x 173.245.59.176
# host 173.245.59.176
# ping 173.245.59.176
# nmap -sV 173.245.59.176
# nmap -O 173.245.59.176
# nmap -O --osscan-guess --max-os-tries 10 173.245.59.176

#------------------------------#


# PART I - Challenge 2 💬ANSWER: 5💬
nmap -sn -PR -T5 -n 192.168.10.0/24
### INFO: IP Address → 192.168.10.1, 192.168.10.101, 192.168.10.111, 192.168.10.121, 192.168.10.144, 192.168.10.222

# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***
# nmap -sn -PR -T5 -n 192.168.10.0/24 -oG - | awk '/Up$/{print $2}' > ~/output.txt
# nmap -sn -PR -n --exclude 192.168.10.1 192.168.10.0/24


#------------------------------#


# PART I - Challenge 3 💬ANSWER: 192.168.10.111💬
# PART I - Challenge 7  💬ANSWER: 8.9p1💬
nmap -p 22 --open 192.168.10.101 192.168.10.111 192.168.10.121 192.168.10.144 192.168.10.222 
nmap -p 22 -sV --version-light 192.168.10.101 192.168.10.111
### INFO: 22/tcp  open  ssh  OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0) 

# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***
# nmap -O --osscan-limit 192.168.10.101 192.168.10.111 # ⚠️ WARNING: Use only on hosts with SSH enabled.


#------------------------------#


# PART I - Challenge 4 💬ANSWER: 192.168.0.222💬  
nmap -sn -PR -T5 -n 192.168.0.0/24
nmap -p 53,88,135,139,389,445 --open -n -T5 --min-rate 1000 192.168.0.222
### INFO: 135/tcp  open  msrpc          Microsoft Windows RPC
### INFO: 139/tcp  open  netbios-ssn    Microsoft Windows netbios-ssn
### INFO: 389/tcp  open  ldap           Microsoft Windows Active Directory LDAP  MIicrosoft Windows Active Directory LDAP (Domain: SKILL.CEH.com0., Site: Default-First-Site-Name)
### INFO: 445/tcp  open  microsoft-ds   Microsoft Windows Serve 2008 R2 - 2012 microsoft-ds (workgroup; SKILL.CEH) 
### INFO: Service Info: Host: SKILL; OS: Windows; CPE: cpe:/o:microsoft:windows

# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***
nmap -p 445 --script smb-os-discovery 192.168.0.222 # 🔘 OPTIONAL
# nmap -p 53  --open 192.168.0.222 # DNS
# nmap -p 88  --open 192.168.0.222 # Kerberos
# nmap -p 135 --open 192.168.0.222 # RPC
# nmap -p 139 --open 192.168.0.222 # NetBIOS
# nmap -p 389 --open 192.168.0.222 # LDAP
# nmap -p 445 --open 192.168.0.222 # SMB


#------------------------------#


# PART I - Challenge 5 💬ANSWER: SKILL.CEH💬clear
nmap -p 445 --script smb-os-discovery 192.168.0.222
### INFO: smb-os-discovery
### INFO:       OS: Windows Server 2022 Standard 20348 (Windows Server 2022 Standard 6.3)
### INFO:       Computer name: SKILL
### INFO:       NetBIOS computer name: SKILL\x00
### INFO:       Workgroup: : SKILL.CEH\x00
### INFO:       System time: 2026-01-17T12:39:02-08:00

# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***
nmap -sS -sV -p 389,445 192.168.0.222 # 🔘 OPTIONAL
nmap -sV --script ms-sql-info,ms-sql-ntlm-info 192.168.0.222 # 🔘 OPTIONAL
# nmap -sS -sV -p 53,88,135,139,389,445 192.168.0.222
# nmap -O --osscan-limit 192.168.0.222
# enum4linux -a 192.168.0.222


#------------------------------#


# PART I - Challenge 6 💬ANSWER: SKILL.CEH.com💬 
ldapsearch -x -H ldap://192.168.0.222 -s base -b "" namingContexts
### INFO: namingContexts: DC=SKILL,DC=CEH,DC=com
### INFO: namingContexts: CN=Configuration,DC=SKILL,DC=CEH,DC=com
### INFO: namingContexts: CN=Schema,CN=Configuration,DC=SKILL,DC=CEH,DC=com
### INFO: namingContexts: DC=DomainDnsZones,DC=SKILL,DC=CEH,DC=com
### INFO: namingContexts: DC=ForestDnsZones,DC=SKILL,DC=CEH,DC=com

# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***
nmap -p 445 --script smb-os-discovery 192.168.0.222 # 🔘 OPTIONAL
nmap -sS -sV -p 389,445 192.168.0.222 # 🔘 OPTIONAL
nmap -sV --script ms-sql-info,ms-sql-ntlm-info 192.168.0.222 # 🔘 OPTIONAL


#------------------------------#


# PART I - Challenge 8  💬ANSWER: Ubuntu💬
nmap -p 3306 --open -T4 172.30.10.0/24
nmap -p 22 -sV 172.30.10.99
### INFO: 22/tcp  open  ssh  OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0) 
### INFO: Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***
ssh -v -o BatchMode=yes -o ConnectTimeout=3 172.30.10.99 # 🔘 OPTIONAL
# nmap -p 3306 -sV 172.30.10.99 # ⚠️ WARNING: Unauthorized banner.
# nmap -sV -O -p 3306 172.30.10.99 # ⚠️ WARNING: It presented possible kernel versions.
# nmap -sn -PR -T5 -n 172.30.10.0/24


#------------------------------#


# PART I - Challenge 9  💬ANSWER: 192.168.10.144💬
nmap -p 1433 --open 192.168.10.101 192.168.10.111 192.168.10.121 192.168.10.144 192.168.10.222 # ⚠️ WARNING: 1433 is the default port for Microsoft SQL Server (MSSQL).
### INFO: Nmap scan report for 192.168.10.144
### INFO:       1433/tcp  open  ms-sql-s

# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***
nmap -sV --script ms-sql-info,ms-sql-ntlm-info -p 1433 192.168.10.144 # 🔘 OPTIONAL
# nmap -T4 -A 192.168.10.144
# nmap -sV 192.168.10.144
# nmap -O 192.168.10.144
# nmap -O --osscan-guess --max-os-tries 10 192.168.10.144


#------------------------------#


# PART I - Challenge 10  💬ANSWER: ns1.bluehost.com, ns2.bluehost.com💬
dig NS certifiedhacker.com +short
### INFO: ns1.bluehost.com.
### INFO: ns2.bluehost.com.

# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***
# dig A certifiedhacker.com +short
# dig MX certifiedhacker.com +short
# whois 162.241.216.11


#------------------------------#


# PART I - Challenge 11 💬ANSWER: 172.30.10.200💬
nmap -p 25,587 --open 172.30.10.0/24 # ⚠️ WARNING: Standard SMTP ports (25 = traditional sending, 587 = authenticated/submit sending)
### INFO: Nmap scan report for www.goodshopping.com (172.30.10.200)
### INFO: 25/tcp  open  smtp


#------------------------------#


# PART I - Challenge 12 💬ANSWER: No💬
nmap -p 445 --script smb2-security-mode 172.30.10.200 
### INFO: 445/tcp  open  microsoft-ds
### INFO: Host script results
### INFO: | smb2-security-mode:
### INFO: |     3:1:1:
### INFO: |_        Message signing enabled but not requiredd        

# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***
# nmap -p 445 --script smb-security-mode,smb-os-discovery,smb2-security-mode 172.30.10.200 


#------------------------------#


# PART I - Challenge 13 💬ANSWER: Incorrect Default Permissions💬
#### MOZILLA FIREFOX: cwe 276 site:mitre.org
#### MOZILLA FIREFOX: cwe.mitre.org/data/definitions/276.html
### INFO: CWE-276: Incorrect Default Permissions (4.19)


#------------------------------#


# PART I - Challenge 14 💬ANSWER: 70💬
# PART I - Challenge 15 💬ANSWER: FTP Unencrypted Cleartext Login💬
#### EH Workstation-2: ~/Desktop/StartOpenVAS
#### MOZILLA FIREFOX: http://127.0.0.1/login/login.html  
### USERNAME: admin
### PASSWORD: admin
### PATH: Scans → Tasks → ⭐ → New Tasks → (Scan Targets ⭐) → Create → ▶️
###    Name: Task-Linux-192.168.10
###    Scan Targets: Linux-192.168.10
###    Scan Config: Full and fast
### PATH: (Scan Targets ⭐) → New Target → OK
###    Name: Linux-192.168.10
###    Hosts: 192.168.10.111,192.168.10.121,192.168.10.144,192.168.10.222
###    Port List: Default
###    Alive Test: ICMP + TCP-ACK Service & ARP Ping
###    Credentials fot authenticated checks SSH on port: 22
### PATH: Scans → Dashboard
### INFO: Medium (4)
### INFO:   DCE/RPC and MSRPC Services Enumeration Reporting → QoD → 70%
### INFO:   DCE/RPC and MSRPC Services Enumeration Reporting → Severity → 5.0 (Medium)
### INFO:   DCE/RPC and MSRPC Services Enumeration Reporting → Host → 192.168.10.144
### INFO:   FTP Unencrypted Cleartext Login → QoD → 70%
### INFO:   FTP Unencrypted Cleartext Login → Severity → 4.8 (Medium)
### INFO:   FTP Unencrypted Cleartext Login → Host → 192.168.10.144

# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***
### PATH: Assets → Dashboard → Host topology
### PATH: Configuration → Targets
### PATH: Scans → Tasks
### PATH: Scans → Dashboard
### PATH: Assets → Hosts
### PATH: Assets → Dashboard
