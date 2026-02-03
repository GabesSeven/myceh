#------------------------------#


# PART I - Challenge 1 💬ANSWER: henry.ns.cloudflare.com💬
#### EH Workstation-1: C:\Users\Admin\Documents\Dumpster.xlsx # Abrir ele com MS Excel
### INFO: IP Address → 173.245.59.176
### INFO: Hostname → henry.ns.cloudflare.com

# ⚠️ IMPORTANT COMMANDS
dig -x 173.245.59.176 +short
# dig -x 173.245.59.176
# host 173.245.59.176


#------------------------------#


# PART I - Challenge 2 💬ANSWER: 5💬
nmap -sn -PR -T5 -n 192.168.10.0/24
### INFO: IP Address → 192.168.10.1, 192.168.10.101, 192.168.10.111, 192.168.10.121, 192.168.10.144, 192.168.10.222

# ⚠️ IMPORTANT COMMANDS
# nmap -sn -PR -T5 -n 192.168.10.0/24 -oG - | awk '/Up$/{print $2}' > ~/anotacoes/1_2.txt
# nmap -sn -PR -n --exclude 192.168.10.1 192.168.10.0/24


#------------------------------#


# PART I - Challenge 3 💬ANSWER: 192.168.10.111💬
# PART I - Challenge 7  💬ANSWER: 8.9p1💬
nmap -p 22 --open 192.168.10.101 192.168.10.111 192.168.10.121 192.168.10.144 192.168.10.222 
nmap -p 22 -sV --version-light 192.168.10.101 192.168.10.111
### INFO: 22/tcp  open  ssh  OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0) 

# ⚠️ IMPORTANT COMMANDS
# nmap -O --osscan-limit 192.168.10.101 192.168.10.111 # ⚠️ WARNING: Use only on hosts with SSH enabled.


#------------------------------#


# PART I - Challenge 4 💬ANSWER: 192.168.0.222💬  
nmap -sn -PR -T5 -n 192.168.0.0/24
nmap -p 53,88,135,139,389,445 --open -n -T5 --min-rate 1000 192.168.0.222
### INFO: 135/tcp  open  msrpc          Microsoft Windows RPC
### INFO: 139/tcp  open  netbios-ssn    Microsoft Windows netbios-ssn
### INFO: 389/tcp  open  ldap           Microsoft Windows Active Directory LDAP  MIicrosoft Windows Active Directory LDAP (Domain: SKILL.CEH.com0., Site: Default-First-Site-Name)
### INFO: 445/tcp  open  microsoft-ds   Microsoft Windows Serve 2008 R2 - 2012 microsoft-ds (workgroup; SKILL.CEH) 
### INFO: Service Info: Host: SKILL; OS: WIndows; CPE: cpe:/o:microsoft:windows

nmap -p 445 --script smb-os-discovery 192.168.0.222 # 🔘 OPTIONAL

# ⚠️ IMPORTANT COMMANDS
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

nmap -sS -sV -p 389,445 192.168.0.222 # 🔘 OPTIONAL

# ⚠️ IMPORTANT COMMANDS
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

nmap -p 445 --script smb-os-discovery 192.168.0.222 # 🔘 OPTIONAL
nmap -sS -sV -p 389,445 192.168.0.222 # 🔘 OPTIONAL


#------------------------------#


# PART I - Challenge 8  💬ANSWER: Ubuntu💬
nmap -p 3306 --open -T4 172.30.10.0/24
nmap -p 22 -sV 172.30.10.99
# ssh -v -o BatchMode=yes -o ConnectTimeout=3 172.30.10.99

# nmap -p 3306 -sV 172.30.10.99 # BANNER NÃO AUTORIZADO
# nmap -sV -O -p 3306 172.30.10.99 # APRESENTOU POSSÍVEIS VERSÕES DE KERNEL

## 🗒️ NOTES
echo -e "172.30.10.99 --> msql --> Ubuntu" > ~/anotacoes/1_4.txt
cat ~/anotacoes/1_6.txt


#------------------------------#


# PART I - Challenge 9  💬ANSWER: 192.168.10.144💬
nmap -p 1433 --open -iL ~/anotacoes/1_2.txt # 1433 porta padrão do Microsoft SQL Server (MSSQL)
nmap -sV --script ms-sql-info,ms-sql-ntlm-info -p 1433 192.168.10.144
# nmap -T4 -A -p 1433 192.168.10.144

## 🗒️ NOTES
echo -e "192.168.10.144 --> 1433 ms-sql-s" > ~/anotacoes/1_9.txt
cat ~/anotacoes/1_9.txt


#------------------------------#


# PART I - Challenge 10  💬ANSWER: ns1.bluehost.com, ns2.bluehost.com💬
dig NS certifiedhacker.com +short
#### ~/PhoneSploit-Pro/phonesploitpro.py
sudo su
### PASSWORD: toor
python ~/PhoneSploit-Pro/phonesploitpro.py
### [Y] Yes → [N] Next Page → [N] Next Page → [39] Use Keycodes (Control Device) → [5] Power Button → [0] Exit
### INFO: 5. Power Button
## 🗒️ NOTES
echo -e "certifiedhacker.com (NS):\nns1.bluehost.com\nns2.bluehost.com" > ~/anotacoes/1_10.txt
cat ~/anotacoes/1_10.txt


#------------------------------#


# PART I - Challenge 11 💬ANSWER: 172.30.10.200💬
nmap -p 25,587 --open 172.30.10.0/24 # Portas padrão do SMTP (25 = envio tradicional, 587 = envio autenticado/submit)

## 🗒️ NOTES
echo -e "172.30.10.200 --> 25 smb" > ~/anotacoes/1_11.txt
cat ~/anotacoes/1_11.txt


#------------------------------#


# PART I - Challenge 12 💬ANSWER: No💬
nmap -p 445 --script smb-security-mode,smb-os-discovery,smb2-security-mode 172.30.10.200 

## 🗒️ NOTES
echo -e "SMB signing habilitado mas não requerido (smb relay attack, ntlm relay, mitm)" >> ~/anotacoes/1_11.txt
cat ~/anotacoes/1_11.txt


#------------------------------#


# PART I - Challenge 13 💬ANSWER: Incorrect Default Permissions💬
cwe 276 site:mitre.org
#### GOOGLE: cwe.mitre.org/data/definitions/276.html



#------------------------------#


# PART I - Challenge 14 💬ANSWER: 70💬
# PART I - Challenge 15 💬ANSWER: FTP Unencrypted Cleartext Login💬
#### ~/Desktop/StartOpenVAS
#### GOOGLE: http://127.0.0.1/login/login.html  
### USERNAME: admin
### PASSWORD: admin
#### Scans → Tasks → ⭐ → New Tasks → (Scan Targets ⭐) → Create → ▶️
####    Name: Task-Linux-192.168.10
####    Scan Targets: Linux-192.168.10
####    Scan Config: Full and fast
#### (Scan Targets ⭐) → New Target → OK
####    Name: Linux-192.168.10
####    Hosts: 192.168.10.111,192.168.10.121,192.168.10.144,192.168.10.222
####    Port List: Default
####    Alive Test: ICMP + TCP-ACK Service & ARP Ping
####    Credentials fot authenticated checks SSH on port: 22
#### Scans → Dashboard
### INFO: Medium (4)
### INFO:   DCE/RPC and MSRPC Services Enumeration Reporting → QoD → 70%
### INFO:   DCE/RPC and MSRPC Services Enumeration Reporting → Severity → 5.0 (Medium)
### INFO:   DCE/RPC and MSRPC Services Enumeration Reporting → Host → 192.168.10.144
### INFO:   FTP Unencrypted Cleartext Login → QoD → 70%
### INFO:   FTP Unencrypted Cleartext Login → Severity → 4.8 (Medium)
### INFO:   FTP Unencrypted Cleartext Login → Host → 192.168.10.144

### Assets → Dashboard --> Host topology

### Configuration → Targets
### Scans → Tasks
### Scans → Dashboard
### Assets → Hosts
### Assets → Dashboard

## 🗒️ NOTES
echo -e "FTP Unencrypted Cleartext Login = não possui TLS/SSL" > ~/anotacoes/1_15.txt
cat ~/anotacoes/1_15.txt
