# PART I - Challenge 1 💬ANSWER: henry.ns.cloudflare.com💬
dig -x 173.245.59.176
host 173.245.59.176

# PART I - Challenge 2 💬ANSWER: 5💬
nmap -sn 192.168.10.0/24

# PART I - Challenge 3 💬ANSWER: 192.168.10.111💬 && PART I - Challenge 4 💬ANSWER: 192.168.0.222💬  
nmap -p 22 -sV 192.168.10.0/24

# PART I - Challenge 5 💬ANSWER: SKILL.CEH💬
# ntbscan -v 192.168.0.222
# nbmlookup -A 192.168.0.222
enum4linux -a 192.168.0.222

# PART I - Challenge 6 💬ANSWER: SKILL.CEH.com💬
# nslookup 192.168.0.222
# nmap -sL 192.168.0.222
nmap -p 445 --script smb-os-discovery 192.168.0.222
ldapsearch -x -H ldap://192.168.0.222 -s base -b "" namingContexts

# PART I - Challenge 7  💬ANSWER: 8.9p1💬
nmap -p 22 -sV 192.16.10.0/24

# PART I - Challenge 8  💬ANSWER: Ubuntu💬
nmap -p 3306 --open -sV -T4 172.30.10.0/24
nmap -O 172.30.10.99
ssh -v -o BatchMode=yes -o ConnectTimeout=3 172.30.10.99 2>&1

# PART I - Challenge 9  💬ANSWER: 192.168.10.144💬
nmap -p 1433 --open 192.168.10.0/24

# PART I - Challenge 10  💬ANSWER: ns1.bluehost.com, ns2.bluehost.com💬
dig NS certifiedhacker.com +short

# PART I - Challenge 11 💬ANSWER: 172.30.10.200💬
nmap -p 25,587 --open 172.30.10.0/24

# PART I - Challenge 12 💬ANSWER: No💬
# smbclient -L 172.30.10.200 -U user
# rpcclient -U user 172.30.10.200
nmap -p 445 --script smb-security-mode 172.30.10.200 -oN smb_security_1723010200.txt
cat smb_security_1723010200.txt


# PART I - Challenge 13 💬ANSWER: Incorrect Default Permissions💬
#### GOOGLE: cwe.mitre.org/data/definitions/276.html

# PART I - Challenge 14 💬ANSWER: 70💬 && PART I - Challenge 15 💬ANSWER: FTP Unencrypted Cleartext Login💬
#### StartOpenVAS --> http://127.0.0.1/login/login.html
#### Configuration --> Targets
#### Task --> New Task --> Run