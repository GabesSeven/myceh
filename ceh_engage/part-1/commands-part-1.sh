####### Arrumar teclado em pt-br
# Vá em Menu → Preferences → Keyboard → Layouts
# Clique em Add → Portuguese (Brazil)
# Selecione Portuguese (Brazil, ABNT2)
# Remova o layout antigo (geralmente “English (US)”)

xdg-open .

ip addr show
## ip route show
## ifconfig

## sudo apt install arp-scan -y
## sudo arp-scan --locanet
sudo nmap -sn 172.25.0.0/24
# 172.25.0.1
# 172.25.0.10 # Linux
# 172.25.0.11 # Windows

whoami
## id -un
## id

ss -tnp | grep sshd

ssh 172.25.0.11
ssh $(whoami)@172.25.0.11

# NO WINDOWS
echo %USERPROFILE%

where ncat
where nc

# ncat -l -p 4444 < "%USERPROFILE%\Documents\pawned.txt"
cd /d "%USERPROFILE%\Documents"
ncat -v -l -p 4444 < pawned.txt

# NO LINUX
nc -zv 172.25.0.11 4444
ping -c 3 172.25.0.11

nc -v 172.25.0.11 4444 > pawnet.txt

ls -l pawned.txt
file pawned.txt
xxd -l 80 pawned.txt | sed -n '1,6p'
strings pawned.txt | head -n 40




Olá tudo bem? Gostaria de saber a localizacao
Estou pretendendo ficar 4 meses em Itajaí. Qualquer coisa renovo mais por mais tempo