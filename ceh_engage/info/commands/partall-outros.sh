### VERIFICAR DENTRO DA MESMA REDE
# ifconfig
ip addr show
ip neigh show
# ip neigh show nud reachable
sudo arp-scan --interface=eth0 --localnet
# arping -b -I eth0 192.168.1.1 # Envia requisições para toda rede local

### VERIFICAR DENTRO DA MESMA REDE - FLUXO COMPLETO
# ip neigh flush all # Limpa completamente a tabela ARP
# ping -b 192.168.1.255 # Pinga no broadcast
# sleep 3 # Espera tabela ser atualizada
# ip neigh # Exibe tabela ARP
## ip -6 neigh
# tcpdump -i eth0 arp # Exibe tráfego ARP
## tcpdump -e -n -i eth0 arp

### VERIFICAR DENTRO DA MESMA REDE - OUTROS IMPORTANT COMMANDS
bridge fdb show # Analisa tabela de encaminhamento (FDB – Forwarding Database), usada para saber onde encaminhar frames Ethernet: MAC address → porta/interface → VLAN → estado

### VERIFICAR DENTRO DE OUTRAS REDES
###
# Você NUNCA verá ARP da rede remota.
# Você verá apenas:
#     Gateway (MAC)
#     IPs de destino nos pacotes IP
# Isso é por design da pilha TCP/IP.
###

ip route show
# tcpdump -i wlan0 -n not net 192.168.18.0/24 # Capiturar tráfego que não é de LAN
ss -tunp # Ver conexões ativas
sudo conntrack -L # Ver histórico de conexões
ip route show table all # Descobrir redes acessíveis além da LAN


#### DICA PARA SALVAR SOMENTE OS IPs
## 1.3
nmap -sn -PR -T5 -n 192.168.10.0/24 | grep "Nmap scan report for" | awk '{print $5}' > ~/anotacoes/1_2.txt
nmap -sn -PR -T5 -n 192.168.10.0/24 | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' > ~/anotacoes/1_2.txt
nmap -sn -PR -T5 -n 192.168.10.0/24 -oG - | awk '/Up$/{print $2}' > ~/anotacoes/1_2.txt
## 1.4
nmap -p 53,88,389,445 --open -n -T5 --min-rate 1000 -iL ~/anotacoes/1_2.txt -oN ~/anotacoes/ad_services_fast.txt
nmap -p 53,88,389,445 -sV --version-light -iL ~/anotacoes/ad_hosts.txt
nmap -p 53,88,389,445 --open -n -T4 -iL ~/anotacoes/1_2.txt -oG - | awk '/open/{print $2}' | sort -u > ~/anotacoes/ad_hosts.txt
nmap -sV -p 53,88,389,445 -iL ~/anotacoes/ad_hosts.txt


#### PENTEST SMB
# smbclient -L 172.30.10.200 -U user # Conecta via SMB
# rpcclient -U user 172.30.10.200 # Conecta ao serviço MS-RPC via SMB
