#!/bin/bash

# Define o alvo individual e o range de IPs
TARGET_IP="10.10.1.22"
TARGET_RANGE_1="10.10.1.10-23"
TARGET_RANGE_2="10.10.1.*"

###############
# MOD 3 - Lab 1: Perform Host Discovery
###############

nmap -sn -PR $TARGET_IP # ARP Ping Scan - Envia requisição ARP para ver se o host responde. Usado principalmente em redes locais (LAN).
nmap -sn -PU $TARGET_IP # UDP Ping Scan - Envia pacotes UDP. Se o host estiver ativo, pode responder ou gerar mensagens ICMP de erro.
nmap -sn -PE $TARGET_IP # ICMP Echo Ping Scan - Envia "ping" padrão (ICMP Echo Request) e espera resposta.
nmap -sn -PE $TARGET_RANGE_1 # ICMP Echo Ping Sweep - Escaneia múltiplos IPs com ICMP para encontrar hosts ativos.
nmap -sn -PP $TARGET_IP # ICMP Timestamp Ping - Envia requisição ICMP de timestamp. Host ativo responde com a hora.
nmap -sn -PM $TARGET_IP # ICMP Address Mask Ping - Alternativa ao ping padrão, útil quando ICMP Echo está bloqueado.
nmap -sn -PS $TARGET_IP # TCP SYN Ping - Envia pacotes SYN. Se o host responder com ACK/RST, está ativo.
nmap -sn -PA $TARGET_IP # TCP ACK Ping - Envia pacotes ACK. Um RST como resposta indica que o host está ativo.
nmap -sn -PO $TARGET_IP # IP Protocol Ping - Envia pacotes com diferentes protocolos IP. Qualquer resposta indica host ativo.


###############
# MOD 3 - Lab 2: Perform Port and Service Discovery
###############

nmap -sT -v $TARGET_IP   # TCP Connect Scan - Faz handshake completo (3-way) com o alvo. Detecta serviços com precisão, mas é mais ruidoso.
nmap -sS -v $TARGET_IP   # Stealth Scan (Half-Open) - Envia SYN e finaliza com RST. Menos detectável por firewalls e logs.
nmap -sX -v $TARGET_IP   # Xmas Scan - Envia pacotes com flags FIN, URG e PUSH. Pode burlar alguns firewalls, útil em detecção passiva.
nmap -sM -v $TARGET_IP   # Maimon Scan - Envia FIN/ACK. Útil para identificar hosts com comportamento incomum com pacotes estranhos.
nmap -sA -v $TARGET_IP   # ACK Scan - Verifica regras de filtragem de firewall. Útil para mapear presença de firewalls stateful.
nmap -sU -v $TARGET_IP   # UDP Scan - Envia pacotes UDP. Lento, mas necessário para encontrar serviços sem conexão como DNS, SNMP, etc.
nmap -sV $TARGET_IP      # Service Version Detection - Detecta versão dos serviços. Essencial para identificar vulnerabilidades conhecidas.
nmap -A $TARGET_RANGE_2    # Aggressive Scan - Inclui OS detection, versão, scripts NSE e traceroute. Muito informativo, mas invasivo.
nmap -sI -v $TARGET_IP   # Idle/IPID Scan - Scan furtivo usando host zumbi. Oculta IP real do atacante. Requer IPID previsível no zumbi.
nmap -sY -v $TARGET_IP   # SCTP INIT Scan - Envia pacote INIT SCTP. INIT+ACK indica porta aberta. Útil para sistemas que usam SCTP (ex: telecom).
nmap -sZ -v $TARGET_IP   # SCTP COOKIE ECHO Scan - Envia COOKIE-ECHO. Sem resposta = aberta. ABORT = fechada. Menos ruidoso que INIT.


###############
# MOD 3 - Lab 3: Perform OS Discovery
###############

nmap -A $TARGET_IP # Agressive Scan - Detecta OS, versões de serviços, realiza traceroute e executa scripts NSE padrão.
nmap -O $TARGET_IP # OS Detection - Analisa TTL, TCP window size, opções IP e comportamento do protocolo para identificar o sistema operacional.
nmap --script smb-os-discovery.nse $TARGET_IP # SMB OS Discovery - Usa o protocolo SMB (ports 445/139) para descobrir OS, hostname, domínio e horário da máquina.


###############
# MOD 3 - Lab 4: Scan beyond IDS and Firewall
###############

nmap -f $TARGET_IP # Fragmentação - Envia pacotes IP fragmentados. IDSs mal configurados podem ignorar esses fragmentos.
nmap -g 80 $TARGET_IP # Source Port Manipulation - Usa porta de origem 80 (HTTP) para tentar burlar firewalls que permitem portas comuns.
nmap --mtu 8 $TARGET_IP # MTU - Define o tamanho máximo dos pacotes como 8 bytes, provocando fragmentação e evasão de filtros.
nmap -D RND:10 $TARGET_IP # Decoy Scan - Envia pacotes com 10 IPs falsos misturados ao IP real para dificultar rastreamento.
nmap -sT -Pn --spoof-mac 0 $TARGET_IP # MAC Spoofing - Faz uma varredura TCP completa com MAC address aleatório, sem enviar pings ICMP.


###############
# MOD 3 - Lab 5: Perform Network Scanning using Various Scanning Tools
###############

msfconsole # Iniciar o Metasploit Framework
nmap -Pn -sS -A -oX Test 10.10.1.0/24 # 🔍 1. Escaneamento com Nmap a partir do console do Metasploit. Realiza uma varredura completa na rede 10.10.1.0/24 com técnicas agressivas e salva a saída em XML
search portscan # 🔍 2. Procurar por módulos de portscan no Metasploit
use auxiliary/scanner/portscan/syn # 🔍 3. Utilizar o módulo SYN Scan auxiliar
set INTERFACE eth0 # Definir interface de rede (eth0), porta alvo (80), IPs alvo e quantidade de threads
set PORTS 80
set RHOSTS 10.10.1.5-23
set THREADS 50
run # Iniciar a varredura SYN

use auxiliary/scanner/portscan/tcp # 🔍 4. Utilizar o módulo TCP Connect Scan
show options # Mostrar opções do módulo
set RHOSTS 10.10.1.22 # Definir IP de destino único (ex: 10.10.1.22) para escanear todas as TCP
run # Iniciar a varredura TCP (pode levar ~20min)

back # 🔍 5. Determinar versão do SMB/OS usando módulo de verificação SMB
use auxiliary/scanner/smb/smb_version
set RHOSTS 10.10.1.5-23 # Definir IPs de destino e número de threads
set THREADS 11
run # Iniciar o scanner SMB para coletar versão do SO e do Samba


###############
# MOD 3 - Lab 6: Perform Network Scanning using AI 
###############

bash sgpt.sh # 🚀 2. Iniciar a configuração do ShellGPT # (Aqui será necessário inserir a chave de ativação do AI)
sgpt --chat scan --shell "Use hping3 to perform ICMP scanning on the target IP address 10.10.1.11 and stop after 10 iterations" # 🧠 3. ICMP Scan (com hping3)
sgpt --chat scan --shell "Run a hping3 ACK scan on port 80 of target IP 10.10.1.11" # 🧠 4. ACK Scan na porta 80 com hping3
sgpt --chat scan --shell "Scan the target network 10.10.1.0/24 for active hosts and place only the IP addresses into a file scan1.txt" # 🧠 5. Descoberta de hosts ativos (salvar IPs no arquivo scan1.txt)
pluma scan1.txt # 📂 Ver os IPs encontrados
sgpt --chat scan --shell "Run a fast but comprehensive nmap scan against scan1.txt with low verbosity and write the results to scan2.txt" # 🧠 6. Scan Nmap rápido e abrangente (usando lista scan1.txt e salvando em scan2.txt)
pluma scan2.txt # 📂 Ver resultados do scan
sgpt --chat scan --shell "Use nmap to perform ICMP ECHO ping sweep on the target network 10.10.1.0/24" # 🧠 7. ICMP Echo ping sweep com Nmap
sgpt --chat scan --shell "Use nmap to find open ports on target IP 10.10.1.11" # 🧠 8. Port Scan tradicional com Nmap
sgpt --chat scan --shell "Perform stealth scan on target IP 10.10.1.11 and display the results" # 🧠 9. Stealth Scan (SYN Scan)
sgpt --chat scan --shell "Perform an XMAS scan on target IP 10.10.1.11" # 🧠 10. XMAS Scan
sgpt --chat scan --shell "Use Nmap to scan for open ports and services against a list of IP addresses in scan1.txt and copy only the port, service and version information with the respective IP address to a new file called scan3.txt" # 🧠 11. Scan completo com Nmap: serviços + versões (lista de IPs em scan1.txt, saída em scan3.txt)
pluma scan3.txt # 📂 Ver os resultados do scan3
sgpt --chat scan --shell "Use Metasploit to discover open ports on the IP address 10.10.1.22" # 🧠 12. Usar Metasploit via ShellGPT
sgpt --chat scan --shell "Use Nmap to scan open ports, MAC details, services running on open ports with their versions on target IP 10.10.1.11" # 🧠 13. Service Version Detection via Nmap
sgpt --chat scan --shell "Use TTL value and identify the operating system running on the target IP address 10.10.1.11, display the TTL value and OS" # 🧠 14. Descobrir SO com TTL
sgpt --chat scan --shell "Use TTL value and identify the operating system running on the target IP address 10.10.1.9, display the TTL value and OS"
sgpt --chat scan --shell "Use Nmap script engine to perform OS discovery on the target IP addresses in scan1.txt" # 🧠 15. Descoberta de SOs via NSE (Nmap Scripting Engine)
sgpt --chat scan --shell "Develop a script which will automate network scanning efforts and find out live systems, open ports, running services, service versions, etc. on target IP range 10.10.1.0/24" # 🧠 16. Criar um script automatizado com ShellGPT
sgpt --chat scan --shell "To evade an IDS/Firewall, use IP address decoy technique to scan the target IP address 10.10.1.22" # 🧠 17. Técnicas de evasão: Decoy Scan com Nmap
sgpt --chat scan --shell "Within scan1.txt file remove 10.10.1.14 and 10.10.1.13 entries, then display results" # 🧠 18. Manipular scan1.txt: remover IPs específicos
sgpt --chat scancode --code "Create a python script to run a fast but comprehensive Nmap scan on the IP addresses in scan1.txt and then execute vulnerability scanning using nikto against each IP address in scan1.txt" # 🐍 19. Criar script em Python para Nmap + Nikto (scan + vulnerability assessment)
pluma python_scan.py  # colar e salvar o código # 🐍 Editar e executar o script Python
python3 python_scan.py


