#!/bin/bash



###############
# MOD 16 - Lab 1: Perform wireless traffic analysis
###############

########
# TASK 1: Wi-Fi packet analysis using Wireshark
########

# Objetivo
#   Realizar análise de pacotes Wi-Fi capturados em uma rede wireless vulnerável para:
#   Identificar o SSID (nome da rede),
#   Descobrir o método de autenticação,
#   Verificar o algoritmo de criptografia (WEP, WPA, WPA2),
#   Analisar pacotes de controle, gerenciamento e dados do padrão 802.11,
#   Extrair dados úteis sobre a estrutura e segurança da rede wireless.

# Ferramentas Utilizadas
#   Wireshark	Sniffer e analisador de pacotes
#   Arquivo WPA2crack-01.cap	Arquivo .cap com pacotes wireless capturados previamente
#   Protocolo 802.11	Padrão de pacotes de rede wireless
#   Radiotap Header	Contém metadados de sinal como força, canal, taxa

# Fluxo Resumido do Lab
graph TD
# A[Iniciar Windows 11 VM] --> B[Fazer login como Admin]
# B --> C[Abrir Wireshark]
# C --> D[Abrir arquivo WPA2crack-01.cap]
# D --> E[Aplicar filtros e analisar pacotes 802.11]
# E --> F[Examinar SSID, MACs, criptografia e protocolos]

# Acessar a Máquina e Fazer Login
#   Sistema: Windows 11 (iLabs)
#   Login:
#       Usuário: Admin
#       Senha: Pa$$w0rd
#   Quando aparecer o aviso de rede:
#   Clique Yes para tornar o PC detectável na rede (importante em redes corporativas para futuras análises).

# Abrir o Wireshark
#   Clique na 🔍 lupa (barra de busca).
#   Digite Wireshark e clique para abrir o aplicativo.
#   Se aparecer janela de atualização, clique em “Skip this version”.

# Abrir Arquivo de Captura (.cap)
#   Menu superior → clique em File > Open.
#   Navegue até:
E:\CEH-Tools\CEHv13 Module 16 Hacking Wireless Networks\Sample Captures
#   Selecione o arquivo:
WPA2crack-01.cap
#   Clique em Open.

# Entendendo a Captura WPA2crack-01.cap
#   O arquivo contém pacotes capturados de uma rede Wi-Fi com criptografia WPA2.
#   Os pacotes estão no formato IEEE 802.11.
#   Podem ser do tipo:
#       Gerenciamento: Beacon frames, Probe requests/responses, Authentication, Association
#       Controle: RTS/CTS, ACKs
#       Dados: Tráfego entre clientes e access point

# Aplicar Filtros de Pacote no Wireshark
#   Para filtrar pacotes somente Wi-Fi (802.11):
wlan
#   Para ver somente Beacon Frames (Broadcast de SSID):
wlan.fc.type_subtype == 0x08
#   Para filtrar pacotes com SSID explícito:
wlan.ssid
#   Para ver pacotes do protocolo EAPOL (handshake WPA/WPA2):
eapol
#   Isso é essencial para ataques como:
#       Captura de handshake WPA2
#       Crack de senhas com ferramentas como Hashcat e Aircrack-ng
#   Identifica dispositivos envolvidos
wlan.sa
wlan.da

# Informações Técnicas Importantes Observadas
#   SSID	                Tagged Parameters → SSID	Nome da rede
#   BSSID	                wlan.sa ou wlan.bssid	    MAC do AP
#   Estação (cliente)	    wlan.da ou wlan.ta	        MAC do cliente conectado
#   Criptografia	        RSN Information	            Mostra WPA/WPA2 e tipo de cifra (AES, TKIP)
#   Handshake WPA2	        EAPOL	                    Pacotes usados para capturar hashes de senha
#   Canal/RSSI/SNR	        Radiotap Header	            Canal usado e qualidade do sinal

# Importância da Análise de Tráfego Wireless
#   Permite entender a estrutura da rede sem precisar estar conectado.
#   Ajuda a identificar vulnerabilidades como uso de WEP ou WPA desatualizado.
#   Captura do handshake EAPOL permite:
#       Cracking offline da senha WPA/WPA2 usando ferramentas como:
#           aircrack-ng
#           hashcat
#   Possibilita ataques como:
#       Rogue AP (Evil Twin)
#       Deauth Attacks
#       Sniffing de sessões não criptografadas (HTTP)

# Ferramentas Alternativas para Análise Wireless
#   Além do Wireshark, o lab cita ferramentas profissionais como:
#       AirMagnet WiFi Analyzer PRO	    Análise profissional de WLANs
https://www.netally.com
#       SteelCentral Packet Analyzer	Análise de performance de rede
https://www.riverbed.com
#       Omnipeek Network Analyzer   	Captura e análise Wi-Fi em tempo real
https://www.liveaction.com
#       CommView for Wi-Fi          	Captura de pacotes e análise detalhada
https://www.tamos.com 


# Conclusão
#   Este laboratório demonstrou como:
#       Capturar e analisar pacotes wireless com Wireshark;
#       Usar filtros eficazes para detectar:
#           SSIDs
#           Algoritmos de criptografia
#           Handshakes WPA2
#       Entender a estrutura do protocolo 802.11
#   Esse tipo de análise é essencial para qualquer pentester que deseja:
#     Planejar ataques a redes Wi-Fi
#     Crackear WPA2
#     Detectar falhas e APs vulneráveis



###############
# MOD 16 - Lab 2: Perform wireless attacks
###############

########
# TASK 1: Crack a WPA2 network using Aircrack-ng
########


# Objetivo
#   Simular ataques contra redes Wi-Fi com foco na quebra de criptografia WPA2-PSK
#   Utilizar Aircrack-ng e análise de captura .cap.

# Ferramentas Utilizadas
#   Aircrack-ng	                                Suite para análise e quebra de criptografia em redes Wi-Fi
#   Parrot Security OS	                        Distribuição Linux para testes de penetração
#   Adaptador Wireless (simulado via .cap)	    Requisito para capturar tráfego Wi-Fi
#   WPA2crack-01.cap	                        Arquivo de captura de handshake WPA2
#   password.txt	                            Wordlist de senhas utilizadas no ataque por dicionário

# Preparação do Ambiente
#   Trocar para a máquina Parrot Security
#   Login:
#       Usuário: attacker
#       Senha: toor

# Copiar pastas de captura e wordlist
#   Acesse: Places > Desktop
#   Copie as pastas:
#       Sample Captures
#       Wordlist
#   Use:
Ctrl+C (copiar) → Navegar até Desktop → Ctrl+V (colar)

# Acesso Root
#   Abra um terminal e execute:
sudo su
#       Senha: toor
#   Isso garante permissões administrativas, necessárias para ferramentas como aircrack-ng.

# Comando Principal do Ataque com Aircrack-ng
aircrack-ng -a2 -b 22:7F:AC:6D:E6:8B -w /home/attacker/Desktop/Wordlist/password.txt "/home/attacker/Desktop/Sample Captures/WPA2crack-01.cap"
#   Explicando o Comando
#       aircrack-ng	Ferramenta principal para quebra de chaves WEP/WPA/WPA2
#       -a2	Define o modo de ataque: 2 = WPA/WPA2 (handshake)
#       -b	Define o BSSID (MAC) do roteador alvo
#       -w	Caminho para o arquivo de wordlist (dicionário de senhas)
#       "arquivo.cap"	Arquivo de captura contendo o handshake WPA2

# Exemplo com Variáveis
BSSID="22:7F:AC:6D:E6:8B"
WORDLIST="/home/attacker/Desktop/Wordlist/password.txt"
CAPTURE="/home/attacker/Desktop/Sample Captures/WPA2crack-01.cap"
aircrack-ng -a2 -b "$BSSID" -w "$WORDLIST" "$CAPTURE"

# Saída Esperada
#   A ferramenta localiza um WPA Handshake válido no arquivo .cap.
#   Realiza comparação com a wordlist até encontrar a chave correta.
#   Exibe:
KEY FOUND! [ 12345678 ]
#   Observação: Se a senha não estiver na wordlist, o ataque falha. Por isso, ataques reais usam dicionários extensos ou técnicas de brute-force com hashcat.

# Conceitos Técnicos Relevantes
#   WPA2-PSK (Personal)
#       Modo pessoal, com senha pré-compartilhada (Pre-Shared Key).
#       Usa criptografia:
#           CCMP (AES) para confidencialidade.
#           EAPOL handshake para autenticação.
#   Captura do Handshake WPA2
#       Para que o Aircrack-ng funcione, é necessário um arquivo .cap contendo o handshake de 4 vias:
#       Capturado quando um dispositivo se conecta a um AP.

# Ataques Suportados pela Suite Aircrack-ng
#   WPA/WPA2 cracking	        Descobrir chave PSK
#   Fake authentication	        Enganar AP e se registrar
#   Deauth attack	            Forçar clientes a se reconectarem (e capturar handshake)
#   MAC spoofing	            Bypassar filtros de MAC
#   ARP replay	                Injetar pacotes ARP em WEP para acelerar coleta
#   Fragmentation attack	    Obter PRGA em WEP para reconstruir tráfego

# Outros Tipos de Ataques Wireless (explicados no lab)
#   Fragmentation	            Extrai bytes do PRGA (WEP)
#   MAC Spoofing	            Falsifica o MAC para se passar por cliente autorizado
#   Deauthentication	        Desconecta usuários com pacotes forjados
#   Disassociation	            Similar ao deauth, mas usando outro tipo de frame
#   Man-in-the-Middle (MitM)	Intercepta e modifica dados entre cliente e AP
#   ARP Poisoning	            Associa o MAC do atacante ao IP do gateway
#   Evil Twin	                Cria AP falso com mesmo SSID
#   Wi-Jacking	                Sequestra conexões wireless já estabelecidas
#   Rogue AP	                APs não autorizados na rede

# Ferramentas Alternativas ao Aircrack-ng
#   Hashcat	                            hashcat.net	Ataques mais avançados a hashes WPA2 com GPU
https://hashcat.net
#   Portable Penetrator	secpoint.com	Suite gráfica de pentest wireless
https://www.secpoint.com
#   WepCrackGui	                        SourceForge	Interface para ataque WEP/WPA
https://sourceforge.net

# Conclusão e Próximos Passos
#   Este laboratório demonstrou a efetividade de um ataque por dicionário contra WPA2-PSK.
#   Mostrou como o handshake pode ser analisado e quebrado.
#   Em ambiente real, a combinação com ferramentas como airmon-ng, airodump-ng e aireplay-ng permite:
#   Capturar handshakes ao vivo;
#   Forçar desconexões com --deauth;
#   Obter acesso completo à rede alvo.