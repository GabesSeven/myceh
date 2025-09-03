#!/bin/bash



###############
# MOD 8 - Lab 1: Perform Active Sniffing
###############

########
# TASK 1: Perform MAC Flooding using macof
########

# Objetivo
#   Realizar MAC Flooding com a ferramenta macof para:
#       Simular ataque contra uma switch (preenchendo a tabela CAM),
#       Provocar comportamento de hub,
#       Permitir a captura de tráfego de outros hosts na rede (sniffing).
#   Ferramentas envolvidas:
#       macof (do pacote dsniff)
#       wireshark (para visualização dos pacotes)
#       Distribuição: Parrot Security OS

# O que é MAC Flooding?
#   A MAC flooding sobrecarrega a tabela CAM da switch, que armazena mapeamentos IP ↔ MAC.
#   Quando essa tabela enche, a switch começa a reenviar pacotes para todas as portas, como um hub.
#   Isso permite que o atacante veja tráfego de outras máquinas da rede local.

# Acessar a máquina Parrot Security
#   Clique em Parrot Security
#   Login:
#       Usuário: attacker
#       Senha: toor
# Ignorar Pop-ups de atualização
#   Feche qualquer janela perguntando para atualizar o sistema.
# Abrir o Wireshark para captura de pacotes
#   Ação:
#       Clique em: Applications > Pentesting > Information Gathering > Wireshark
#       Ao abrir, insira a senha de root: toor
#   Selecione a interface principal (ex: eth0) e clique em Start para iniciar a captura.
# Abrir terminal e obter privilégios de root
#   Ação:
sudo su
# Senha: toor
#   Agora você está como root, necessário para executar o macof.
# Ir para o diretório root (opcional)
#   Ação:
cd /
# Executar o ataque de MAC Flooding
#   Exemplo de ataque geral:
macof -i eth0 -n 10
#   Explicação dos parâmetros:
#       -i eth0	Interface de rede a ser usada (pode variar: eth0, ens33, etc.)
#       -n 10	Número de pacotes a serem enviados (pode omitir para flood indefinido)
#   Esse comando envia 10 pacotes com IPs/MACs aleatórios, simulando tráfego malicioso.
#   Exemplo para atacar um alvo específico:
macof -i eth0 -d 192.168.0.105
#       -d	Define o IP de destino para o ataque
# Observar pacotes no Wireshark
#   Ação:
#       Volte à janela do Wireshark
#       Observe os IPv4 packets com endereços de origem aleatórios
#       Clique em um pacote → Expanda Ethernet II → Verifique os endereços MAC falsificados
# (Opcional) Verificar captura em outra máquina
#   Se houver outra máquina na mesma rede (e o switch estiver vulnerável), ela também verá os pacotes.
# Encerrar a captura no Wireshark
#   Ação:
#       Clique em Stop
#       Feche o Wireshark
#       Se perguntar sobre salvar, clique em Quit without Saving
#   Encerrar sessão
#       Feche todas as janelas abertas
#       Documente as observações (para relatório técnico)

# Resumo das Ações e Comandos Utilizados
#   Login no Parrot Security	                    Acesso à máquina do atacante
#   Fechar pop-ups	                                Garantir foco no experimento
#   Iniciar Wireshark pela interface gráfica	    Capturar tráfego para análise
#   sudo su	                                        Obter root
#   cd / (opcional)	                                Mover para raiz do sistema
#   macof -i eth0 -n 10	                            Enviar 10 pacotes com MAC/IP aleatórios
#   macof -i eth0 -d [IP]	                        Enviar pacotes para alvo específico
#   Analisar pacotes no Wireshark	                Confirmar comportamento da switch
#   Encerrar Wireshark	                            Finalizar análise

# Observações Técnicas Importantes
#   CAM Table = Content Addressable Memory (armazenamento de MACs por porta)
#   Ao encher a CAM Table, a switch reenvia pacotes para todas as portas
#   MAC Flooding pode ser detectado por:
#       IDS/IPS (ex: Snort)
#       Switches com port security (limite de MACs por porta)
#       Ferramentas como Wireshark, tcpdump, etc.

# Contra-medidas (defesa)
#   Port Security	    Limitar o número de MACs por porta
#   802.1X	            Autenticação por porta
#   SNMP Monitoring	    Monitorar alterações rápidas na tabela MAC
#   IDS/IPS	            Detectar comportamentos anômalos


########
# TASK 2: Perform a DHCP Starvation Attack using Yersinia
########

# Objetivo:
#   Realizar um ataque de DHCP Starvation com a ferramenta Yersinia para:
#   Exaurir o pool de endereços IP do servidor DHCP;
#   Impedir que dispositivos legítimos obtenham IPs;
#   Criar um cenário de negação de serviço (DoS) na rede local.

# O que é DHCP Starvation?
#   Um ataque de exaustão DHCP visa:
#       Enviar múltiplas requisições DHCP com MACs falsos;
#       Consumir todos os IPs disponíveis no servidor DHCP;
#       Impedir que usuários reais se conectem à rede;
#       Possibilitar Rogue DHCP (criar servidor falso depois da exaustão).
#   Ferramenta usada: Yersinia
#   Sistema: Parrot Security OS


# Abrir o Wireshark e iniciar a captura
#   Ação via interface gráfica:
Applications > Pentesting > Information Gathering > Wireshark
#       Interface: selecione eth0 ou outra conectada à rede.
#       Clique em Start para iniciar a captura de pacotes.
#   Ao abrir, forneça a senha root: toor
# Abrir Terminal com privilégios de root
#   Ação:
sudo su
#       Senha: toor
#   Navegar para o diretório raiz (opcional):
cd /
# Maximizar a janela do terminal
#   Necessário para rodar o modo interativo do Yersinia corretamente.
# Executar o Yersinia em modo interativo
#   Comando:
yersinia -I
#       -I	Modo interativo (Interface baseada em terminal, curses)
# Navegação dentro do Yersinia (Modo Interativo)
#   Navegação com atalhos de teclado:
#       Qualquer tecla	Fecha o pop-up inicial
#           h	Ajuda (Help)
#           q	Sai do menu atual ou encerra
#           F2	Muda para o modo DHCP
#           x	Abre o painel de ataques
#           1	Inicia o ataque de DHCP Starvation
#           q (depois do ataque)	Finaliza e sai do Yersinia
# Início do Ataque: DHCP Starvation
#   Ação:
#       [F2]  --> mudar para DHCP  
#       [x]   --> abrir painel de ataque  
#       [1]   --> iniciar ataque DHCP Starvation
#   O Yersinia começa a enviar requisições DHCP com MACs falsificados, consumindo o pool de IPs do servidor.
# Finalização do ataque
#   Ação:
#       [q]   --> encerra o ataque e fecha o Yersinia
# Verificação dos pacotes no Wireshark
#   Ação:
#       Observe o grande volume de pacotes DHCP Discover / Request.
#       Clique em um pacote → Expanda Ethernet II → Observe:
#       MAC de origem: aleatória
#       MAC de destino: broadcast ou do servidor DHCP
# Encerrar a captura no Wireshark
#   Ação:
#       Clique em Stop
#       Feche o Wireshark
#       Se for perguntado sobre salvar, escolha Quit without Saving
# Encerrar a sessão e documentar
#   Feche todas as janelas abertas
# Documente:
#   Comandos usados
#       Capturas de tela
#       Comportamento da rede
#       IPs/MACs gerados
#       Impacto no servidor DHCP

# Resumo das Ações e Comandos
#   Abertura do Wireshark	    Captura de pacotes na interface eth0
#   sudo su	                    Tornar-se root
#   cd /	                    Ir para diretório raiz (opcional)
#   yersinia -I	                Iniciar modo interativo do Yersinia
#   [F2]	                    Selecionar protocolo DHCP
#   [x] → [1]	                Iniciar ataque de DHCP starvation
#   [q]	                        Encerrar ataque e sair do Yersinia
#   Ver Wireshark	            Analisar pacotes DHCP falsificados
#   Stop Wireshark	            Finalizar a análise de pacotes

# Explicações Técnicas Adicionais
#   O que o Yersinia faz neste ataque?
#       Gera múltiplas requisições DHCP usando diferentes MACs;
#       Força o servidor DHCP a atribuir todos os IPs do seu pool;
#       Depois que o pool acaba, nenhum cliente novo consegue IP;
#       Pode ser seguido por um ataque de DHCP Rogue (criação de servidor DHCP falso para redirecionar o tráfego da rede).

# Defesas contra DHCP Starvation
#   Port Security	            Limita número de MACs por porta
#   DHCP Snooping	            Bloqueia pacotes DHCP de hosts não autorizados
#   Rate Limiting	            Limita o número de pacotes por segundo na switch
#   Monitoramento de DHCP	    Detecção por IDS/IPS como Snort, Suricata, etc.
#   Autenticação 802.1X	        Requer autenticação antes de liberar acesso à rede


###############
# MOD 8 - Lab 2: Perform Network Sniffing using Various Sniffing Tools
###############


########
# TASK 1: Perform Password Sniffing using Wireshark
########

# Objetivo:
#   Realizar sniffing de senha via tráfego HTTP usando Wireshark.
#   Capturar tráfego entre duas máquinas (cliente e servidor).
#   Realizar captura remota de pacotes através do serviço RPCAP.
#   Explorar o tráfego HTTP com método POST, analisando credenciais expostas.

# Ferramentas e Ambiente
#   Windows Server	    10.10.1.19	            Administrator	    Pa$$w0rd
#   Windows 11	        10.10.1.11	            Admin / Jason	    Pa$$w0rd / qwerty
#   Navegadores	        Mozilla Firefox		
#   Sniffer	            Wireshark		
#   Serviço remoto	    Remote Packet Capture Protocol v.0 (RPCAP)		

# Captura Local de Senha (HTTP POST)
#   Login na máquina Server (10.10.1.19)
#     Usuário: Administrator
#     Senha: Pa$$w0rd
#   Iniciar o Wireshark
#     Abertura via Menu Iniciar (interface gráfica): Wireshark → Executar como Administrador
#   Iniciar captura na interface principal
#     Ex: Ethernet 2
#     Clique no ícone de tubarão azul para iniciar.
#   Na máquina Windows 11 (10.10.1.11)
#     Login: Admin / Senha: Pa$$w0rd
#     Acessar: http://www.moviescope.com
#     Login no site:
#         Usuário: sam
#         Senha: test
#   Parar captura no Server (Wireshark)
#     Clique no botão vermelho de Stop (□)
#   Salvar captura
#     Menu → File → Save As...
#     Nome: Password Sniffing
#   Aplicar filtro para POST
http.request.method == POST
#   Procurar campo de senha (pwd)
#     Menu → Edit → Find Packet
#         Escolher: Display filter
#         String: pwd
#         Formato: UTF-8 / ASCII (Narrow)
#         Em: Packet details
#         Clicar: Find
#   Expandir os campos do pacote
#     Procurar:
#         HTML Form URL Encoded
#         Ver: username=sam&password=test
#     Aqui se realiza o sniffing da senha.

# Captura Remota via RPCAP
#   Login remoto na máquina alvo (Windows 11)
#       A partir do Windows Server, abra:
#           Menu → Remote Desktop Connection
#           IP: 10.10.1.11
#           Usuário: Jason
#           Senha: qwerty
#   Iniciar serviço de captura remota
#       Control Panel → System and Security → Windows Tools → Services
#       Serviço: Remote Packet Capture Protocol v.0 (experimental)
#           Clique com direito → Start
#   Voltar ao Server e abrir o Wireshark
#   Adicionar interface remota
#       Toolbar → Capture Options → Manage Interfaces
#           Aba: Remote Interfaces
#           Clique no "+" (adicionar host remoto)
#           IP: 10.10.1.11
#           Porta: 2002
#           Autenticação: Jason / qwerty
#   Iniciar captura na nova interface remota
#       Clique em Start após selecioná-la.
#   Na máquina Windows 11 (Jason)
#       Login: Jason / Senha: qwerty
#       Acesse: http://www.goodshopping.com
#       Navegação normal (simulação do tráfego real de usuário)
#   Finalizar captura remota
#       Voltar ao Server → Wireshark
#       Clique em Stop

# Resumo de Comandos, Ações e Etapas Técnicas
#   Login	Administrator / Pa$$w0rd no Server
#   Abrir Wireshark	Iniciar ferramenta gráfica
#   Capturar tráfego	Interface Ethernet 2
#   Login Web	sam / test no site
#   Parar captura	Botão vermelho
#   Salvar captura	File → Save As...
#   Filtro POST	http.request.method == POST
#   Buscar senha	Edit → Find → pwd
#   Inspecionar pacotes	application/x-www-form-urlencoded
#   RDP	Remote Desktop → Jason / qwerty
#   Ativar RPCAP	Iniciar serviço na máquina alvo
#   Adicionar interface remota	IP: 10.10.1.11, Porta: 2002, Auth
#   Captura remota	Começa sniffing remoto
#   Navegação vítima	Navegar site HTTP como Jason
#   Encerrar	Parar captura e analisar

# Ofensivamente (Red Team)
#   Ferramentas sniffers como Wireshark e serviços como RPCAP podem ser usados:
#   Para capturar credenciais em tráfego HTTP sem criptografia
#   Realizar RDP + RPCAP para controlar interfaces remotamente
#   Observar dados sensíveis: cookies, tokens, URLs, headers

# Defensivamente (Blue Team)
#   HTTPS	                                Obrigar uso de TLS para evitar senhas em texto plano
#   Firewall	                            Bloquear porta 2002 (RPCAP) caso não seja usada
#   Desabilitar serviços desnecessários	    Como Remote Packet Capture Protocol
#   Monitoramento	                        Log de conexões RDP e acessos Wireshark
#   IDS/IPS	                                Detectar acessos suspeitos, pacotes POST, sniffers

# Conclusão e Recomendações
#   O tráfego HTTP é extremamente vulnerável e pode ser explorado facilmente.
#   Ferramentas como o Wireshark facilitam tanto admins quanto atacantes.
#   Devemos sempre forçar o uso de HTTPS e aplicar políticas de rede seguras (ACL, VLANs, NAC, etc.).
#   RPCAP deve ser usado com cautela e em redes confiáveis.


###############
# MOD 8 - Lab 3: Detect Network Sniffing
###############

########
# TASK 1: Detect ARP Poisoning and Promiscuous Mode in a Switch-Based Network
########

# Objetivo:
#   Detectar ARP Poisoning e modo promíscuo em uma rede baseada em switch.

# Resumo dos Componentes Usados:
#   Máquina	Sistema Operacional	Função no Lab
#   Windows Server 2019	Windows Server	Atacante (ARP Poisoning + Sniffer)
#   Windows 11	Windows 11	Vítima + Detecção de Promiscuous
#   Parrot Security	Linux (Parrot)	Gerador de tráfego de rede
#   Ubuntu	Ubuntu	Detecção de modo promíscuo com Nmap

# Ativando Sniffer com Cain & Abel (Windows Server 2019)
#   Objetivo: Configurar o modo de escuta da rede e executar ARP Poisoning.
#   Ações realizadas:
#       Abrir o Cain & Abel.
#       Ir em Configure → Sniffer tab → Selecionar Adapter correto.
#       Iniciar sniffer:
#           Ícone Start/Stop Sniffer (🟢)
#       Escanear MACs:
#           Clicar no ícone + ou botão direito → Scan MAC Addresses.
#           Marcar:
#               All hosts in my subnet
#               All Tests
#       ARP Poisoning:
#           Clicar na aba APR.
#           Selecionar IP origem: 10.10.1.11 (Windows 11)
#           Selecionar IP destino: 10.10.1.13 (Parrot)
#           Clicar no ícone + → OK
#           Clicar no botão Start/Stop APR (⚡) para iniciar o envenenamento.

# Gerar Tráfego (Parrot Security)
#   Objetivo: Criar tráfego entre as máquinas para capturar pacotes manipulados.
#   Comandos no terminal:
sudo su
cd /
hping3 10.10.1.11 -c 100000
#       -c 100000 = número de pacotes a serem enviados.

# Capturar e Detectar ARP Poisoning no Wireshark (Windows Server 2019)
#   Ações realizadas:
#       Abrir o Wireshark.
#   Ir em:
#   Edit → Preferences → Protocols → ARP/RARP
#   Marcar:
#       Detect ARP request storms
#       Detect duplicate IP address configuration
#   Iniciar captura de pacotes:
#       Selecionar adaptador → Start
#   Após alguns segundos → Parar captura:
#       Ícone Stop Capture (🔴)
#   Ir em:
#       Analyze → Expert Information
#       Expandir: 
#           Warnings → Duplicate IP address configured
#       Selecionar pacotes listados para ver detalhes no frame ARP.
#   Indício:
#       Duplicate IP Address (10.10.1.11) com diferentes MACs ➜ Ataque ARP detectado.

# Detectar Modo Promíscuo com Nmap (Ubuntu)
#   Comandos no terminal:
sudo su
nmap --script=sniffer-detect 10.10.1.19
#   Resultado Esperado:
Host script results:
| sniffer-detect:
|   Likely in promiscuous mode
#       Isso indica que a máquina está em modo promíscuo, capturando todo o tráfego.

# Resumo Final dos Principais Comandos e Ações
#   Cain & Abel	                            Sniffer, escaneamento de MACs, ARP Poisoning
#   Wireshark → Preferences → ARP	        Ativação de alertas sobre pacotes ARP suspeitos
#   Wireshark → Analyze → Expert Info	    Verificar alertas de IP duplicado indicando spoofing
#   hping3 <IP> -c 100000	                Gerar tráfego entre Parrot e Windows 11
#   nmap --script=sniffer-detect <IP>	    Detectar se interface de rede está em modo promíscuo

# Conclusão do Lab:
#   Esse laboratório demonstrou técnicas ofensivas e defensivas sobre sniffing de rede, com foco em:
#       Como detectar sniffers escondidos por meio de modo promíscuo.
#       Como capturar evidências de ARP poisoning via alertas no Wireshark.
#       Como gerar e analisar tráfego comprometido.
#       Uso ético de ferramentas como Cain & Abel, Wireshark, Nmap, e hping3.