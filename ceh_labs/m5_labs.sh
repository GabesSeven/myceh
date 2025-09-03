#!/bin/bash

# Define o alvo individual e o range de IPs
TARGET_IP="10.10.1.22"
TARGET_RANGE_1="10.10.1.10-23"
TARGET_RANGE_2="10.10.1.*"

###############
# MOD 5 - Lab 1: Perform Vulnerability Research with Vulnerability Scoring Systems and Databases
###############

# Acesso ao site oficial do CWE:
https://cwe.mitre.org

# Pesquisa de vulnerabilidades por serviço (por exemplo, SMB)
#   Usar a barra de pesquisa (Google Custom Search) dentro do site do CWE.
#   Digitar “SMB” e buscar fraquezas relacionadas ao protocolo.

# Análise de uma vulnerabilidade específica
#   Clicar em uma das entradas da pesquisa (ex: CWE-284 – Improper Access Control).
#   Página com descrição completa da vulnerabilidade, suas causas e exemplos.

# Acesso à lista oficial do CWE
#   Navegar até a aba “CWE List”.
#   Escolher a opção “CWE Top 25 (2023)” em “External Mappings”.

# Estudo das 25 vulnerabilidades mais perigosas (CWE Top 25)
#   Exemplo de vulnerabilidades incluídas
#       CWE-79: Improper Neutralization of Input During Web Page Generation (‘Cross-site Scripting’)
#       CWE-89: SQL Injection
#       CWE-787: Out-of-bounds Write
#       CWE-20: Improper Input Validation

# Objetivo do Pentester com Isso
#   Analisar as fraquezas na lista CWE Top 25 e correlacionar com serviços identificados em outras fases (ex: SMB, LDAP, FTP, etc.).
#   Compreender possíveis vetores de ataque e preparar futuras etapas do pentest.


###############
# MOD 5 - Lab 2: Perform Vulnerability Assessment using Various Vulnerability Assessment Tools
###############

# Iniciar o container do OpenVAS via Docker
docker run -d -p 443:443 --name openvas mikesplain/openvas

# Acessar interface web do OpenVAS
#   Abrir Firefox
#   Ir para: https://127.0.0.1
#   Login: admin / admin
#   Se aparecer tela de aviso de segurança (certificado), clicar em “Avançado” → “Aceitar o risco e continuar”

# Criar novo scan:
#   Menu → Scans → Tasks
#   Clicar no ícone de varinha mágica (Task Wizard)
#   Inserir IP de destino: 10.10.1.22
#   Clicar em “Start Scan”

# Aguardar finalização:
#   Status muda de “Requested” para “Done”
#   Clicar em “Done” para visualizar relatório

# Ações dentro do OpenVAS
#   Verificar vulnerabilidades
#       Visualizar cada item listado
#       Checar: severidade, porta, descrição e CVE

# Habilitar Firewall na máquina-alvo
# Sistema Alvo: Windows Server 2022 (IP: 10.10.1.22)
#   Acessar com:
#       Usuário: CEH\Administrator
#       Senha: Pa$$w0rd
#   Navegar até o firewall:
#       Control Panel → System and Security → Windows Defender Firewall → Turn Windows Defender Firewall on or off
#       Ativar o firewall → OK

# Novo Scan com Firewall Ativado
#   Voltar à máquina Parrot Security
#       Criar novo scan (mesmo processo do anterior):
#       Scans → Tasks → Task Wizard
#       Inserir IP: 10.10.1.22
#       Clicar em “Start Scan”
#   Aguardar término e analisar os resultados
#       Concluir que, mesmo com o firewall ativo, o scanner ainda encontrou vulnerabilidades.
#       Isso demonstra que firewalls não substituem políticas de segurança, atualizações e hardening de serviços.

# Encerramento
#   Voltar para o Windows Server 2022:
#       Desativar firewall no mesmo caminho:
#           Control Panel → System and Security → Windows Defender Firewall → Turn Windows Defender Firewall on or off
#           Marcar “Desativar” → OK


###############
# MOD 5 - Lab 3: Perform Vulnerability Analysis using AI
###############

sudo su # Entrar como root	
bash sgpt.sh # Executar script de configuração do ShellGPT com chave de ativação

# Realizar varredura com Nikto em um site
sgpt --chat nikto --shell "Scan the URL https://www.certifiedhacker.com to identify potential vulnerabilities with nikto"

# Encerrar scan Nikto (opcional). Pressionar: 
Ctrl + Z

# Realizar varredura com Nmap para descobrir vulnerabilidades no site
sgpt --chat vuln --shell "Perform vulnerability scan on target url http://www.moviescope.com with Nmap"

# Realizar varredura com Skipfish
sgpt --chat vuln --shell "Perform a vulnerability scan on target url http://testphp.vulnweb.com with skipfish"

# Acessar relatório HTML gerado pelo Skipfish
#   Navegar até "/tmp/skipfish_scan_output/"
#   Abrir "index.html" com Firefox ESR