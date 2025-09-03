#!/bin/bash

###############
# MOD 2 - Lab 1: Perform Footprinting Through Search Engines
###############

cache:www.eccouncil.org # cache: versão em cache da página
allinurl:EC-Council career # allinurl: todos os termos no URL
inurl:copy site:www.eccouncil.org # inurl: termo específico no URL
allintitle:detect malware # allintitle: todos os termos no título
Anti-virus inanchor:Norton # inanchor: termo específico em links apontando para a página
allinanchor:best cloud service provider # allinanchor: todos os termos em links apontando para a página
link:www.eccouncil.org # link: páginas que contêm links para o site
related:www.eccouncil.org # related: sites semelhantes ao especificado
info:eccouncil.org # info: informações sobre o site
location:EC-Council # location: resultados baseados em localização


###############
# MOD 2 - Lab 2: Perform Footprinting Through Internet Research Services
###############

# NETCRAFT (https://www.netcraft.com)
# 1 Acesse: https://www.netcraft.com
# 2. Vá até: Menu > Resources > Research Tools
# 3. Clique em: Site Report
# 4. Digite o domínio: certifiedhacker.com
# 5. Clique em 'LOOK UP'
# 6. Analise as seções: Background, Network, Hosting History
# 7. Clique no link do domínio em 'Network' para ver subdomínios

# DNSDUMPSTER (https://dnsdumpster.com)
# 1. Acesse: https://dnsdumpster.com
# 2. Digite: certifiedhacker.com e clique em 'Search'
# 3. Verifique:
#   - GEOIP dos hosts
#   - Servidores DNS e MX
#   - Host Records (A)
#   - Mapa visual da infraestrutura
# 4. Clique em 'Download .xlsx of Hosts' para baixar a lista de hosts

# Pentest-Tools (https://pentest-tools.com)
# 1. Acesse: https://pentest-tools.com
# 2. Vá até: Information Gathering > Find Subdomains
# 3. Digite o domínio: certifiedhacker.com e aguarde os resultados

# Ferramentas alternativas
https://pentest-tools.com # Pentest-Tools Find Subdomains


###############
# MOD 2 - Lab 3: Perform Footprinting Through Social Networking Sites
###############

# Trocar para usuário root
sudo su

# Buscar perfis do alvo "Elon Musk" em redes sociais com Sherlock
sherlock "Elon Musk"

# Ferramentas alternativas
https://www.social-searcher.com # Social Searcher


###############
# MOD 2 - Lab 4: Perform Whois Footprinting
###############

# Acessar o site da ferramenta Whois
https://whois.domaintools.com

# No campo de busca, digitar o domínio-alvo:
www.certifiedhacker.com

# Anotar as informações obtidas, como:
#   - Nome do registrante
#   - Organização
#   - E-mail e telefone (se disponíveis)
#   - IP associado
#   - Name Servers (DNS)
#   - Localização
#   - Datas de criação e expiração

# Ferramentas alternativas
https://www.tamos.com # SmartWhois
http://www.sabsoft.com # Batch IP Converter


###############
# MOD 2 - Lab 5: Perform DNS Footprinting
###############

# Consulta o endereço IPv4 (registro A) do domínio www.certifiedhacker.com
nslookup -type=A www.certifiedhacker.com

# Consulta o registro CNAME do domínio certifiedhacker.com (canonical name)
nslookup -type=CNAME certifiedhacker.com

# Consulta o endereço IPv4 do servidor de nome ns1.bluehost.com
nslookup -type=A ns1.bluehost.com

# Consulta os registros MX (mail servers) do domínio certifiedhacker.com
nslookup -type=MX certifiedhacker.com

# Consulta os registros NS (name servers) do domínio certifiedhacker.com
nslookup -type=NS certifiedhacker.com

# Mesmo processos anteriores 
nslookup
set type=a
www.certifiedhacker.com
set type=cname
certifiedhacker.com
set type=a
ns1.bluehost.com

# Ferramentas alternativas
http://www.kloth.net/services/nslookup.php # NSLOOKUP Web Tool
https://dnsdumpster.com # DNSdumpster


###############
# MOD 2 - Lab 6: Perform Network Footprinting
###############

# Traceroute padrão para verificar os saltos até o domínio alvo
traceroute www.certifiedhacker.com

# Para Windows, os comandos equivalentes são:
# tracert www.certifiedhacker.com     # Traceroute padrão no Windows
# tracert /?                         # Exibe as opções do comando tracert no Windows
# tracert -h 5 www.certifiedhacker.com  # Limita o traceroute a 5 saltos no Windows

# Ferramentas alternativas
https://www.pingplotter.com/ # PingPlotter
https://www.solarwinds.com/traceroute-ng # Traceroute NG


###############
# MOD 2 - Lab 7: Perform Email Footprinting
###############

# 1. Navegar até a pasta da ferramenta eMailTrackerPro
cd "E:/CEH-Tools/CEHv13 Module 02 Footprinting and Reconnaissance/Email Tracking Tools/eMailTrackerPro"
# 2. Executar o programa eMailTrackerPro
./emt.exe
#   - Se o Controle de Conta de Usuário aparecer, aceitar manualmente
# 3. Instalar o programa (se necessário)
#   - Seguir as etapas do assistente com opções padrão
#   - Após a instalação, desmarcar "Show Readme" e clicar em Finish para abrir o programa
# 4. Navegar na interface:
#   - Clicar em "My Trace Reports"
#   - Clicar em "Trace Headers"
# 5. Obter cabeçalho de e-mail:
#   - No navegador, abrir o e-mail alvo (Gmail ou Outlook)
#   - No Gmail: clicar em "Mais" > "Mostrar original" > copiar cabeçalho
#   - No Outlook: abrir e-mail em nova janela > "Mais ações" > "Exibir fonte da mensagem" > copiar cabeçalho
# 6. Colar o cabeçalho no campo "Email headers" do eMailTrackerPro
# 7. Clicar em "Trace" para iniciar a análise

# Ferramentas alternativas
https://mxtoolbox.com/ # MxToolbox
https://socialcatfish.com/ # Social Catfish
https://www.ip2location.com/ # IP2Location Email Header Tracer


###############
# MOD 2 - Lab 8: Perform Footprinting using Various Footprinting Tools
###############

sudo su # 1. Tornar-se root para executar os comandos
cd / # 2. Ir para o diretório root
recon-ng # 3. Executar o Recon-ng
help # 4. Listar comandos disponíveis
marketplace install all # 5. Instalar todos os módulos disponíveis (ignorar erros)
modules search # 6. Listar módulos disponíveis
workspaces # 7. Visualizar comandos de workspace
workspaces create CEH # 8. Criar um workspace chamado CEH para organizar a análise
workspaces list # 9. Listar workspaces existentes para confirmar
db insert domains # 10. Inserir o domínio alvo para footprinting
# 11. Mostrar domínios inseridos para confirmar # (aqui digitar "certifiedhacker.com" quando solicitado e Enter para notas)
show domains
modules load brute # 12. Buscar módulos de brute forcing hosts
modules load recon/domains-hosts/brute_hosts # 13. Carregar módulo brute_hosts para coletar hosts
run # 14. Executar a coleta de hosts
back # 15. Voltar para o terminal do workspace
modules load recon/domains-hosts/bing_domain_web # 16. Carregar módulo Bing para coleta adicional de hosts
run # 17. Executar o módulo Bing
modules load reverse_resolve # 18. Buscar módulos para reverse lookup
modules load recon/hosts-hosts/reverse_resolve # 19. Carregar módulo reverse_resolve para resolver IPs para hostnames
run # 20. Executar o reverse lookup
show hosts # 21. Mostrar hosts coletados até agora
back # 22. Voltar para o terminal do workspace
modules load reporting # 23. Listar módulos de relatório disponíveis
modules load reporting/html # 24. Carregar módulo para gerar relatório em HTML
options set FILENAME /home/attacker/Desktop/results.html # 25. Configurar nome do arquivo para salvar o relatório
options set CREATOR Jason # 26. Configurar o criador do relatório (exemplo: Jason)
options set CUSTOMER Certifiedhacker Networks # 27. Configurar o cliente (domínio alvo)
run # 28. Executar geração do relatório HTML
workspaces create reconnaissance # 29. Criar outro workspace para coleta de contatos
modules load recon/domains-contacts/whois_pocs # 30. Carregar módulo para coleta de contatos via Whois POCs
options set SOURCE facebook.com # 31. Definir domínio alvo para coleta de contatos (exemplo facebook.com)
run # 32. Executar coleta de contatos
modules load recon/domains-hosts/hackertarget # 33. Carregar módulo para coleta de subdomínios e IPs via hackertarget
options set SOURCE certifiedhacker.com # 34. Definir domínio alvo para coleta de subdomínios
run # 35. Executar coleta de subdomínios/IPs


###############
# MOD 2 - Lab 9: Perform Footprinting using AI
###############

sudo su # 1. Tornar-se root para permissões administrativas
# (Digite a senha toor quando solicitado)
bash sgpt.sh # 2. Configurar ShellGPT (primeira vez, para ativar a chave AI)
sgpt --chat footprint --shell "Use theHarvester to gather email accounts associated with 'microsoft.com', limiting results to 200, and leveraging 'baidu' as a data source" # 3. Usar ShellGPT para coletar emails com theHarvester (limite 200, fonte Baidu)
# Na prompt, digite E e pressione Enter para executar
sgpt --chat footprint --shell "Use Sherlock to gather personal information about 'Sundar Pichai' and save the result in recon2.txt" # 4. Usar ShellGPT para coletar informações pessoais via Sherlock (salvar em arquivo)
# Digite E para executar
ls # 5. Listar arquivos no diretório atual (verificar recon2.txt criado)
pluma recon2.txt # 6. Visualizar o conteúdo do arquivo criado
sgpt --chat footprint --shell "Install and use DNSRecon to perform DNS enumeration on the target domain www.certifiedhacker.com" # 7. Usar ShellGPT para realizar enumeração DNS com DNSRecon
# Digite E para executar
sgpt --chat footprint --shell "Perform network tracerouting to discover the routers on the path to a target host www.certifiedhacker.com" # 8. Usar ShellGPT para realizar traceroute no domínio alvo
# Digite E para executar
sgpt --chat footprint --shell "Develop a Python script which will accept domain name microsoft.com as input and execute a series of website footprinting commands, including DNS lookups, WHOIS records retrieval, email enumeration, and more to gather information about the target domain" # 9. Usar ShellGPT para criar e executar um script Python automatizado para footprinting completo (DNS, WHOIS, emails etc)
# Digite E para executar
