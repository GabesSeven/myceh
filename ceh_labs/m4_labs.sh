#!/bin/bash

# Define o alvo individual e o range de IPs
TARGET_IP="10.10.1.22"
TARGET_RANGE_1="10.10.1.10-23"
TARGET_RANGE_2="10.10.1.*"

###############
# MOD 4 - Lab 1: Perform NetBIOS Enumeration
###############

nbtstat -a 10.10.1.11 # Exibe a tabela de nomes NetBIOS de um computador remoto.
nbtstat -c # Mostra o cache de nomes NetBIOS e os IPs aos quais foram resolvidos.
net use # Lista conexões de rede (compartilhamentos SMB/CIFS).
net use \\10.10.1.11\c$ /user:Administrador Senha # Mostra recursos compartilhados conectados. Exibir se há mapeamento de drives em máquinas remotas. Tentar montar compartilhamentos.


###############
# MOD 4 - Lab 2: Perform SNMP Enumeration
###############

snmpwalk -v1 -c public 10.10.1.22 # Realiza enumeração SNMP utilizando a versão 1 do protocolo.
snmpwalk -v2c -c public 10.10.1.22 #  Realiza enumeração SNMP utilizando a versão 2c do protocolo.


###############
# MOD 4 - Lab 3: Perform LDAP Enumeration
###############

# Abrir o AD Explorer. 
#   Navegar até: "Z:\CEHv13 Module 04 Enumeration\LDAP Enumeration Tools\Active Directory Explorer\"
#   Executar: ADExplorer.exe
#   Aceitar o contrato de licença: Click em “Agree”

# Conectar-se ao Servidor de Diretório
#   Na janela “Connect to Active Directory”:
#   Inserir o IP do alvo: 10.10.1.22
#   Clicar em OK

# Navegar pela Estrutura LDAP
#   Expandir os nós: DC=CEH,DC=com → CN=Users
#   Visualizar os usuários disponíveis.
#   Ao clicar em um usuário no painel esquerdo, os atributos (propriedades) aparecem no painel direito.

# Modificar Atributos LDAP
#   Clicar com o botão direito sobre qualquer atributo (ex: displayName).
#   Selecionar: Modify…
#   Na janela de modificação:
#       Selecionar o valor atual.
#       Clicar em Modify… novamente.
#       Inserir novo valor no campo Value data.
#       Confirmar com OK.

# Tipos de Informações Coletadas via LDAP Enumeration
#   🧑 Nomes de usuários
#   🏢 Departamentos
#   🖥️ Servidores e estações registradas
#   📧 Emails e atributos pessoais
#   📂 Estrutura hierárquica do domínio
#   🔐 Possíveis senhas expostas ou campos mal configurados
#   🧾 Políticas de grupo e permissões

# Ferramenta Usada: AD Explorer
#   Desenvolvido pela Microsoft/Sysinternals.
#   Permite navegar, visualizar, buscar e modificar objetos no Active Directory.
#   Interface gráfica amigável.
#   Permite salvar conexões e exportar resultados.

# Ferramentas alternativas
ldapadministrator.com # Softerra LDAP Administrator	
ldapsoft.com # LDAP Admin Tool
ldap-account-manager.org # LDAP Account Manager
securityxploded.com # LDAP Search


###############
# MOD 4 - Lab 4: Perform NFS Enumeration
###############

# Habilitar o NFS no Windows Server 2019. Ações realizadas manualmente via interface gráfica (GUI):
#   Abrir o Server Manager
#   Clicar em Add roles and features
#   Avançar até a seção Server Roles
#   Marcar:
#       File and Storage Services → File and iSCSI Services → ✅ Server for NFS
#   Confirmar a instalação das features adicionais exigidas
#   Clicar em Install e depois em Close após a instalação


# Verificar se o NFS está disponível (porta 2049)
sudo su                    # Tornar-se root (senha: toor)
nmap -p 2049 10.10.1.19    # Verifica se a porta NFS está aberta

# Executar o SuperEnum
cd SuperEnum                        # Entrar no diretório da ferramenta
echo "10.10.1.19" >> Target.txt     # Criar o arquivo com IP alvo
chmod +x superenum                  # Dar permissão de execução (se necessário)
./superenum                         # Executar a ferramenta
# Quando solicitado, inserir: Target.txt
# Esperar 15–20 minutos para o término do scan
# Analisar a saída: portas abertas, serviços (incluindo NFS/2049)

# Executar o RPCScan
cd ..                             # Voltar um diretório
cd RPCScan                        # Acessar a pasta RPCScan
python3 rpc-scan.py 10.10.1.19 --rpc
# A flag --rpc lista os serviços RPC (incluindo NFS se configurado)
# Saída esperada: porta 2049 aberta e NFS ativo

# Objetivo do Pentester com Isso
#   Identificar diretórios exportados via NFS
#   Descobrir IPs com acesso autorizado
#   Usar essas informações para:
#       Fazer montagem remota de diretórios
#       Spoofar IPs permitidos e acessar os dados
#       Explorar configurações inseguras


###############
# MOD 4 - Lab 5: Perform DNS Enumeration
###############

# Ambiente Linux (Parrot Security)
sudo su # Tornar-se root
cd # Ir para o diretório raiz (opcional)
dig ns www.certifiedhacker.com # Descobrir os Name Servers (NS) do domínio-alvo
dig @ns1.bluehost.com www.certifiedhacker.com axfr # Tentar Zone Transfer com um dos Name Servers. "@ns1.bluehost.com": nome do servidor DNS. "axfr": tentativa de transferência de zona DNS (zone transfer)
#   ❌ Se zone transfer estiver desativado, a saída dirá: Transfer failed.

# Ambiente Windows (Windows 11)
# Abrir o Prompt de Comando
#   Clicar em 🔍 "Search"
#   Digitar cmd
#   Abrir o Command Prompt
nslookup # Entrar no modo interativo do nslookup
set querytype=soa # Definir tipo de consulta como SOA (Start of Authority)
certifiedhacker.com
# Mostra informações administrativas sobre o domínio, como:
#   Servidor primário
#   Email do responsável
#   Serial number da zona
ls -d ns1.bluehost.com # Tentar transferência de zona (zone transfer)
#   ❌ Se a transferência for negada: DNS server refused zone transfer.

# Objetivo do Pentester com Isso
# Descobrir:
#   Subdomínios
#   Hostnames internos
#   IPs internos
#   Estrutura da zona DNS
# Caso zone transfer esteja habilitado por engano, isso é uma falha crítica de configuração e pode comprometer toda a rede da organização.


###############
# MOD 4 - Lab 6: Perform SMTP Enumeration
###############

# Ambiente: Parrot Security OS
sudo su # Acesso root (usuário privilegiado)
nmap -p 25 --script=smtp-enum-users 10.10.1.19 # Enumeração de usuários SMTP. Tenta descobrir usuários válidos no servidor SMTP (usando técnicas como VRFY, RCPT TO etc). Muito útil para ataques de força bruta ou password spraying posteriores.
nmap -p 25 --script=smtp-open-relay 10.10.1.19 # Verificação de Open Relay. Verifica se o servidor SMTP está configurado como open relay, ou seja, se permite envio de emails para terceiros sem autenticação (uma falha crítica que pode ser explorada por spammers e invasores).
nmap -p 25 --script=smtp-commands 10.10.1.19 # Descoberta de comandos SMTP suportados. Lista os comandos SMTP suportados pelo servidor, como HELO, VRFY, EXPN, ETRN, HELP, etc. Permite saber quais comandos podem ser usados em futuras interações ou explorações. 

# Objetivo do Pentester com Isso
#   Identificar falhas de configuração no serviço de email (SMTP)
#   Obter listas de usuários válidos para ataques posteriores
#   Verificar se é possível enviar e-mails falsos (phishing) via open relay
#   Mapear capacidades do servidor (comandos suportados)


###############
# MOD 4 - Lab 7: Perform Enumeration using Various Enumeration Tools
###############

# Abertura da Ferramenta
# No Windows 11, procurar por Global Network Inventory no menu iniciar e abrir o programa.
#    Aceitar o controle de conta de usuário (UAC) se solicitado.
#    “I Agree” para prosseguir com o assistente de abertura.
#    “Tip of the Day” ao abrir a interface gráfica (GUI).

# Configuração do Tipo de Escaneamento
#   Iniciar o New Audit Wizard.
#   Escolher Single address scan (também pode-se usar IP range scan).
#   Inserir o endereço IP de destino — ex: 10.10.1.22.

# Autenticação
#   Opção usada no lab: Connect as → inserir:
#       Username: Administrator
#       Password: Pa$$w0rd
#   Nota: Em um cenário real, invasores não teriam as credenciais e provavelmente usariam:
#       Connect as currently logged on user → obteriam menos informações.

# Execução do Escaneamento
#   “Next” → “Finish”
#   Tela de progressão da varredura
#   Tela com Scan Summary mostrando detalhes do IP escaneado.

# Navegação pelos Resultados
# | 🗂️ Aba                 | 📌 Informações Obtidas                                                           |
# | ---------------------- | -------------------------------------------------------------------------------- |
# | **Computer Details**   | Nome da máquina, endereço IP, domínio, fabricante, etc.                          |
# | **Operating System**   | Nome do SO, versão, arquitetura, detalhes do Windows                             |
# | **BIOS**               | Fabricante, versão, data e outros dados do BIOS                                  |
# | **NetBIOS**            | Nome NetBIOS, domínio de trabalho, detalhes de sessão NetBIOS                    |
# | **User Groups**        | Lista de grupos de usuários e seus membros                                       |
# | **Users**              | Usuários existentes, tempo de login, políticas de senha                          |
# | **Services**           | Serviços em execução, estado, tipo de inicialização                              |
# | **Installed Software** | Lista de softwares instalados, versão, fornecedor                                |
# | **Shares**             | Pastas compartilhadas, caminhos, permissões                                      |
# | **Outras abas**        | **Hardware e sistema:** processador, memória, placa-mãe, atualizações, SNMP etc. |


###############
# MOD 4 - Lab 8: Perform Enumeration using AI
###############

# NetBIOS Enumeration
sgpt --shell "Perform NetBIOS enumeration on target IP 10.10.1.11" # Enumeração simples de NetBIOS
sgpt --shell "Get NetBIOS info for IP 10.10.1.11 and display the associated names" # Obter nomes associados via NetBIOS
sgpt --shell "Enumerate NetBIOS on target IP 10.10.1.22 with nmap" # Usar Nmap para NetBIOS

# SNMP Enumeration
sgpt --chat enum --shell "Perform SNMP enumeration on target IP 10.10.1.22 using SnmpWalk and display the result here" # Com `snmpwalk`
sgpt --chat enum --shell "Perform SNMP enumeration on target IP 10.10.1.22 using nmap and display the result here" # Com `nmap`
sgpt --chat enum --shell "Perform SNMP processes on target IP 10.10.1.22 using nmap and display the result here" # Processos via SNMP com nmap

# SMTP Enumeration
sgpt --chat enum --shell "Perform SMTP enumeration on target IP 10.10.1.19." # Enumeração de SMTP

# DNS Enumeration
sgpt --chat enum --shell "Use Nmap to perform DNS Enumeration on target domain www.certifiedhacker.com" # Usar nmap para DNS
sgpt --chat enum --shell "Use dig command to perform DNS cache snooping on target domain www.certifiedhacker.com using recursive method. Use DNS server IP as 162.241.216.11" # Snooping recursivo
sgpt --chat enum --shell "Use dig command to perform DNS cache snooping on target domain www.certifiedhacker.com using recursive method. Use DNS server IP as 162.241.216.11" # Snooping não recursivo

# IPsec Enumeration
sgpt --shell "Perform IPsec enumeration on target IP 10.10.1.22 with Nmap" # Enumeração IPsec com nmap

# SMB Enumeration
sgpt --shell "Scan the target IP 10.10.1.22 for the port using SMB with Nmap" # Scan SMB com nmap

# Automação de Enumeração
sgpt --chat enum --shell "Develop and execute a script which will automate various network enumeration tasks on target IP range 10.10.1.0/24" # Criar script automático para enumeração

# LDAP Enumeration
sgpt --shell "Use nmap script to perform ldap-brute-force on IP 10.10.1.22" # Ataque de força bruta LDAP

# FTP Enumeration
sgpt --shell "Use Nmap to perform FTP Enumeration on www.certifiedhacker.com" # Enumeração FTP com Nmap