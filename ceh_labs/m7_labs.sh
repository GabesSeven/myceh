#!/bin/bash



###############
# MOD 7 - Lab 1: Gain Access to the System
###############

########
# TASK 1: Perform Active Online Attack to Crack the System's Password using Responder
########

# Objetivo do Lab
#   Demonstrar como atacantes:
#   Criam e implantam um Remote Access Trojan (RAT);
#   Obtêm acesso remoto completo à GUI da máquina da vítima;
#   Executam ações como keylogging, captura de tela, acesso a arquivos, entre outras;
#   Estabelecem comunicação persistente com a máquina da vítima mesmo após reinicialização.

# Ferramentas Utilizadas
#   njRAT v0.8d	Trojan (Remote Access Tool) usado para controlar remotamente a vítima
#   Test.exe	Arquivo malicioso gerado com o builder do njRAT
#   Windows 11	Máquina do atacante
#   Windows Server 2022	Máquina da vítima
#   CEH-Tools	Compartilhamento de arquivos entre atacante e vítima

# Preparação e Execução do njRAT (Atacante)
#   Login	                    Logar na máquina Windows 11 com usuário Admin e senha Pa$$w0rd.
#   Navegação	                Ir até o caminho E:\CEH-Tools\CEHv13 Module 07 Malware Threats\Trojans Types\Remote Access Trojans (RAT)\njRAT.
#   Execução	                Rodar o njRAT v0.8d.exe.
#   Construção	                Clicar em Build para abrir o construtor do trojan.
#   Configuração do Payload	    Preencher o IP da máquina atacante (ex: 10.10.1.11) no campo Host e ativar: Randomize Stub, ✔️ USB Spread, ✔️ Protect Process.
#   Gerar Server	            Salvar o payload como Test.exe na área de trabalho.

# Entrega do Trojan (Simulação do Ataque)
#   Compartilhamento        Copiar o arquivo Test.exe para o diretório compartilhado CEH-Tools.
#   Alternar para Vítima	Logar na máquina Windows Server 2022 como CEH\Administrator / Pa$$w0rd.
#   Receber o arquivo	    Acessar o compartilhamento CEH-Tools e copiar Test.exe para a área de trabalho.
#   Executar o Trojan	    Rodar o Test.exe na máquina da vítima (executável malicioso).

# Conexão e Controle Remoto com a Vítima (Atacante)
#   Assim que o Test.exe é executado, a vítima aparece na interface do njRAT. O atacante pode então:
#   Visualizar Informações da Vítima
#       IP
#       Usuário
#       Sistema operacional
#   File Manager
#       Navegar por diretórios e arquivos da vítima.
#       Realizar ações como abrir, deletar, mover arquivos etc.
#   Process Manager
#       Listar processos em execução.
#       Realizar ações como: Kill, Suspend, Kill + Delete.
#   Registry Manager
#       Visualizar e editar o Registro do Windows remotamente.
#   Remote Shell
#     Acessar o terminal da máquina da vítima.
#     Exemplo de comando executado:
ipconfig /all
#   Remote Desktop
#     Abrir uma sessão gráfica da vítima sem sua percepção.
#     Espionar ações da vítima em tempo real.
#   Remote Cam e Mic
#     Espionar vídeo e áudio da vítima.
#   Keylogger
#     Captura de tudo que a vítima digita.
#     Pode ser usado para roubar senhas, mensagens, etc.
#   Open Chat
#     Abrir um chat com a vítima (usado como demonstração).
#     Mensagem aparece como pop-up na máquina da vítima.

# Persistência (Reconexão Pós-Reboot)
#   Mesmo após reiniciar a máquina:
#       A vítima se reconecta automaticamente ao atacante.
#       Demonstra o uso de persistência configurada no Test.exe.

# Finalização e Limpeza
#   Encerrar Sessão da Vítima	    Ir até o Task Manager da máquina Server 2022.
#   Finalizar Processo	            Encerrar o processo Explorer.exe (32 bit) para forçar o desligamento.
#   Reboot	                        Reiniciar a máquina (efeito: simular desconexão do RAT).
#   Reconectar	                    Após o reboot, o njRAT na máquina do atacante recebe nova conexão automaticamente.


# Lições de Segurança
#   RATs como njRAT são extremamente perigosos quando executados com privilégios de usuário.
#   A educação do usuário e o uso de antivírus configurados corretamente são essenciais.
#   Detecção de comportamentos anômalos, controle de tráfego e gestão de dispositivos USB podem prevenir infecções.
#   O uso de sandboxing ou software de restrição de execução pode mitigar a execução de arquivos desconhecidos.



###############
# MOD 7 - Lab 2: Infect the Target System using a Virus
###############


########
# TASK 1: Create a Virus using the JPS Virus Maker Tool and Infect the Target System
########

# Acesso ao JPS Virus Maker
#   Ação:
#       Navegar até o diretório:
E:\CEH-Tools\CEHv13 Module 07 Malware Threats\Virus Maker\JPS Virus Maker
#   Executar:
JPS.exe
#   Se o Windows exibir um alerta de segurança ("Open File – Security Warning"), clicar em Run.
#   Objetivo: Iniciar a ferramenta de criação de vírus para configuração personalizada.

# Configuração do Vírus (Opções Marcadas)
#   Ações dentro da GUI da ferramenta JPS Virus Maker:
#   Habilitar Auto Startup
#   Opções maliciosas ativadas:
#       Disable Task Manager
#       Disable Windows Update
#       Disable Control Panel
#       Disable Drives
#       Hide Desktop Icons
#       Enable Remote Desktop
#       Remove Bluetooth
#       Turn Off Windows Firewall
#       Turn Off Windows Defender
#   Definições Avançadas:
#       Change Windows Password:
#           Senha nova: qwerty
#       Change Computer Name:
#           Novo nome: Test
#       Enable Convert to Worm:
#           Nome do worm: fedevi
#           Replicação a cada: 1 segundo
#       Ícone:
#           Selecionado: JPG Icon
#   Trigger do vírus:
#       Opção marcada: None (sem necessidade de evento externo – executa ao rodar o .exe)

# Geração do Executável Malicioso
#   Ação:
#       Clicar na seta ao lado do botão Create Virus! e selecionar:
x64(64Bit)
#       Clicar em:
Create Virus!
#   Resultado:
#       Pop-up:
Virus Created Successfully!
#   Arquivo gerado:
Server.exe
#   Criado no mesmo diretório onde o JPS.exe está localizado.

# Entrega da Carga Maliciosa
#   Método de entrega usado no lab:
#       Compartilhamento via *Z:* (mapped network drive)
#   Outros métodos possíveis em contextos reais (não usados no lab):
#       Email com anexo malicioso
#       Compartilhamento via pendrive (USB)
#       Compartilhamento em rede local (LAN)
#       Engenharia social (mensagem de "foto", "documento urgente" etc.)

# Execução no Sistema da Vítima (Windows Server 2019)
#   Ações no sistema infectado:
#       Login com:
Usuário: Administrator
Senha: Pa$$w0rd
#       Navegar até:
Z:\CEHv13 Module 07 Malware Threats\Virus Maker\JPS Virus Maker
#       Duplo clique em:
Server.exe
#   Resultado imediato:
#       Ícones da área de trabalho desaparecem
#       Sistema começa a exibir comportamentos estranhos
#       Algumas funções são desativadas (Painel de Controle, Firewall, etc.)

# Reinicialização e Teste de Persistência
#   Comportamento do vírus após reboot:
#       Ao tentar logar com:
Pa$$w0rd
#       Erro: senha incorreta.
#   Solução:
#       Tentar logar com a nova senha definida no vírus:
qwerty
#   Verificação de efeitos:
#       Tentativa de abrir Task Manager:
#           Pop-up de erro
#       Painel de controle inacessível
#       Várias funções do sistema desativadas
#   Conclusão da infecção: O vírus modificou configurações críticas do sistema, como:
#       Senha do usuário
#       Nome do computador
#       Políticas de sistema
#       Firewall e antivírus

# Restauração do Sistema (Reverter Máquina)
#   Ação:
#       Clique no botão:
Power and Display → Revert Machine
#       Se não funcionar:
Exit Lab → End Lab
#   Depois, relançar o laboratório para um ambiente limpo.

# Resumo das Técnicas Utilizadas
#   Criação de Vírus Personalizado	    Com JPS Virus Maker, configurando payload, nome de worm, ícone, etc.
#   Engenharia Social (implícita)	    Assumido que o arquivo foi entregue por e-mail ou rede
#   Persistência	                    Auto Startup, troca de senha, desativação de Task Manager
#   Interrupção de Serviços	            Desativa Firewall, Defender, Atualizações, etc.
#   Replicação (Worm)	                Configurado para replicar a cada 1 segundo
#   Evasão	                            Alteração de ícone, nome e tentativa de disfarce

# Importante: Considerações Éticas e de Segurança
#   Este laboratório é apenas para fins educacionais, controlado em ambiente seguro.
#   Criar e disseminar vírus fora de ambientes de laboratório é crime segundo a legislação brasileira e internacional.
#   Ferramentas como JPS Virus Maker devem ser utilizadas somente por profissionais de segurança para fins de teste, auditoria e simulação controlada.


###############
# MOD 7 - Lab 3: Perform Static Malware Analysis
###############

########
# TASK 1: Perform Malware Scanning using Hybrid Analysis
########

# Malware Scanning com Hybrid Analysis
#   Ferramentas utilizadas
#       Sistema operacional: Windows 11
#       Navegador: Google Chrome
#       Serviço online: Hybrid Analysis
#       Arquivo analisado: tini.exe

# Resumo das Ações Executadas
#   Login	                        Acessar a máquina Windows 11 com Admin / Pa$$w0rd
#   Permitir rede	                Na tela "Networks", clicar em Yes para permitir descoberta na rede
#   Acessar o site	                Abrir navegador e ir para 
https://www.hybrid-analysis.com
#   Aceitar cookies	                Clicar em ACCEPT se aparecer notificação de cookies
#   Upload do malware	            Clicar na área “Drag & Drop For Instant Analysis” e selecionar tini.exe no caminho
E:\CEH-Tools\CEHv13 Module 07 Malware Threats\Viruses
#   Preencher informações           Inserir:
#       Email pessoal	
#       Comentário (qualquer observação útil)	
#       Marcar checkbox de aceite dos termos	
#       Marcar o captcha	
#       Clicar em Continue	
#   Selecionar ambiente	            Selecionar sistema: Windows 11 64-bit
#   Gerar relatório	                Clicar em Generate Public Report
#   Visualizar resultados	        Aguardar conclusão e visualizar a aba "Analysis Overview"
#   Verificar detecção	            Confirmar que o arquivo tini.exe tem Threat Score: 100
#       Analisar SHA	                Verificar valores hash (SHA-256, MD5 etc) gerados para o arquivo
#       Ver AVs	                        Conferir seções com os resultados das engines antivírus (ex: CrowdStrike Falcon, MetaDefender)
#       Ver detalhes	                Clicar em More Details em MetaDefender para ver detalhes em nova aba
#       Encerrar análise	            Fechar abas e concluir tarefa

# Detalhes Técnicos Coletados
#   Hash SHA-256 / MD5      Identificador único do arquivo, usado para verificar reputação
#   Threat Score	        Indicador da periculosidade (0 a 100) – aqui foi 100 (extremamente perigoso)
#   Signatures	            Indicações conhecidas de comportamento malicioso detectadas
#   AV Engines	            Resultados de múltiplos antivírus (ex: Kaspersky, Microsoft Defender, etc.)
#   Behavior Analysis	    Logs e detalhes do que o malware tentaria executar se fosse aberto

# Outras Plataformas Recomendadas
#   Any.Run                 
https://app.any.run
#   Valkyrie Sandbox	    
https://valkyrie.comodo.com
#   JOESandbox Cloud	    
https://www.joesandbox.com
#   Jotti	                
https://virusscan.jotti.org
# Essas plataformas também oferecem sandboxing, análise comportamental e estática com resultados semelhantes.

# Outros Conceitos Importantes do Lab
#   Análise Estática	        Avaliar malware sem executá-lo
#   Fingerprinting	            Geração de hash do arquivo (ex: SHA-256)
#   Obfuscação	                Técnicas para esconder código real do malware
#   Empacotamento (Packing)	    Compactar ou criptografar o malware para evitar detecção
#   Strings	                    Cadeias de texto dentro do binário que podem indicar comandos, URLs, mensagens ou funções

# Resumo Final
#   Este lab demonstrou como:
#       Realizar upload seguro de malware para sandbox online
#       Analisar resultados de múltiplas engines antivírus
#       Coletar indicadores de comprometimento (IOCs)
#       Avaliar comportamento e classificação de ameaça
#       Agir com segurança em ambiente isolado para evitar contaminações


########
# TASK 2: Analyze ELF Executable File using Detect It Easy (DIE)
########

# Objetivo: 
#   Realizar análise estática em um arquivo ELF (Executável Linux) com a ferramenta DIE
#   Identificar informações como compilador, arquitetura, entropia, assinaturas e mais — sem executar o malware

# Ferramenta Utilizada
#   Nome	                Detect It Easy (DIE)
#   Plataforma	            Windows (usada neste lab), mas disponível também para Linux e Mac
#   Propósito	            Análise estática de arquivos binários (PE, ELF, Mach-O)
#   Método de detecção	    Baseado em assinaturas para identificar compilador, packer, linker, etc.

# Resumo das Ações Executadas
#   Acessar pasta do DIE
#       Ir para: 
E:\CEH-Tools\CEHv13 Module 07 Malware Threats\Malware Analysis Tools\Static Malware Analysis Tools\Packaging and Obfuscation Tools\DIE
#   Abrir o programa	Clique duplo em die.exe
#   Executar	Na janela “Open File – Security Warning”, clicar em Run
#   Selecionar arquivo ELF	Clicar no botão ... ao lado do campo File name e abrir ELF Test File em 
E:\CEH-Tools\CEHv13 Module 07 Malware Threats\Viruses
#   Visualizar informações	O DIE exibe automaticamente: sistema operacional alvo, linguagem de programação, compilador/linker usado, tipo de arquivo
#   Ativar visão avançada	Marcar a checkbox Advanced no painel lateral direito
#   Ver detalhes do arquivo	Clicar em File info (canto superior esquerdo) para visualizar:
#       Nome do arquivo	
#       Tamanho	
#       MD5, SHA1	
#       Entry point	
#       Entropia (nível de aleatoriedade do conteúdo)	
#       Arquitetura (ex: x86-64)	
#       Formato (ELF executável)	
#   Ver hashes	Clicar no botão Hash (canto superior direito) para visualizar todos os algoritmos de hash gerados (MD5, SHA1, SHA256)
#   Ver entropia	Clicar em Entropy para analisar se o binário está empacotado (valores acima de 7 indicam ofuscação)
#   Explorar mais opções	(opcional) Clicar nos botões:
#       MIME – Tipo MIME detectado	
#       Signatures – Assinaturas conhecidas para detectar packers ou obfuscações	
#       Demangle – Decodificação de nomes C++ (se existirem)	
#       HEX – Visualização hexadecimal do binário	

# Detalhes Técnicos Coletados com o DIE
#   Sistema alvo	        Ex: Linux x86-64
#   Tipo do arquivo	        Ex: Executável ELF
#   Compilador/linker	    Indica ferramenta usada para compilar (ex: GCC, Clang, etc.)
#   Assinatura detectada	Se o arquivo foi empacotado ou não
#   Entropia	            Mede a aleatoriedade: valores acima de 7.0 geralmente indicam obfuscation ou packing
#   Hash MD5/SHA1/SHA256	Importantes para IOCs (indicadores de comprometimento) e análise de integridade
#   Entry Point	            Endereço de entrada do executável (ponto inicial de execução)
#   Seções e offsets	    Pode ser útil para engenharia reversa posterior com IDA ou Ghidra

# Outras Ferramentas para Obfuscation/Packing
# Macro_Pack	    
#   Gera documentos Office com payloads ocultos	GitHub
# UPX	Packer open-source (comprime executáveis)	
https://upx.github.io
# ASPack	Packer comercial para Windows executáveis
http://www.aspack.com
# VMProtect	Ofuscação avançada com virtualização de código
https://vmpsoft.com

# Resumo Final
# A análise com Detect It Easy (DIE) permite extrair metadados críticos de um arquivo ELF malicioso sem a necessidade de executá-lo:
#   Detectar tipo e arquitetura do binário
#   Identificar compiladores, linguagens, e empacotadores
#   Observar entropia para suspeitar de ofuscação
#   Obter hashes para comparar com IOCs e bancos de dados de malware
#   Examinar assinaturas e seções internas


########
# TASK 3: Perform Malware Disassembly using IDA and OllyDbg
########

# Objetivo: 
#   Realizar engenharia reversa estática de malwares .exe
#   Analisando instruções em linguagem de máquina, APIs chamadas, estrutura de execução, e mapeamento da memória
#   Extrair lógica de funcionamento
#   Detectar chamadas perigosas
#   Compreender técnicas evasivas
#   Preparar o terreno para possíveis explorações defensivas ou ofensivas

# Ferramentas Utilizadas
#   IDA (Interactive Disassembler)	    Disassembler e debugger poderoso que converte binários em código assembly, exibindo o fluxo lógico do programa
#   OllyDbg	                            Debugger focado em análise de executáveis de 32-bit em Windows, muito útil quando não se tem o código-fonte

# Usando o IDA (IDA Freeware 8.4)
#   Pesquisar IDA no Windows        Buscar ida e clicar em IDA Freeware 8.4
#   Aceitar Termos	                Na janela IDA License, clicar em I Agree
#   Desativar Telemetria	        Desmarcar "Yes, I want to help improve IDA" e clicar em OK
#   Selecionar novo arquivo	        Na janela IDA: Quick Start, clicar em New
#   Escolher malware	            Navegar até: E:\CEH-Tools\CEHv13 Module 07 Malware Threats\Viruses e abrir o arquivo face.exe
#   Tipo de arquivo	                Na janela Load a new file, manter selecionado: Portable executable for 80386 (PE) [pe64.dll], clicar em OK
#   Confirmar avisos	            Clicar em OK nas janelas de warning e confirmação
#   Aguardar análise	            IDA analisará automaticamente o binário
#   Ativar visão em texto	        Clicar com botão direito em qualquer lugar da tela IDA View-A > Selecionar Text View
#   Visualizar Fluxo	            Menu View > Graphs > Flow Chart (mostra fluxo condicional da função atual)
#   Visualizar chamadas	            Menu View > Graphs > Function Calls (exibe chamadas entre funções, ideal para traçar o comportamento geral)
#   Hexadecimal	                    Clicar na aba HexView-1 para ver conteúdo hexadecimal
#   Imports	                        Clicar na aba Imports para ver APIs/funções chamadas externamente
#   Salvar banco de dados	        Fechar IDA > clicar em OK na janela "Save database"

# Principais Recursos e Comandos Usados no IDA
#   Text View                   Exibe instruções em assembly em formato legível
#   Graph View / Flow Chart	    Mostra o fluxo lógico da função atual com blocos e decisões
#   Function Calls	            Mapa de chamadas entre funções (útil para rastrear malware modular)
#   Imports	                    Mostra chamadas externas – APIs do Windows como CreateFileA, WinExec, etc
#   Hex View	                Exibe os bytes do binário em hexadecimal
#   Save database	            Permite salvar a análise para retomada posterior

# Usando o OllyDbg
#   Abrir OllyDbg	            Ir para E:\CEH-Tools\CEHv13 Module 07 Malware Threats\Malware Analysis Tools\Static Malware Analysis Tools\Disassembling and Debugging Tools\OllyDbg e abrir Ollydbg.exe
#   Permitir execução	        Clicar em Run na janela "Open File - Security Warning"
#   Confirmar DLL antiga	    Clicar Yes se aparecer a mensagem sobre DLLs antigas
#   Aviso de administrador	    Clicar OK se aparecer aviso de privilégios
#   Fechar sub-janelas	        Fechar as sub-janelas abertas automaticamente (Log, Registers, etc)
#   Abrir arquivo	            Menu File > Open > Selecionar tini.exe na pasta Viruses
#   Análise de CPU	            Janela CPU - main thread mostra instruções assembly com comentários
#   Abrir Log	                Menu View > Log – mostra entrada no ponto inicial e chamadas a funções
#   Ver Módulos	                Menu View > Executable Modules – lista módulos carregados pelo executável
#   Analisar Módulo	            Duplo clique em um módulo (ex: 75750000) para abrir no visualizador de código
#   Ver Mapeamento de Memória	Menu View > Memory Map – mostra layout da memória, segmentos, permissões
#   Ver Threads	                Menu View > Threads – exibe todos os threads em execução do processo

# Principais Recursos e Comandos Usados no OllyDbg
#   CPU Main Thread	        Mostra instruções assembly com cores e comentários
#   Log	                    Mostra chamadas a funções conhecidas, como APIs do Windows
#   Executable Modules	    Mostra os módulos carregados com endereços base
#   Memory Map	            Mapeamento de memória (RWX, .text, .data, etc)
#   Threads	                Lista de threads do processo analisado

# Dicas Técnicas para Análise com IDA/OllyDbg
#   Verificar se um malware chama APIs perigosas (ex: WinExec)	    IDA	            Use aba Imports ou busque call no assembly
#   Identificar se o malware cria arquivos ou conexões	            OllyDbg	        Acompanhar chamadas como CreateFile, socket, connect no log
#   Detecção de obfuscação	                                        IDA	            Cheque entropia, instruções incomuns ou saltos indiretos
#   Identificar packing	                                            Ambos	        Presença de poucas funções, strings ofuscadas, instruções jmp para endereços suspeitos
#   Estudo de comportamento sem execução	                        IDA (static)	Melhor para malware altamente evasivo
#   Depuração passo a passo	                                        OllyDbg	        Excelente para entender lógica do malware em tempo real

# Resumo Final da Tarefa
#   IDA             Pro	Disassembly estático com mapeamento de fluxo	                                        View > Graphs > Flow Chart, Imports, Text View
#   OllyDbg	        Depuração dinâmica (passo a passo) com visual de registradores, memória e chamadas	        View > CPU, Log, Memory Map, Threads


###############
# MOD 7 - Lab 4: Perform Dynamic Malware Analysis
###############

########
# TASK 1: Perform Port Monitoring using TCPView and CurrPorts
########

# Objetivo:
#   Realizar a análise dinâmica de malware (comportamental) ao executar um arquivo malicioso (Trojan.exe criado via njRAT)
#   Monitorar seu comportamento em portas de rede utilizando ferramentas como TCPView e CurrPorts.

# Criação do Trojan com njRAT
#   Ferramenta: njRAT v0.8d.exe
E:\CEH-Tools\CEHv13 Module 07 Malware Threats\Trojans Types\Remote Access Trojans (RAT)\njRAT
#   Comandos/Ações:
#     Abrir njRAT	    Duplo clique em njRAT v0.8d.exe
#     Build	            Clicar no botão Build na interface
#     Configuração	    Inserir o IP do atacante 10.10.1.11
#     Salvar	        Nomear o executável como Trojan.exe e clicar em Save

# Execução do Malware na Máquina-Alvo (Windows Server 2022)
#   Arquivo malicioso: Trojan.exe
Z:\CEHv13 Module 07 Malware Threats\Trojans Types\Remote Access Trojans (RAT)\njRAT
#   Comandos/Ações:
#       Acesso ao SO	    Acessar a máquina com CEH\Administrator / Pa$$w0rd
#       Executar malware	Duplo clique em Trojan.exe

# Monitoramento de Portas com TCPView
#   Ferramenta: tcpview.exe
Z:\CEHv13 Module 07 Malware Threats\Malware Analysis Tools\Dynamic Malware Analysis Tools\Port Monitoring Tools\TCPView
#   Comandos/Ações:
#       Iniciar TCPView	                    Duplo clique em tcpview.exe
#       UAC	                                Se aparecer o UAC, clicar em Yes
#       Licença	                            Clicar em Agree
#       Visualizar portas	                Clicar na coluna Local Port para ordená-las
#       Identificar malware	                Procurar pelo processo Trojan.exe
#       (Opcional) Finalizar processo	    Clicar com o direito > Kill Process (⛔ não feito neste caso)

# Monitoramento de Portas com CurrPorts
#   Ferramenta: cports.exe
Z:\CEHv13 Module 07 Malware Threats\Malware Analysis Tools\Dynamic Malware Analysis Tools\Port Monitoring Tools\CurrPorts
#   Comandos/Ações:
#       Iniciar CurrPorts	        Duplo clique em cports.exe
#       Identificar processo	    Buscar pelo Trojan.exe na lista
#       Ver detalhes	            Clique com o botão direito > Properties
#       (Opcional) Matar processo	Clique com o direito > Kill Processes Of Selected Ports ou Close Selected TCP Connections (⛔ não feito neste caso)
#   Comportamento Observado
#       O Trojan.exe conecta-se ao IP do atacante (10.10.1.11) através de uma porta TCP (ex: 5553).

# As ferramentas TCPView e CurrPorts mostram:
#   Nome do processo
#   PID (Process ID)
#   Endereço remoto
#   Porta remota
#   Caminho do executável
#   Estado da conexão (ex: ESTABLISHED)

# Ferramentas Alternativas de Port Monitoring
#   TCP Port Monitor / Telnet	
dotcom-monitor.com
#   PRTG Network Monitor
paessler.com
#   SolarWinds Open Port Scanner
solarwinds.com

#   Resumo das Ações Técnicas-Chave
#   Criação do malware	            njRAT	                Construção e salvamento de Trojan.exe
#   Execução	                    Windows Server	        Execução do Trojan via duplo clique
#   Análise de Porta	            TCPView	                Identificação do processo malicioso e sua porta
#   Análise de Porta	            CurrPorts	            Verificação detalhada do processo e propriedades
#   Ação preventiva (opcional)	    TCPView / CurrPorts	    Encerrar processo ou fechar conexão TCP


########
# TASK 2: Perform Process Monitoring using Process Monitor
########

# Objetivo:
#   Monitorar e identificar o comportamento do processo malicioso Trojan.exe em tempo real, analisando seu impacto no sistema, como:
#       Arquivos acessados
#       Chaves de registro manipuladas
#       Bibliotecas carregadas
#       Threads/processos filhos criados
#       Caminhos e permissões utilizados

# Pré-Requisito
#   Antes de começar, é necessário ter o processo Trojan.exe em execução. Se ele tiver sido encerrado na Task 1, reexecute-o:
Z:\CEHv13 Module 07 Malware Threats\Trojans Types\Remote Access Trojans (RAT)\njRAT\Trojan.exe

# Passo A Passo Com Todas As Ações E Comandos
#   Executar o Process Monitor
Z:\CEHv13 Module 07 Malware Threats\Malware Analysis Tools\Dynamic Malware Analysis Tools\Process Monitoring Tools\ProcessMonitor
#   Duplo clique em Procmon.exe e o Process Monitor será iniciado.

# Aceitar os termos de uso
#   Ação:
#       Clique em "Agree" na janela de licença

# Visualizar processos ativos
#   Ação:
#       A janela principal do Process Monitor exibirá eventos em tempo real:
#           Nome do processo
#           Tipo de operação (Operation)
#           Caminho acessado (Path)
#           Resultado da operação (Success, Access Denied etc.)
#           Detalhes adicionais (Details)

# Localizar o processo Trojan.exe
#   Ação:
#       Role a lista ou use Ctrl + F para abrir o campo de busca e procure por:
Trojan.exe

# Analisar os detalhes de eventos do processo
#   Ação:
#       Clique com o botão direito sobre um evento relacionado ao Trojan.exe > Clique em "Properties"
#   Resultado:
#       Uma janela com 3 abas será exibida:
#           Event (detalhes do evento: operação, caminho, resultado etc.)
#           Process (PID, nome do executável, caminho, sessão, etc.)
#           Stack (funções e DLLs carregadas durante a execução)

# Interpretar as abas da janela de propriedades
#   Aba: Event
#   Informações exibidas:
#       Data e hora
#       Nome da operação (ex: RegOpenKey, CreateFile, LoadImage)
#       Caminho acessado
#       Resultado (SUCCESS, ACCESS DENIED, etc.)
#       Duração da chamada
#   Aba: Process
#   Informações úteis:
#       Nome do processo
#       Caminho do executável
#       PID
#       ID da sessão
#       Arquitetura (32/64 bits)
#   Aba: Stack
#   Informações úteis:
#       Mostra o stack trace de chamadas (útil para identificar funções maliciosas)
#       DLLs e APIs carregadas
#       Permite ver o comportamento interno do malware
#   Ação final:
#       Clique em "Close" para fechar a janela

# (Opcional) Encerrar processo malicioso
#   Se for necessário encerrar o processo:
#       Alternativas:
#   Usar o Gerenciador de Tarefas (Ctrl+Shift+Esc)
#   Ou voltar ao CurrPorts/TCPView e usar as opções de:
#   Kill Process
#   Close Connection

# Outras Ferramentas para Monitorar Processos (mencionadas no lab)
#   Process Explorer	    docs.microsoft.com	    Versão mais visual e poderosa do Gerenciador de Tarefas
#   OpManager	            manageengine.com	    Monitoramento de desempenho em rede
#   Monit	                mmonit.com	            Monitoramento de servidores e processos no Linux/Unix
#   ESET SysInspector	    eset.com	            Análise avançada de sistema com foco em segurança
#   System Explorer	        systemexplorer.net	    Visualização detalhada de processos e conexões de rede