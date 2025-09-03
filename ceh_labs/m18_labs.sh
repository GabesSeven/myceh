#!/bin/bash



###############
# MOD 18 - Lab 1: Perform footprinting using various footprinting techniques
###############

########
# TASK 1: Gather information using online footprinting tools
########

# Objetivo: 
#   Coletar o máximo de informações possíveis sobre dispositivos IoT/OT usando técnicas de footprinting online.

# Ferramentas e Sites Utilizados
#   Whois Lookup (whois.com)	                Buscar informações de registro de domínio
#   Google Hacking Database (exploit-db.com)	Encontrar dorks específicos relacionados a SCADA/IoT
#   Google Search	                            Usar dorks para encontrar páginas sensíveis
#   Shodan	                                    Descobrir dispositivos expostos na internet

# Acesso e Preparação
#   Login no Windows 11 com:
#       Usuário: Admin
#       Senha: Pa$$w0rd
#   Ao abrir a tela de rede, clicar em "Yes" para permitir descoberta na rede.

# Footprinting via Whois
#   Passos:
#   Abrir navegador (Firefox).
#   Acessar: 
https://www.whois.com/whois
#   Buscar pelo domínio:
www.oasis-open.org
#   Observar as seções:
#       Domain Information
#       Registrant Contact
#       Raw Whois Data

# Objetivo:
#   Obter informações sobre a organização responsável pelo MQTT, como:
#       Dono do domínio
#       Contato do registrante
#       Localização e data de criação

# Google Hacking (Avançado)
#   Passos:
#       Acessar: 
https://www.exploit-db.com/google-hacking-database
#   Pesquisar:
SCADA
#   Copiar dorks relevantes, como:
intitle:"scada login"
inurl:"/SCADA"
intitle:"index of" scada
#   Acessar o Google e pesquisar com dork, ex:
"login" intitle:"scada login"
#   Clicar em resultados relevantes (ex: SEAMTEC SCADA login)

# Objetivo:
#   Descobrir interfaces expostas de SCADA/IoT que estão acessíveis publicamente, inclusive para:
#       Login
#       Diretórios com arquivos sensíveis
#       Portas de serviço visíveis

# Footprinting via Shodan
#   Passos:
#       Acessar: 
https://account.shodan.io/login
#       Fazer login ou registrar conta
#       Após login, clicar em "Shodan" no canto superior
#       Na barra de busca, digitar:
port:1883

# Outras buscas úteis no Shodan:
#   port:502	                Dispositivos com Modbus exposto
#   "Schneider Electric"	    Dispositivos SCADA da Schneider
#   SCADA country:"BR"	        SCADA localizados no Brasil
#   mqtt ou protocol:mqtt	    Serviços MQTT na internet pública
#   title:"index of"	        Diretórios expostos na web

# Clicar em IPs listados → visualizar:
#   Portas abertas
#   ASN
#   Banner do dispositivo
#   Geolocalização
#   Fabricante

# Objetivo:
#   Identificar dispositivos IoT/OT expostos
#   Coletar informações que ajudem a explorar ou mapear vulnerabilidades

# Informações coletadas nas etapas
#   Durante a execução dos comandos acima, foram obtidos:
#       IPs Públicos	        Ex: 45.33.32.156
#       Localização	            País, cidade
#       Fabricante	            Ex: Schneider Electric
#       Protocolo	            MQTT, ModBus
#       Portas Abertas	        1883 (MQTT), 502 (ModBus)
#       Tipo do Dispositivo	    SCADA login pages, câmeras IP, sensores
#       Diretórios Expostos	    /scada, /data, /config/
#       Banner do Serviço	    Identifica versão de firmware ou software
#       Dados de Registro	    Domínio, organização, contato, etc.

# Resumo Final
#   O laboratório demonstrou técnicas eficazes de reconhecimento passivo e ativo, importantes para:
#       Coletar metadados antes de executar ataques
#       Identificar dispositivos vulneráveis
#       Realizar mapeamento de serviços expostos
#       Descobrir configurações inseguras em SCADA/IoT

# Checklist das Técnicas Utilizadas
#   Whois Lookup
#   Google Dorks
#   Google Search com dorks
#   Acesso a interfaces SCADA
#   Uso de Shodan para buscar portas e banners
#   Identificação de protocolos (MQTT, ModBus)


###############
# MOD 18 - Lab 2: Capture and analyze IoT device traffic
###############

########
# TASK 1: Capture and analyze IoT traffic using Wireshark
########

# Objetivo
#   Capturar e analisar o tráfego de rede entre dispositivos IoT e um broker MQTT.
#   Usar Wireshark para monitorar e estudar pacotes MQTT.
#   Entender como comandos são enviados do servidor para os dispositivos.

# Ferramentas Utilizadas
#   MQTT Broker (MQTTRoute)	        Recebe e envia mensagens MQTT entre cliente e servidor.
#   IoT Simulator	                Simula dispositivos IoT virtuais conectando-se ao broker MQTT.
#   Wireshark	                    Captura e analisa pacotes de rede entre os dispositivos e o broker.
#   Navegadores (Edge/Firefox)	    Acessa o painel web de gerenciamento do MQTT e do simulador.

# Instalar o MQTT Broker no Windows Server 2019
Z:\CEHv13 Module 18 IoT and OT Hacking\Bevywise IoT Simulator\Bevywise_MQTTRoute_4.exe
#   Executar o instalador e seguir o assistente.
#   Verificar se a porta 1883 está ativa no terminal (porta padrão do MQTT).
#   Manter o MQTT Broker executando.

# Instalar o IoT Simulator no Windows Server 2022
Z:\CEHv13 Module 18 IoT and OT Hacking\Bevywise IoT Simulator\Bevywise_IoTSimulator_3.exe
#   Instalar normalmente e reiniciar o sistema se solicitado.
#   Após iniciar, executar:
C:\Bevywise\IotSimulator\bin\runsimulator.bat
#   O navegador Edge será aberto automaticamente no endereço:
http://127.0.0.1:9000/setnetwork?network=HEALTH_CARE

# Criar Rede IoT Virtual
#   Acessar o menu ➕ e clicar em +New Network.
#   Nome sugerido: CEH_FINANCE_NETWORK.
#   IP do Broker: 10.10.1.19 (IP do Server 2019).
#   Salvar e confirmar.

# Adicionar Dispositivo IoT
#   Clicar em Add blank Device.
#   Exemplo:
#       Nome: Temperature_Sensor
#       ID: TS1
#       Descrição: qualquer uma
#   Clicar em Save.

# Conectar Rede e Dispositivo ao Broker
#   Clicar no botão vermelho Start Network ➡️ se tornará verde quando conectado.

# Acessar o Broker via Web
#   No Windows Server 2019:
http://localhost:8080
#   Login: admin/admin
#   Verificar a conexão com o dispositivo TS1 vindo do IP 10.10.1.22.

# Criar Comando MQTT
#   No IoT Simulator (Server 2022):
#   Menu superior ➕ ➝ Subscribe to Command
#   Tópico: High_Tempe
#   QoS: 1 (Atleast once)
#   Ao iniciar: On start
#   Clicar em Save

# Iniciar Captura com o Wireshark
#   No Server 2022:
#       Abrir o Wireshark
#       Selecionar a interface de rede com IP 10.10.1.22
#       Iniciar captura

# Enviar Comando ao Dispositivo
#   No Server 2019:
#       No painel do broker ➝ clicar no dispositivo TS1
#       Tópico: High_Tempe
#       Mensagem: Alert for High Temperature
#       Clicar em Submit

# Verificar Mensagem no Dispositivo
#   No Server 2022:
#       No painel do IoT Simulator ➝ expandir o log do dispositivo
#       Verificar recebimento da mensagem Alert for High Temperature

# Filtrar e Analisar Pacotes MQTT no Wireshark
#   Filtros Usados:
mqtt
#   Pacotes relevantes:
#       Publish Message	            Mensagem enviada do cliente ao broker
#       Publish Ack (PUBACK)	    Confirmação de recebimento (QoS 1)
#       Publish Recv (PUBREC)	    QoS 2: confirmação de recebimento inicial
#       Publish Rel (PUBREL)	    QoS 2: cliente confirma a intenção de entrega
#       Publish Comp (PUBCOMP)	    QoS 2: broker confirma que o processo de entrega foi concluído
#       Ping Request/Response	    Mantém a conexão viva

# Campos Importantes do Protocolo MQTT
#   Header Flags	        Tipo de pacote MQTT
#   DUP flag	            Indica se é uma retransmissão
#   QoS	                    Nível de qualidade do serviço (0, 1, 2)
#   Retain Flag	            Se deve armazenar a mensagem para futuras assinaturas
#   Topic Name	            Tópico da mensagem MQTT
#   Payload / Message	    Conteúdo da mensagem propriamente dita

# Conclusão
#   Este lab demonstrou como:
#       Criar uma simulação de dispositivos IoT conectados por MQTT.
#       Utilizar o Wireshark para interceptar e analisar pacotes MQTT em tempo real.
#       Compreender os diferentes tipos de mensagens do protocolo MQTT.
#       Observar como a comunicação acontece entre dispositivos e broker, identificando possíveis vetores de ataque.


###############
# MOD 18 - Lab 3: Perform IoT Attacks
###############

########
# TASK 1: Perform replay attack on CAN protocol
########

# Objetivo
#   Realizar um ataque de replay (retransmissão) no protocolo CAN (Controller Area Network) usando o simulador ICSim. O objetivo é:
#       Capturar e registrar pacotes CAN de um sistema simulado de painel automotivo.
#       Reproduzir os pacotes com canplayer para simular ações reais no veículo (como destravar portas ou acelerar), sem interação direta do usuário.

# Conceito de Replay Attack
#   Um Replay Attack consiste em capturar e reproduzir pacotes válidos da comunicação entre dois dispositivos. No caso do CAN Bus (muito usado em veículos), isso permite a um invasor simular comandos como:
#       Destravar portas
#       Ligar o motor
#       Girar volante
#       Acelerar ou frear

# Pré-requisitos e Ambiente
#   Sistema: Ubuntu Linux
#       Usuário: Ubuntu
#       Senha: toor
#   Ferramentas:
#       can-utils
#       ICSim (IC Simulator + CANBus Control Panel)

# Acessar como Root
sudo su
# Senha: toor
#   Necessário para executar comandos que configuram interfaces e controlam dispositivos virtuais.

# Criar Interface Virtual CAN (vcan0)
sudo modprobe can                           # Carrega módulo CAN
sudo modprobe vcan                          # Carrega módulo de interface virtual CAN
sudo ip link add dev vcan0 type vcan        # Cria interface virtual
sudo ip link set up vcan0                   # Ativa interface
#   Cria o canal de comunicação CAN simulado — essencial para testes locais sem hardware real.

# Verificar Interface vcan0
ifconfig
#   Procure a interface vcan0 na lista para confirmar a criação com sucesso.

# Dar Permissão à Pasta do ICSim
chmod -R 777 ICSim
#   Garante que todos os arquivos do simulador tenham permissão total para leitura/escrita/execução.

# Acessar Diretório e Compilar o ICSim
cd ICSim
make
#   Compila o simulador de painel (icsim) e o painel de controle (controls).

# Iniciar o IC Simulator (Painel do Carro)
./icsim vcan0
#   Abre a interface do carro (velocímetro, portas, etc) conectada à interface vcan0.

# Iniciar o Controlador (CANBus Control Panel)
#   Novo terminal:
sudo su
cd ICSim
./controls vcan0
#   Permite simular comandos no veículo, como acelerar ou destravar portas.

# Iniciar o Sniffer (Analisador de Tráfego CAN)
#   Novo terminal:
sudo su
cd ICSim
cansniffer -c vcan0
#   Mostra os IDs e mensagens trafegando na interface vcan0 em tempo real.

# Gravar os Pacotes CAN
#   Novo terminal:
sudo su
cd ICSim
candump -l vcan0
#   Grava os pacotes CAN trocados em um arquivo .log no formato candump-AAAA-MM-DD_HHMMSS.log.

# Executar Ações no Painel
#   Use o teclado para simular comandos:
#       Acelerar	                    ↑ (seta para cima)
#       Virar à esquerda/direita	    ← / →
#       Destravar portas traseiras	    Right Shift + X / Y
#       Destravar portas dianteiras	    Right Shift + A / B
#       Trancar todas as portas	        Hold Right Shift + Left Shift
#       Destravar todas as portas	    Hold Left Shift + Right Shift
#   Após realizar ações → pare a gravação com Ctrl + C.

# Verificar o Arquivo de Log Criado
ls
#   Deve haver um arquivo como: candump-2024-05-07_063502.log

# Executar o Replay Attack
canplayer -I candump-2024-05-07_063502.log
#   Reproduz todas as ações gravadas no IC Simulator e painel de controle, como se estivessem sendo feitas ao vivo.

# Boas Práticas para Relatórios e Documentação
#   Você pode registrar no relatório final:
#       Durante o laboratório, executou-se uma simulação de ataque de replay no protocolo CAN utilizando os simuladores ICSim e CANBus Control Panel. 
#       Os comandos CAN foram gerados por ações como aceleração e destravamento de portas.
#       Estes comandos foram interceptados usando a ferramenta candump e posteriormente reproduzidos com canplayer, simulando com sucesso ações no veículo sem interação real, 
#       demonstrando a vulnerabilidade dos sistemas automotivos baseados em CAN frente a ataques de retransmissão.
