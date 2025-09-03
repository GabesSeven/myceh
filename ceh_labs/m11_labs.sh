#!/bin/bash



###############
# MOD 11 - Lab 1: Perform Session Hijacking
###############

########
# TASK 1: Hijack a Session using Caido
########

# Objetivo do Lab
# Simular um ataque de Session Hijacking via HTTP Interception
# Redirecionar a navegação de um usuário autenticado sem seu conhecimento
# Alterar o conteúdo de uma requisição interceptada.

# Visão Geral da Arquitetura do Lab
#   Windows Server 2019	(vítima)	    Usuário autenticado, navegador Firefox
#   Windows 11	10.10.1.11	            Atacante, rodando o Caido
#   Porta Proxy Caido	8080	        Comunicação MITM entre navegador e destino

# Preparação na Máquina Atacante (Windows 11)
#   Ações:
#       Buscar e executar o Caido:
#           Ir no menu iniciar → Pesquisar por Caido → Abrir.
#       Configurar instância para escutar todas interfaces:
#           Menu lateral do botão Start → Edit.
#           Selecionar All interfaces (0.0.0.0) → Save.
#       Iniciar a instância:
#           Clicar em Start.
#       Criar conta e ativar licença:
#           Criar conta na interface.
#           Verificar e-mail → Copiar código → Inserir em Caido.
#           Efetuar login com a conta.
#       Registrar nova instância:
#           Nomear como Session Hijacking → Register.
#       Criar novo projeto:
#           Clicar em + Create a Project → Nomear como Session Hijacking.
#       Ativar interceptação:
#           Clicar em Intercept no painel lateral.
#           Ativar modo Queuing (o botão de encaminhamento muda de verde para vermelho).

# Configuração do Proxy na Máquina Vítima (Windows Server 2019)
#   Ações:
#       Login como administrador:
#       Usuário: Administrator
#       Senha: Pa$$w0rd
#   Limpar cache DNS (cmd como admin):
ipconfig /flushdns
#   Abrir Firefox e baixar o certificado CA do Caido:
#       Acessar:
http://10.10.1.11:8080/ca.crt
#       O navegador baixa automaticamente o certificado ca.crt.
#   Importar o certificado no Firefox:
#       Firefox → Settings → Buscar “Certificates” → View Certificates.
#       Guia “Authorities” → Import… → Selecionar ca.crt.
#       Marcar: Trust this CA to identify websites → OK.
#   Configurar o proxy manual no Firefox:
#       Ainda em Settings, buscar por Proxy.
#       Selecionar: Manual Proxy Configuration.
#           HTTP Proxy: 10.10.1.11
#           Port: 8080
#           Marcar: Also use this proxy for HTTPS → OK.

# Execução do Ataque (Hijacking com Caido)
#   Ações:
#       Na vítima (Windows Server 2019):
#           Abrir Firefox → Navegar até:
www.moviescope.com
#           Aparecerá um aviso SSL (conexão insegura).
#           Clicar em Advanced → Proceed to www.moviescope.com (unsafe).
#       Na máquina atacante (Windows 11 / Caido):
#           Ir para a aba Requests.
#           Observar requisições da vítima.
#           Para cada requisição GET a www.moviescope.com:
#               Editar o campo Host ou URL → alterar www.moviescope.com para www.goodshopping.com.
#               Clicar em Forward.
#       Na vítima novamente (Windows Server 2019):
#           O navegador continuará mostrando o domínio www.moviescope.com,
#           Mas o conteúdo exibido será de www.goodshopping.com, manipulando a sessão.

# Encerrar o Ataque e Reverter Configurações
#   Ações:
#       Na máquina vítima (Windows Server 2019):
#           Firefox → Settings → Buscar por Proxy.
#           Marcar: No Proxy → OK.


# O que foi Demonstrado
#   Interceptação e modificação de requisições HTTP/HTTPS em tempo real (proxy MITM).
#   Uso de CA falsa para contornar HTTPS (SSL strip sem aviso).
#   Redirecionamento invisível do conteúdo do site para outro domínio.
#   A vítima não percebe que foi redirecionada — endereço na barra permanece o mesmo.

# Conclusão
#   Este laboratório mostra como uma ferramenta como o Caido, combinada com manipulação de certificados SSL e configuração de proxy, pode permitir o controle completo de sessões de usuários na web. Essa técnica é poderosa e demonstra a importância de:
#       Habilitar HSTS nos sites.
#       Usar certificados válidos e pinning de certificado.
#       Bloquear proxies não autorizados em endpoints corporativos.


########
# TASK 2: Intercept HTTP Traffic using Hetty
########

# Objetivo
#   Interceptar requisições HTTP (incluindo dados sensíveis) feitas por uma máquina-alvo (Windows Server 2022)
#   Redirecionar para uma ferramenta proxy HTTP (Hetty) rodando na máquina atacante (Windows 11).

# Principais Ferramentas
#   Hetty: proxy HTTP/HTTPS para intercepção de tráfego, similar ao Burp Suite.
#   Navegadores Web: Firefox e Google Chrome.
#   Sistema Alvo: Windows Server 2022 (vítima).
#   Sistema Atacante: Windows 11 (proxy com Hetty).

# Iniciar o Hetty na máquina atacante (Windows 11)
Caminho: E:\CEH-Tools\CEHv13 Module 11 Session Hijacking\Hetty\
#   Ação: Duplo clique em `hetty.exe`
#   Hetty abre via terminal (janela de prompt de comando).
#   Inicia um servidor proxy local em http://localhost:8080.

# Acessar Interface Web do Hetty
#   Navegador: Firefox
#   Endereço: http://localhost:8080
#   Etapas na Interface Web:
#   Clicar em MANAGE PROJECTS
#       Criar novo projeto:
#       Nome: Moviescope
#   Botão: + CREATE & OPEN PROJECT
#   Ir para Proxy Logs (ícone lateral)

# Configurar Proxy na máquina vítima (Windows Server 2022)
#   Caminho no Chrome:
Chrome → Configurações → Sistema → Abrir configurações de proxy do computador
#   Configurações manuais:
#       Endereço (Proxy): 10.10.1.11 (IP da máquina atacante)
#       Porta: 8080
#       Opção: Ativar "Usar um servidor proxy"
#   Isso redireciona todo o tráfego HTTP/HTTPS da vítima para o Hetty.

# Gerar tráfego HTTP na máquina vítima
#   Navegador: Chrome
#   URL acessada: http://www.moviescope.com
#       Isso faz com que o tráfego HTTP passe pelo Hetty e seja capturado nos logs.

# Capturar Requisições no Hetty (Windows 11)
#   Ir até a aba Proxy logs
#   Procurar pelas requisições relacionadas ao domínio moviescope.com

# Capturar Dados Sensíveis (Login do Usuário)
#   Na máquina vítima, logar no site com:
Usuário: sam
Senha: test
#   No Hetty:
#       Achar a requisição POST correspondente (login)
#       Ver o conteúdo em Body > POST

# Exemplo de corpo interceptado:
username=sam&password=test

# Resultado Esperado
#   Credenciais de login da vítima são interceptadas com sucesso.
#   Ataque demonstrado: Machine-in-the-Middle (MITM) passivo via proxy.

# Restaurar Configuração de Proxy (Vítima)
#   Acessar novamente:
Chrome → Configurações → Sistema → Proxy
#   Desativar o uso de proxy ("Usar um servidor proxy" → OFF)

# Conceitos Importantes Envolvidos
#   Session Hijacking	        Interceptação ou uso indevido de uma sessão autenticada
#   MITM	                    Interposição do atacante entre cliente e servidor
#   Interceptação HTTP	        Captura de requisições e respostas trocadas entre navegador e servidor
#   Proxy Transparente	        O Hetty age como intermediário, mas o usuário da vítima não percebe
#   POST Request Sniffing	    Captura de dados enviados via formulário (ex: login)


# Documentação Final a Ser Registrada
#   IPs usados:                 Atacante (10.10.1.11), Vítima (dinâmico)
#   Ferramentas:                Hetty, Firefox, Chrome
#   Site alvo:                  www.moviescope.com
#   Credenciais capturadas:     sam:test
#   Técnicas envolvidas:        MITM, captura POST, proxy HTTP manual


###############
# MOD 11 - Lab 2: Detect Session Hijacking
###############

########
# TASK 1: Detect Session Hijacking using Wireshark
########

# Objetivo
#   Simular e detectar um ataque de Session Hijacking (sequestro de sessão) em uma rede local.
#   Usar o bettercap (na máquina Parrot Security) para conduzir o ataque.
#   Usar o Wireshark (na máquina Windows 11) para detectar e analisar o ataque manualmente.

# Máquina Alvo (Vítima): Windows 11
#   Ações Realizadas para Detectar o Ataque
#       Iniciar o Wireshark:
#           Buscar no menu:
#               Wireshark
#       Abrir o programa.
#   Selecionar Interface de Captura:
#       Selecionar:
#           Ethernet (interface principal)
#       Clicar em:
#           Start Capturing
#       Monitoramento de Pacotes:
#           Observar o tráfego sendo capturado.
#           Durante o ataque, notar várias requisições ARP (pacotes "Who has ...? Tell ...").
#           Esses pacotes indicam que a máquina atacante está tentando se passar por outros hosts da rede (spoofing ARP).

# Máquina Atacante: Parrot Security (10.10.1.13)
#   Ações Realizadas para Executar o Ataque
#       Acessar o terminal com privilégios de root:
sudo su
#           Senha padrão: toor
#   Mudar para o diretório raiz (opcional):
cd
#   Iniciar o bettercap com a interface de rede correta:
bettercap -iface eth0
#       -iface eth0: define o uso da interface de rede eth0.
#   Ativar o módulo de sondagem de rede:
net.probe on
#       Envia pacotes de sondagem para IPs na sub-rede, preparando para descobrir os hosts.
#   Ativar o módulo de reconhecimento da rede:
net.recon on
#   Detecta dispositivos na rede usando a tabela ARP.
#       Permite saber quais hosts estão ativos.
#   Ativar o sniffer de pacotes de rede:
net.sniff on
#       Inicia a captura de pacotes (como senhas, cookies, tokens etc.) trafegando pela rede local.
#   (Opcional) Outras funcionalidades possíveis:
#       Spoofing ARP, DNS, HTTPS, mas não foram usadas explicitamente neste lab.

# O que Wireshark mostra durante o ataque
#   Grande número de ARP Requests e ARP Replies:
#       Exemplo:
Who has 10.10.1.11? Tell 10.10.1.13
#       O atacante se passa pelo gateway e pela vítima ao mesmo tempo (man-in-the-middle).
#       Isso redireciona o tráfego da vítima para o atacante, permitindo o sequestro de sessões autenticadas.

# Conceitos Reforçados no Lab
#   Session Hijacking:
#       É o sequestro de sessões legítimas (ex: sessões autenticadas em sites).
#       Quando ocorre, o atacante pode assumir a identidade da vítima em uma conexão web, SSH, RDP etc.

# Detecção via Wireshark:
#   Uso de filtros para detectar tráfego ARP suspeito:
arp
arp && eth.src == [MAC do atacante]

# Melhoria do ataque com spoofing + MITM (não feito, mas possível):
#   Uso de:
arp.spoof on
set arp.spoof.targets 10.10.1.11
set arp.spoof.internal true

# Conclusão
#   O Wireshark permite detectar indícios de ataque ARP (base para session hijacking).
#   O bettercap é uma ferramenta poderosa para mitM + hijacking.
#   A observação de tráfego ARP anormal, especialmente vindo de uma máquina que não é o gateway, é um forte indicador de ataque.