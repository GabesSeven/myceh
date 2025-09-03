#!/bin/bash


###############
# MOD 20 - Lab 1: Encrypt the information using various cryptography tools
###############

########
# TASK 1: Perform multi-layer hashing using CyberChef
########

# Objetivo
#   Demonstrar como criptografar informações e realizar multi-layer hashing usando ferramentas de criptografia modernas — focando neste caso no CyberChef, diretamente no navegador.

# Conceitos Envolvidos
#   Criptografia	Técnica para proteger dados convertendo-os de texto claro para texto cifrado
#   Hash	        Função unidirecional que gera um "resumo" único de dados, de tamanho fixo
#   MD5	            Função de hash de 128 bits. Rápida, mas já considerada fraca para segurança
#   SHA1	        Função de hash de 160 bits. Mais segura que o MD5, mas ainda vulnerável
#   HMAC	        Hash com chave secreta (Hash-based Message Authentication Code)
#   CyberChef	    Ferramenta online que permite realizar transformações criptográficas
#   Auto Bake	    Função que aplica automaticamente os filtros e transforma o input

# Acessar a Máquina Windows 11
#   Login: Admin
#   Senha: Pa$$w0rd

# Criar o Arquivo Secreto
My Account number is 0234569198
#   Caminho: Desktop → Novo → Documento de Texto
#   Nome: Secret.txt
#   Salvar com: Ctrl + S

# Abrir o CyberChef
#   Acesse: 
https://gchq.github.io/CyberChef/
#   Navegador usado: Firefox (pode usar outro)

# Importar o Arquivo para o CyberChef
#   Clique no botão Open file as input (no topo da seção de entrada)
#   Selecione o arquivo Secret.txt na área de trabalho
#   O conteúdo aparecerá no Input automaticamente

# Aplicar Hash MD5
#   Na barra de busca de Operations, digite: md5
#   Arraste a operação MD5 para a seção Recipe
#   O resultado da função hash MD5 aparecerá em Output
#   Exemplo de resultado (Output):
f9d2a6b788f739d8c7e8fd29b1cc0e57

# Aplicar Hash SHA1 sobre o MD5
#   Procure por: 
sha1
#   Arraste SHA1 para a sequência (abaixo de MD5)
#   Configure Number of rounds: 
80 (opcional ou exigido)
#   Agora você está fazendo uma camada dupla: 
SHA1(MD5(input))
#   Exemplo de resultado (Output):
c4ac18fe0a464924122ee0d27cd86c3c843ee0e4

# Adicionar HMAC como Terceira Camada
#   Procure por: 
hmac
#   Arraste HMAC para o Recipe (abaixo de SHA1)
#   Configure:
#   Key: 
12
#   Hash Function:
MD5
#   Isso aplica: 
HMAC-MD5(SHA1(MD5(input)))
#   Exemplo de Output:
6f3e09744e274a6fa9dbdbe14c1de57c

# Recursos Extras no CyberChef
#   Set Breakpoint: pausa a execução antes da operação selecionada
#   Disable Operation: desativa temporariamente uma operação específica na Recipe


# Interpretação Técnica
#   A estrutura final da transformação ficou assim:
Input → MD5 → SHA1 → HMAC-MD5 (key: 12) → Output
#   Ou seja:
HMAC_MD5(key=12, SHA1(MD5("My Account number is 0234569198")))

# Aplicações Práticas no Mundo Real
#   Assinatura digital de mensagens
#   Verificação de integridade de arquivos
#   Camadas extras de segurança em dados sensíveis
#   Proteção contra ataques de colisão e força bruta

# Checklist Final do Laboratório
#   Criação de arquivo secreto (Secret.txt)
#   Acesso ao CyberChef
#   Upload do arquivo
#   Hash MD5 aplicado
#   Hash SHA1 aplicado sobre MD5
#   Aplicação de HMAC (com key e função MD5)
#   Uso de recursos avançados (breakpoint, disable operation)
#   Output final interpretado
#   Documentação do processo


########
# TASK 2: Perform file and text message encryption using CryptoForge
########

# Objetivo
#   Demonstrar como criptografar arquivos e mensagens de texto usando o software CryptoForge
#   Proteger dados sensíveis contra acessos não autorizados, mesmo que transportados em redes ou dispositivos inseguros.

# Conceitos Envolvidos
#   Criptografia de Arquivo	        Processo de proteger um arquivo com senha e algoritmo de cifra forte, tornando seu conteúdo inacessível sem a devida chave.
#   Passphrase	                    Senha forte usada para criptografar e descriptografar o conteúdo.
#   .cfe / .cfd	                    Extensões de arquivos criptografados pelo CryptoForge (file encryption / text encryption).
#   Compartilhamento seguro	        É necessário compartilhar a senha com o destinatário por canal seguro (mensagem, email, etc).

# Acessar a Máquina Windows 11
#   Acesse: Windows 11
#   Login: Admin
#   Senha: Pa$$w0rd

# Criptografar Arquivo com CryptoForge
#   Vá até:
E:\CEH-Tools\CEHv13 Module 20 Cryptography\Cryptography Tools\CryptoForge
#   Clique com o botão direito no arquivo Confidential.txt
#   Clique em Show more options
#   Selecione Encrypt no menu de contexto do CryptoForge

# Inserir Senha de Criptografia
#   Aparecerá a caixa: Enter Passphrase - CryptoForge Files
#   Preencha os campos:
#       Passphrase: qwerty@1234
#       Confirm: qwerty@1234
#   Clique OK
#   Isso irá:
#       Gerar um novo arquivo criptografado com a extensão .cfe
#       Excluir o original (por padrão) para segurança
#       Exemplo de nome gerado: Confidential.txt.cfe

# Simular Compartilhamento pela Rede
#   Assuma que o arquivo foi compartilhado pela rede em:
Z:\CEHv13 Module 20 Cryptography\Cryptography Tools\CryptoForge

# Acessar Windows Server 2019 e Descriptografar o Arquivo
#   Acesse: Windows Server 2019
#   Login: Administrator
#   Senha: Pa$$w0rd
#   Navegue até:
Z:\CEHv13 Module 20 Cryptography\Cryptography Tools\CryptoForge
#   Dê duplo clique no arquivo .cfe (criptografado)
#   Na caixa Enter Passphrase - CryptoForge Files, insira a senha:
qwerty@1234
#   Clique OK
#   O arquivo será descriptografado automaticamente, podendo ser aberto normalmente

# Criptografar Mensagem de Texto no CryptoForge Text
#   No Windows Server 2019, clique no campo de busca e digite: crypto
#   Clique em CryptoForge Text
#   Digite uma mensagem, por exemplo:
As credenciais de acesso estão no anexo seguro.
#   Clique no botão Encrypt na barra de ferramentas

# Inserir Senha para Mensagem
#   Senha: test@123
#   Confirmar: test@123
#   Clique OK
#   Resultado: o texto será convertido em código cifrado na mesma janela.

# Salvar Mensagem Criptografada
#   Clique em File > Save
#   Caminho:
Z:\CEHv13 Module 20 Cryptography\Cryptography Tools\CryptoForge
#   Nome do arquivo: Secret Message.cfd
#   Clique em Save

# Acessar a Mensagem Criptografada pela Máquina Windows 11
#   Acesse novamente o Windows 11
#   Caminho:
E:\CEH-Tools\CEHv13 Module 20 Cryptography\Cryptography Tools\CryptoForge
#   Clique duas vezes em Secret Message.cfd
#   O CryptoForge Text será aberto exibindo o texto cifrado
#   Clique em Decrypt

# Descriptografar Mensagem
#   Insira a senha: test@123
#   Clique OK
#   O conteúdo original aparecerá em texto claro

# Formato dos Arquivos Encriptados
#   .cfe	CryptoForge Encrypted File (arquivo comum criptografado)
#   .cfd	CryptoForge Encrypted Document (mensagem de texto criptografada)

# Importância no Mundo Real
#   Proteção de dados corporativos sensíveis (contratos, senhas, logs)
#   Compartilhamento seguro de arquivos por rede
#   Mensagens confidenciais protegidas por senha
#   Evita vazamento de informações em ataques ou acessos indevidos
#   Compliance com LGPD, GDPR, ISO 27001

# Checklist Final do Lab
#   Criptografar Confidential.txt
#   Descriptografar em outra máquina (Windows Server)
#   Enviar mensagem criptografada usando CryptoForge Text
#   Salvar e compartilhar Secret Message.cfd
#   Descriptografar mensagem no Windows 11
#   Documentar os caminhos, senhas e ações


###############
# MOD 20 - Lab 2: Create a self-signed certificate
###############

########
# TASK 1: Create and use self-signed certificates
########

# Objetivo
#   Demonstrar a criação e utilização de um certificado digital autoassinado (self-signed certificate) em um ambiente de testes, associando-o a um site no IIS (Internet Information Services).

# Conceitos Envolvidos
#   Certificado Digital	                    Documento eletrônico que associa uma chave pública a uma identidade (usuário, empresa, servidor etc.).
#   Certificado Autoassinado	            Certificado assinado por ele mesmo, sem autoridade certificadora externa (CA). Útil para testes internos.
#   HTTPS e Porta 443	                    Protocolo HTTP sobre camada SSL/TLS, garantindo comunicação segura. Usa a porta 443.
#   IIS (Internet Information Services)	    Servidor web nativo do Windows Server, usado para hospedar e configurar aplicações web.

# Acessar a Máquina Windows Server 2019
#   Acesse: Windows Server 2019
#   Login: Administrator
#   Senha: Pa$$w0rd

# Testar o Site antes do Certificado
#   Abrir navegador (ex: Mozilla Firefox)
#   Acessar o site:
https://www.goodshopping.com
#   Resultado: erro de conexão segura — pois o certificado SSL ainda não foi configurado.
#   Fechar o navegador.

# Acessar o IIS (Servidor Web)
#   Clique em "Type here to search" (canto inferior esquerdo da tela)
#   Digite: 
iis
#   Selecione: 
Internet Information Services (IIS) Manager

# Criar Certificado Autoassinado no IIS
#   No painel esquerdo (Connections), clique no nome da máquina:
SERVER2019 (SERVER2019\Administrator)
#   Na seção IIS do painel do meio, dê duplo clique em Server Certificates
#   No painel da direita (Actions), clique em:
Create Self-Signed Certificate…
#   Na janela aberta:
#       Nome: GoodShopping
#       Store: Personal
#       Clique OK
#   O certificado GoodShopping será exibido na lista de certificados.

# Associar o Certificado ao Site (Binding)
#   No painel esquerdo, expanda Sites
#   Clique em GoodShopping (site fictício já criado)
#   No painel direito (Actions), clique em:
Bindings…
#   Na janela Site Bindings, clique em:
Add…
#   Configurações na janela Add Site Binding:
#       Type: https
#       Port: 443 (preenchido automaticamente)
#       IP address: 10.10.1.19
#       Host name: www.goodshopping.com
#       SSL certificate: GoodShopping (selecionado na lista)
#       Clique OK
#   O binding HTTPS será adicionado ao site.
#   Clique em Close

# Atualizar a Visualização do Site
#   Clique com o botão direito no site GoodShopping
#   Selecione Refresh

# Testar o Acesso HTTPS com o Certificado
#   Minimize o IIS
#   Abra novamente o navegador (Mozilla Firefox)
#   Vá até:
https://www.goodshopping.com
#   Aparecerá:
Warning: Potential Security Risk Ahead
#   Isso é esperado, pois o certificado é autoassinado.
#   Clique em:
Advanced… > Accept the Risk and Continue
#   A página do site GoodShopping será carregada com HTTPS, validando o uso do certificado.

# Caminho Padrão de Armazenamento do Certificado
#   O certificado autoassinado fica armazenado no repositório:
Certificados Pessoais (Personal Store) do Computador Local
#   Pode ser acessado por:
mmc → Add/Remove Snap-in → Certificates → Computer account → Personal → Certificates

# Considerações Técnicas
#   Certificado assinado por	Ele mesmo (self-signed)
#   Validade típica	            1 ano (por padrão)
#   Validação no navegador	    Mostra aviso, pois não é confiável por uma CA reconhecida
#   Uso recomendado	            Testes internos, ambientes de desenvolvimento
#   Riscos em produção	        Navegadores rejeitam / mostram alerta de segurança

# Possíveis Extensões de Aprendizado
#   Exportar certificado .cer ou .pfx para uso externo
#   Adicionar o certificado ao Trusted Root Certification Authorities no cliente
#   Criar um certificado com OpenSSL no Linux para comparação

# Checklist Final do Lab
#   Acessar Windows Server 2019
#   Verificar site sem certificado
#   Criar certificado autoassinado no IIS
#   Atribuir certificado ao site com Binding
#   Testar acesso HTTPS ao site com o certificado
#   Aceitar o certificado autoassinado no navegador
#   Documentar etapas e conceitos envolvidos


###############
# MOD 20 - Lab 3: Perform disk encryption
###############

########
# TASK 1: Perform disk encryption using VeraCrypt
########

# Objetivo
#   Demonstrar como criar, montar, utilizar e desmontar um volume criptografado com o software VeraCrypt, protegendo arquivos com senha forte e volume virtual.

# Conceitos Fundamentais
#   Criptografia de Disco	            Processo de transformar os dados de um disco (interno, externo ou volume virtual) em formato ilegível sem a chave de acesso.
#   VeraCrypt	                        Software gratuito e open-source de criptografia de disco, baseado no TrueCrypt.
#   Criptografia on-the-fly	            Os dados são criptografados automaticamente antes de serem gravados e descriptografados após a leitura, sem intervenção do usuário.
#   Volume Virtual Criptografado	    Um arquivo no disco que se comporta como uma unidade de armazenamento criptografada, montada como drive virtual.

# Acessar a Máquina Windows 11
#   Acesse: Windows 11
#   Ação: clique no ícone de Search na barra de tarefas
#   Pesquise: vera
#   Clique: Open → Lança o VeraCrypt

# Criar Volume Criptografado
#   Janela principal do VeraCrypt → clique em:
Create Volume
#   Selecione:
Create an encrypted file container
#   Cria um volume criptografado no formato de um arquivo comum
# Clique: 
Next

# Definir Local e Tipo de Volume
#   Tipo: Standard VeraCrypt volume (opção padrão)
#   Clique: 
Next
#   Em Volume Location, clique:
Select File…
#   Navegue até a área de trabalho (Desktop)
#   Nome do volume: MyVolume
#   Clique: Save → Depois clique Next

# Configurar Criptografia e Tamanho
#   Tela Encryption Options:
#       Mantenha os padrões: 
AES / SHA-512
#       Clique: 
Next
#   Tela Volume Size:
#       Selecione: 
MB
#       Tamanho: 
5 MB
#       Clique: 
Next

# Definir Senha Forte
#   Defina uma senha forte:
qwerty@123
#   Confirme a senha
#   Clique: 
Next
#   VeraCrypt alerta se a senha é fraca (menos de 20 caracteres), mas permite prosseguir com confirmação.

# Formatar o Volume Criptografado
#   Sistema de arquivos: FAT (padrão)
#   Cluster: 
Default
#   Randomize os dados:
#       Mova o mouse aleatoriamente dentro da janela por pelo menos 30 segundos
#   Clique: 
Format
#   Isso criará o volume MyVolume como um arquivo .hc (container VeraCrypt).
#   Aguarde a criação → Clique: OK → Depois clique: Exit

# Montar o Volume Criptografado
#   De volta à janela principal do VeraCrypt:
#       Selecione um drive, ex: 
I:
#       Clique: 
Select File…
#       Localize o arquivo MyVolume na área de trabalho
#       Clique: 
Open
#       Clique: 
Mount
#       Digite a senha:
qwerty@123
#       Clique: 
OK
#   O volume será montado como disco virtual I: e pode ser acessado via "This PC" como se fosse um pen drive.

# Inserir Arquivo no Volume Criptografado
#   Crie um novo arquivo de texto no Desktop:
#       Nome: 
Test.txt
#       Conteúdo: 
qualquer texto (ex: “Arquivo secreto”)
#   Salve o arquivo
#   Copie Test.txt para o disco I: (o volume VeraCrypt montado)

# Desmontar o Volume
#   Volte para o VeraCrypt
#   Clique: 
Dismount para o volume I:
#   Clique: 
Exit
#   Resultado: o drive I: desaparece do sistema — os arquivos só podem ser acessados novamente montando o volume e digitando a senha correta.

# Importância de Criptografia de Disco
#   Proteção em caso de acesso físico	    Mesmo que um atacante acesse fisicamente o disco ou sistema, não poderá acessar os dados sem a senha.
#   Confidencialidade e integridade	        Garante que apenas usuários autorizados acessem as informações armazenadas.
#   Uso corporativo e pessoal	            Ideal para proteger dados sensíveis em pendrives, HDs externos, backups, laptops e containers.

# Implicações em Segurança Ofensiva
#   Como ethical hacker ou pentester, conhecer e testar volumes criptografados ajuda a:
#       Avaliar se dados sensíveis estão protegidos
#       Testar a resistência contra ataques de força bruta ou engenharia social
#       Garantir conformidade com normas como LGPD, GDPR, HIPAA etc.
#       Implementar criptografia em dispositivos usados em campo

# Resumo Final do Lab (Checklist)
#   Abrir VeraCrypt e criar volume criptografado
#   Definir senha e formato do volume
#   Montar o volume com senha correta
#   Mover arquivo para o volume criptografado
#   Desmontar o volume e verificar que ele não é mais acessível
#   Demonstrar utilidade para proteção contra invasores remotos


###############
# MOD 20 - Lab 4: Perform cryptography using AI
###############

########
# TASK 1: Perform cryptographic techniques using ShellGPT
########


# Objetivo Geral
#   Demonstrar como realizar operações criptográficas (hashing, criptografia, descriptografia) usando ShellGPT, uma ferramenta baseada em inteligência artificial integrada ao terminal shell Linux, com foco em automação e segurança da informação.

# Conceitos Fundamentais
#   ShellGPT	            Ferramenta que integra IA ao terminal shell para gerar comandos, realizar tarefas automatizadas e executar operações com base em linguagem natural.
#   Hash	                Função unidirecional que converte dados em uma string de tamanho fixo. Usada para integridade, autenticação e assinatura digital.
#   Base64	                Algoritmo de codificação que transforma dados binários em texto ASCII, usado para criptografias simples e transporte de dados.
#   MD5 / SHA1 / CRC32	    Algoritmos de hash com diferentes níveis de segurança e aplicação, usados para verificar integridade e gerar assinaturas digitais.

# Acessar a Máquina Parrot OS
#   Sistema: Parrot Security OS
#   Usuário: attacker
#   Senha: toor
sudo su        # Acessa como root
# senha: toor

# Executar ShellGPT com a chave de ativação
bash sgpt.sh
#   Prompt:
#       Enter Your AI Activation Key: <inserir chave>
#   A chave é obtida no módulo 00 do CEH Lab Setup (ou no PDF CEHv13).

# Operações Criptográficas com ShellGPT

# A) Hash MD5 de um texto simples
sgpt --shell "Calculate MD5 hash of text 'My Account number is 0234569198'"
#   Explicação:
#       O algoritmo MD5 gera um hash de 128 bits (32 caracteres hexadecimais). Apesar de obsoleto para segurança forte, ainda é usado para verificação de integridade.

# B) Hash duplo: MD5 seguido de SHA1
sgpt --shell "Calculate MD5 hash of text 'My Account number is 0234569198' and calculate the SHA1 hash value of the MD5 value"
#   Explicação:
#       Aqui usamos multi-layer hashing, aplicando primeiro MD5 e depois SHA-1 (160 bits). Isso encadeia duas funções de hash, útil em sistemas com dupla verificação ou legacy intercompatível.

# C) Hash de arquivo com CRC32
sgpt --chat hash --shell "Calculate CRC32 hash of the file passwords.txt located at /home/attacker"
#   Explicação:
#       CRC32 é um hash rápido de 32 bits, ideal para detecção de corrupção acidental de dados (ZIP, Ethernet, etc). Não é adequado para segurança criptográfica.

# D) Criptografar texto com Base64 e salvar
sgpt --shell "Encrypt 'Hello World' text using base64 algorithm and save the result to Output.txt"
#   Para visualizar:
pluma Output.txt
#   Explicação:
#       Base64 transforma dados binários (como textos ou arquivos) em strings ASCII, facilitando transmissão por e-mail, XML ou JSON.

# E) Descriptografar conteúdo Base64
sgpt --shell "Decrypt the contents of encrypted Output.txt file located at /home/attacker using base64 algorithm"
#   Para visualizar o resultado:
pluma DecryptedOutput.txt
#   Explicação:
#       Reverte a codificação Base64, retornando ao conteúdo original ("Hello World").


# Importância de Criptografia com AI
#   Geração dinâmica de comandos	                Permite escrever prompts em linguagem natural para tarefas complexas
#   Hashing em camadas	                            Verificação de integridade e segurança redundante
#   Análise e automação com AI	                    Integração com scripts e pipelines de segurança
#   Base para ataques/defesas automatizadas	        IA pode gerar ou quebrar padrões com aprendizado

# Cenários de Aplicação Real
#   Automação de hash/checksum em backups
#   Verificação de integridade de arquivos antes da transmissão
#   Criptografia de dados sensíveis em pipelines DevSecOps
#   Educação em segurança ofensiva (ataques por hash collisions, brute-force e reconhecimento)

# Checklist Final do Lab
#   Entrar no Parrot Security e ativar root
#   Ativar ShellGPT com chave de API
#   Calcular hash MD5 de texto
#   Fazer dupla camada de hashing (MD5 + SHA1)
#   Calcular hash CRC32 de arquivo
#   Criptografar texto com base64 e salvar
#   Visualizar conteúdo criptografado
#   Descriptografar texto base64
#   Visualizar conteúdo decriptado
#   Finalizar terminal e registrar informações

# Extras e Dicas Avançadas
#   Outras operações possíveis com ShellGPT:
#       Criptografar com AES/RSA (se instalados):
sgpt --shell "Encrypt file secrets.txt using AES-256 and save to secrets.enc"
#       Gerar chaves públicas/privadas:
sgpt --shell "Generate RSA key pair of 2048 bits"
#       Detectar alteração em arquivos:
sgpt --shell "Monitor file integrity using SHA256 hash for config.conf"