# 🧠 Como pensar os *Operations* do Procmon

👉 Cada linha do Procmon responde a uma pergunta simples:

> **“O que esse processo acabou de pedir ao Windows?”**

Arquivo?
Registro?
Rede?
Processo?
Memória?

---

# 📂 OPERAÇÕES DE ARQUIVO (File System)

### 🔹 `CreateFile`

📌 **Não significa criar arquivo necessariamente**

➡️ Significa:

* Abrir
* Criar
* Acessar
* Obter handle

✔️ Normal:

* Abrir DLL
* Abrir EXE
* Abrir config

⚠️ Suspeito quando:

* Abrindo arquivos em `System32`
* Abrindo arquivos sensíveis (`SAM`, `NTDS.dit`)
* Abrindo muitos arquivos rapidamente

---

### 🔹 `ReadFile`

➡️ Processo leu dados de um arquivo

✔️ Normal:

* Ler DLLs
* Ler configs

⚠️ Suspeito:

* Ler senhas
* Ler bancos de dados
* Ler arquivos de usuários sem motivo

---

### 🔹 `WriteFile`

➡️ Processo escreveu dados em disco

✔️ Normal:

* Criar logs
* Atualizar cache

⚠️ Suspeito:

* Escrever em diretórios de inicialização
* Dropar outro executável
* Modificar arquivos do sistema

---

### 🔹 `CloseFile`

➡️ Fecha o handle do arquivo

✔️ Normal
📌 Geralmente ignora

---

### 🔹 `QueryBasicInformationFile`

➡️ Consulta:

* Tamanho
* Datas
* Atributos básicos

✔️ Normal
📌 Muito comum antes de `ReadFile`

---

### 🔹 `QueryAttributeInformationVolume`

➡️ Consulta informações do disco:

* Tipo
* Permissões
* Sistema de arquivos

✔️ Normal
📌 Muito comum na inicialização

---

# 🧬 OPERAÇÕES DE REGISTRO (Registry)

### 🔹 `RegOpenKey`

➡️ Abre uma chave do registro

✔️ Normal:

* Ler configurações
* Ver políticas

⚠️ Suspeito:

* Abrindo chaves de **Run**
* Chaves de **Services**
* Chaves de persistência

---

### 🔹 `RegQueryKey`

➡️ Consulta informações da chave

✔️ Normal
📌 Normalmente vem depois de RegOpenKey

---

### 🔹 `RegSetInfoKey`

➡️ **MODIFICA** uma chave

⚠️ MUITO IMPORTANTE

✔️ Normal:

* Programas legítimos

❌ Suspeito:

* Criar persistência
* Alterar políticas de segurança
* Modificar startup

📌 **Em malware analysis, isso é ouro**

---

### 🔹 `RegCreateKey`

➡️ Cria nova chave no registro

⚠️ Suspeito se:

* Em `Run`
* Em `Services`
* Em `Winlogon`

---

# 🌐 OPERAÇÕES DE REDE

### 🔹 `TCP Connect`

➡️ Tentativa de conexão TCP

✔️ Normal:

* Navegador
* Atualização

⚠️ Suspeito:

* IP externo estranho
* Porta incomum

---

### 🔹 `TCP Reconnect`

➡️ Tentativa de reconectar

⚠️ Pode indicar:

* C2
* Beaconing

---

### 🔹 `TCP Disconnect`

➡️ Conexão encerrada

✔️ Normal

---

### 🔹 `UDP Send / UDP Receive`

➡️ Tráfego UDP

⚠️ Suspeito:

* Flood
* DDoS
* DNS tunneling

---

# ⚙️ OPERAÇÕES DE PROCESSO

### 🔹 `Process Create`

⭐ **MAIS IMPORTANTE PARA ORIGEM**
➡️ Processo foi criado

📌 Contém:

* Parent PID
* Linha de comando

---

### 🔹 `Process Exit`

➡️ Processo terminou

✔️ Normal

---

### 🔹 `Process Profiling`

➡️ Início de execução monitorada

📌 Similar ao Process Create (em logs antigos)

---

# 🧠 OPERAÇÕES DE MEMÓRIA

### 🔹 `Load Image`

➡️ DLL ou EXE carregado na memória

✔️ Normal

⚠️ Suspeito:

* DLL não assinada
* Local estranho

---

### 🔹 `VirtualAlloc`

➡️ Alocação de memória

⚠️ Suspeito se:

* Executável
* Grande volume
* Após download

---

### 🔹 `WriteProcessMemory`

➡️ Um processo escreve na memória de outro

🚨 **ALTAMENTE SUSPEITO**

* Injeção de código
* Malware avançado

---

# 📋 OPERAÇÕES COMUNS QUE VOCÊ VAI VER SEMPRE

| Operation      | Significado         |
| -------------- | ------------------- |
| CreateFile     | Abrir/criar arquivo |
| ReadFile       | Ler arquivo         |
| WriteFile      | Escrever arquivo    |
| CloseFile      | Fechar arquivo      |
| RegOpenKey     | Abrir chave         |
| RegQueryKey    | Ler chave           |
| RegSetInfoKey  | Modificar chave     |
| Load Image     | Carregar DLL        |
| Process Create | Criar processo      |
| TCP Connect    | Conectar            |

📌 **90% dos logs são esses**

---

# 🧠 Regra de ouro (para não se perder)

| Objetivo                | Operation          |
| ----------------------- | ------------------ |
| Quem iniciou o malware? | Process Create     |
| Persistência?           | RegSetInfoKey      |
| Comunicação C2?         | TCP Connect        |
| Dropper?                | WriteFile          |
| Injeção?                | WriteProcessMemory |


---

# 🌐 TCP Connect / Reconnect / Disconnect — O que cada um significa

Esses eventos **não dizem quem criou o processo**, mas dizem **o que o processo fez na rede depois de existir**.

---

## 🔹 TCP Connect

### 📌 O que é

➡️ O processo **tentou iniciar uma conexão TCP** com outro host.

Tecnicamente:

* Envio de pacote **SYN**
* Início do **3-way handshake**

Exemplo:

```text
H3ll0.exe → TCP Connect → 192.168.10.50:80
```

---

### 🧠 O que isso indica

✔️ O processo tentou falar com alguém
✔️ Pode ser:

* Download
* Upload
* Beaconing
* Comunicação C2

---

### ⚠️ Quando é suspeito

* IP externo desconhecido
* Porta incomum
* Muitas conexões em curto intervalo

---

## 🔹 TCP Reconnect

### 📌 O que é

➡️ O processo **tentou reconectar** a um destino já conhecido.

Normalmente acontece quando:

* A conexão caiu
* O servidor não respondeu
* O malware tenta manter persistência de comunicação

Exemplo:

```text
H3ll0.exe → TCP Reconnect → 185.XX.XX.XX:4444
```

---

### 🧠 O que isso indica

⚠️ **Tentativa repetida de comunicação**

Muito comum em:

* Malware com **C2**
* Backdoors
* Bots

📌 Reconnect em loop = **beaconing**

---

## 🔹 TCP Disconnect

### 📌 O que é

➡️ A conexão TCP foi encerrada.

Pode ocorrer por:

* FIN (fechamento normal)
* RST (reset)

Exemplo:

```text
H3ll0.exe → TCP Disconnect
```

---

### 🧠 O que isso indica

✔️ Comunicação terminou
✔️ Sozinho não é suspeito

⚠️ Suspeito se:

* Conecta → desconecta → reconecta rapidamente
* Em grandes volumes

---

# 🧠 O que esses eventos NÃO dizem

❌ Quem executou o H3ll0.exe
❌ Qual processo pai
❌ Como o malware entrou

➡️ Para isso:

```text
Process Create / Process Profiling
```

---

# 🧠 Por que o SEU caso teve esses eventos?

Porque:

1. `H3ll0.exe` foi executado ✔️
2. Ele **se comunicou pela rede** ✔️
3. O Procmon registrou cada tentativa ✔️

📌 Isso mostra que o malware:

* Estava ativo
* Tentou comunicação externa ou lateral
* Não era um executável “inofensivo”

---

# 🧠 Como analisar esses eventos corretamente (se fosse outro desafio)

### 🔍 Passo 1 – Filtrar

```text
Process Name is H3ll0.exe
Operation is TCP Connect
```

---

### 🔍 Passo 2 – Olhar o campo **Path / Detail**

Ali você vê:

* IP destino
* Porta
* Estado

---

### 🔍 Passo 3 – Padrão temporal

* Muitos connects?
* Reconnects frequentes?
* Intervalos regulares?

➡️ Indício de **C2**

---

# 🧠 Analogia simples (pra fixar)

Imagine o malware como uma pessoa:

| Evento         | Analogia      |
| -------------- | ------------- |
| Process Create | Nascimento    |
| TCP Connect    | Telefonar     |
| TCP Reconnect  | Ligar de novo |
| TCP Disconnect | Desligar      |


---


# 🚨 O que é Beaconing?

📡 **Beaconing** ocorre quando um host comprometido:

* Envia conexões **regulares**
* Para o **mesmo IP ou domínio**
* Em **intervalos previsíveis**
* Normalmente com **baixo volume de dados**

👉 É como o malware dizendo:

> “Oi, ainda estou aqui. Alguma ordem?”

---

# 🧠 Definição simples (pra prova)

> **Beaconing** is a periodic communication between an infected host and a command-and-control server to check for instructions.

---

# 🔁 Como funciona tecnicamente

1. Malware infecta o sistema
2. Ele entra em modo “espera”
3. A cada X segundos/minutos:

   * Abre conexão (TCP/HTTP/DNS)
   * Envia pequeno pacote
   * Aguarda resposta
4. Se receber comando → executa
5. Se não → fecha conexão e espera

---

# 🌐 Protocolos mais usados para beaconing

* **HTTP / HTTPS** (mais comum)
* **DNS** (DNS tunneling)
* **TCP puro**
* **ICMP** (mais stealth)

---

# 📊 Exemplo prático (Wireshark / Procmon)

### No Procmon:

```text
H3ll0.exe → TCP Connect → 185.22.45.10:443
H3ll0.exe → TCP Disconnect
(repetido a cada 60 segundos)
```

📌 Intervalo regular = beaconing

---

### No Wireshark:

```text
GET /checkin HTTP/1.1
Host: evil-server.com
```

Repetido a cada minuto.

---

# 🧠 Como identificar beaconing (checklist mental)

✔️ Mesmo IP / domínio
✔️ Mesma porta
✔️ Intervalos constantes (ex: 30s, 60s)
✔️ Baixo volume de dados
✔️ Longa duração no tempo

Se marcar 3 ou mais → **suspeito**

---

# 🚩 Por que beaconing é perigoso?

Porque indica:

* Controle remoto ativo
* Malware persistente
* Possível exfiltração futura
* Sistema ainda comprometido

📌 Mesmo sem comandos, o acesso continua.

---

# 🧠 Diferença entre beaconing e tráfego normal

| Tráfego normal         | Beaconing              |
| ---------------------- | ---------------------- |
| Intervalos irregulares | Intervalos regulares   |
| Destinos variados      | Mesmo destino          |
| Volume variável        | Volume constante       |
| Usuário inicia         | Processo oculto inicia |

---

# 🧠 Beaconing em provas CEH

A CEH pode perguntar de várias formas:

* “Identify the suspicious periodic traffic”
* “Which behavior indicates C2 communication?”
* “What technique is used by malware to maintain contact?”

📌 **Resposta certa:** Beaconing

---

# 🛡️ Como mitigar beaconing (visão defensiva)

* IDS / IPS
* Análise de fluxo (NetFlow)
* EDR
* Bloqueio de domínios suspeitos
* DNS logging

---

# 🧠 Tradução literal do termo

**Beacon** = sinalizador / farol
➡️ Malware envia “sinais” periódicos
