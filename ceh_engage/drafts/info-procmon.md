# 🎯 Desafio 11 – Parte 2 (O que ele quer)

> **Determine o Parent PID do processo malicioso `H3ll0.exe` a partir do arquivo Logfile.PML**

📌 **PML** = log gerado pelo **Process Monitor (Procmon)**
📌 **Parent PID** = processo que **criou/executou** o malware

👉 Em malware analysis isso responde:

> *“Quem lançou o malware?”*

---

# 🧠 Visão geral da ferramenta (Procmon.exe)

## 🔍 O que é o Process Monitor?

**Process Monitor (Sysinternals)** é uma ferramenta da Microsoft que monitora em tempo real:

* Criação de processos
* Acesso a arquivos
* Registro do Windows
* Threads
* DLLs
* Chamadas do kernel

📌 Ele substitui:

* FileMon
* RegMon

---

## 📂 O que é um arquivo `.PML`

* Formato **nativo do Procmon**
* Contém **eventos de sistema gravados**
* Não é texto, nem CSV
* Só o Procmon consegue interpretar corretamente

👉 Por isso você **precisou abrir no Windows**

---

# 🧠 Por que essa parte do Linux + http.server?

```bash
python3 -m http.server 8000
```

Isso foi só para:

* Compartilhar o arquivo `Logfile.PML`
* Baixar pelo navegador no Windows

📌 **Isso NÃO faz parte da análise**, só logística.

---

# 🧠 Agora vem a parte importante: Procmon na prática

---

## 🛠️ Abrindo o arquivo

No Windows:

```
Procmon.exe
File → Open → Logfile.PML
```

➡️ Aqui você está **reproduzindo eventos passados**, não monitorando ao vivo.

---

# 🧩 Entendendo os CAMPOS do Procmon

Vamos usar um evento real seu:

```
Time: 11:36:xx
Process Name: H3ll0.exe
PID: 8688
Operation: Process Profiling
Result: SUCCESS
Parent PID: 6952
```

---

## 🔹 Process Name

```text
H3ll0.exe
```

➡️ Processo malicioso identificado

---

## 🔹 PID

```text
8688
```

➡️ Identificador **único** do processo

📌 Importante:

* PID ≠ Parent PID
* PID muda a cada execução

---

## 🔹 Operation: Process Profiling

Esse campo indica:

* O Windows iniciou análise de desempenho do processo
* Confirma que **o processo realmente executou**

📌 Isso prova que o malware **rodou**, não é só um arquivo parado.

---

## 🔹 Result: SUCCESS

➡️ Execução bem-sucedida

---

## 🔹 Parent PID (⭐ MAIS IMPORTANTE ⭐)

```text
Parent PID: 6952
```

➡️ Processo que **criou/executou** o `H3ll0.exe`

---

# 🧠 O QUE É Parent PID (conceito de prova)

> **Parent PID** é o identificador do processo pai responsável por iniciar outro processo.

Exemplo real:

```text
explorer.exe → cmd.exe → malware.exe
```

Nesse caso:

* `cmd.exe` = Parent
* `malware.exe` = Child

---

# 🧠 Por que isso é crítico em malware analysis?

Porque responde perguntas como:

* Foi iniciado por usuário?
* Foi iniciado por serviço?
* Foi iniciado por script?
* Foi iniciado por outro malware?

📌 Isso define:

* Persistência
* Vetor de ataque
* Nível de comprometimento

---

# 🔍 Como você chegou corretamente à resposta

Você fez:

1. Abriu o `.PML`
2. Localizou eventos do `H3ll0.exe`
3. Abriu **Event Properties**
4. Leu o campo **Parent PID**

✔️ **Metodologia correta**
✔️ **Resposta correta**
✔️ **Exatamente o que a prova espera**

---

# 🚀 Forma MAIS EFICIENTE de resolver (modo prova CEH)

### 1️⃣ Abrir PML

```text
Procmon → File → Open
```

---

### 2️⃣ Aplicar filtro (ESSENCIAL)

```text
Process Name is H3ll0.exe → Include
```

📌 Isso remove **milhares de eventos irrelevantes**

---

### 3️⃣ Selecionar qualquer evento válido

* De preferência:

  * `Process Create`
  * `Process Profiling`

---

### 4️⃣ Event Properties → Parent PID

➡️ **Resposta direta**

---

# 🧠 Tradução do desafio (em português claro)

> Você recebeu um log de monitoramento de processos.
> Analise o arquivo e descubra **qual processo iniciou o malware H3ll0.exe**.

---

# 🧠 Resposta oficial CEH (como eles pensam)

> By analyzing the Process Monitor log file, it was observed that the malicious process H3ll0.exe was spawned by a parent process with PID 6952.

---

# 🧠 Se quiser ir além (nível analista real)

Você poderia:

* Filtrar pelo **Parent PID = 6952**
* Descobrir **qual processo é esse**
* Identificar se foi:

  * `explorer.exe`
  * `cmd.exe`
  * `powershell.exe`
  * Serviço do Windows

📌 Isso já entra em **Incident Response real**

---

# 🧠 Depois do filtro `Process Name is H3ll0.exe → Include`, o que vem?

👉 **Você NÃO deve analisar todas as linhas**
👉 Você deve **achar um tipo específico de evento**

📌 **Objetivo do desafio**

> Encontrar o **Parent PID** do processo `H3ll0.exe`

⚠️ **Parent PID NÃO aparece em qualquer evento**

---

# 🎯 O EVENTO CERTO (regra de ouro)

## ✅ Procure por:

* **Operation: `Process Create`**
* **OU** `Process Profiling`

📌 **Somente esses eventos mostram o Parent PID**

---

# ❌ O que NÃO serve para esse desafio

Os eventos que você citou:

* `TCP Reconnect`
* `TCP Disconnect`
* `CloseFile`
* `CreateFile`
* `ReadFile`
* `WriteFile`
* `RegOpenKey`
* `RegSetInfoKey`
* `RegQueryKey`

➡️ **Todos esses são eventos gerados DEPOIS que o processo já existe**

Eles **não mostram quem criou o processo**.

---

# 🧠 Por que aparecem MUITAS linhas para H3ll0.exe?

Porque um processo, enquanto está rodando, faz:

* Leitura de arquivos
* Escrita em disco
* Acesso ao registro
* Comunicação de rede
* Carregamento de DLLs
* Fechamento de handles

📌 **Cada ação vira uma linha no Procmon**

Exemplo real:

```text
H3ll0.exe → ReadFile
H3ll0.exe → RegQueryKey
H3ll0.exe → TCP Connect
H3ll0.exe → TCP Disconnect
```

Isso **não é suspeito por si só**, é comportamento normal de execução.

---

# 🧠 Então por que você achou Parent PID em TCP Reconnect?

Boa observação 👀
Em **algumas versões do Procmon**, o campo **Parent PID pode aparecer em eventos de rede**, mas:

⚠️ **Não é confiável**
⚠️ **Não é o método esperado pela prova CEH**

👉 A **fonte correta e limpa** é sempre:

> **Process Create / Process Profiling**

---

# 🧭 Fluxo correto (PASSO A PASSO – PROVA CEH)

### 1️⃣ Aplicar filtro

```text
Process Name is H3ll0.exe → Include
```

---

### 2️⃣ Adicionar filtro adicional (OPCIONAL, mas perfeito)

```text
Operation is Process Create → Include
```

OU

```text
Operation is Process Profiling → Include
```

📌 Agora sobra **1 ou 2 eventos apenas**

---

### 3️⃣ Abrir Event Properties

Clique duplo na linha restante.

---

### 4️⃣ Ler o campo **Parent PID**

```text
Parent PID: 6952
```

➡️ **Resposta final**

---

# 🧠 Entendendo os tipos de Operation (resumo inteligente)

## 🔹 `Process Create`

✔️ Processo foi criado
✔️ **Contém Parent PID** ⭐
✔️ Melhor evento para esse desafio

---

## 🔹 `Process Profiling`

✔️ Processo começou a executar
✔️ **Contém Parent PID** ⭐
✔️ Muito usado em provas CEH

---

## 🔹 `CreateFile`

❌ Arquivo foi aberto/criado
❌ Não indica quem iniciou o processo

---

## 🔹 `ReadFile / WriteFile`

❌ Atividade de IO
❌ Processo já está rodando

---

## 🔹 `RegOpenKey / RegQueryKey / RegSetInfoKey`

❌ Acesso ao Registro
❌ Normal em execução

---

## 🔹 `TCP Connect / TCP Reconnect / TCP Disconnect`

❌ Comunicação de rede
❌ NÃO indica origem do processo

---

# 🧠 Analogia simples (pra nunca mais esquecer)

Imagine:

> Quem é o pai de uma pessoa?

❌ **Não é** quem ela conversa (TCP)
❌ **Não é** o que ela lê (ReadFile)
❌ **Não é** onde ela escreve (WriteFile)

✔️ **É quem deu origem a ela** → `Process Create`

---

# 🧠 Por que o Procmon mostra tudo isso?

Porque ele é uma ferramenta de:

* **Monitoramento de baixo nível**
* **Forense**
* **Malware analysis**
* **Incident response**

Ele **não decide o que é importante**, quem decide é você.

---


# 📍 ONDE ver **Process Create / Process Profiling** no Procmon

Você vai ver isso em **DOIS lugares diferentes**:

1. Na **coluna “Operation”**
2. Dentro de **Event Properties** (janela de detalhes)

Vamos por partes.

---

## 🧭 1️⃣ Onde aparece o **Operation** (tela principal)

Quando você abre o `Logfile.PML` no Procmon, a tela principal tem colunas como:

```
Time | Process Name | PID | Operation | Path | Result | Detail
```

👉 **É na coluna “Operation” que aparece:**

* `Process Create`
* `Process Profiling`
* `CreateFile`
* `TCP Connect`
* etc.

📌 **Você NÃO precisa abrir evento nenhum ainda**
Primeiro, **olhe a coluna Operation**.

---

## 🧪 2️⃣ Como FILTRAR para ver só Process Create (passo essencial)

### 🔹 Método 1 – Pelo menu de filtro (RECOMENDADO)

1. Vá em:

```
Filter → Filter...
```

2. Adicione estas regras:

```
Process Name   is   H3ll0.exe      → Include
Operation      is   Process Create → Include
```

(ou troque `Process Create` por `Process Profiling` se não aparecer)

3. Clique em **Add**
4. Clique em **OK**

📌 Agora a tela deve mostrar **1 ou pouquíssimas linhas**.

---

### 🔹 Método 2 – Sem filtro (manual, mas funciona)

1. Olhe a coluna **Operation**
2. Role a lista
3. Procure visualmente por:

```
Process Create
```

ou

```
Process Profiling
```

⚠️ Funciona, mas em logs grandes é ruim.

---

## 🔍 3️⃣ Onde ver o **Parent PID** (isso é o ponto-chave)

Depois de encontrar uma linha com:

```
Operation: Process Create
```

### 👉 Faça **duplo clique** nessa linha

Vai abrir a janela:

### 🪟 **Event Properties**

Agora observe:

---

## 🧩 Aba **Event**

Você verá algo como:

```
Process Name: H3ll0.exe
PID: 8688
Parent PID: 6952   ⭐⭐⭐
```

📌 **É AQUI que está a resposta do desafio**

---

## 🧠 Importante: Parent PID NÃO aparece na tabela principal

Na tela principal você vê:

* PID ❌
* Parent PID ❌

👉 **Parent PID só aparece dentro de Event Properties**

---

## 🧠 E se NÃO existir “Process Create”?

Alguns logs usam:

```
Operation: Process Profiling
```

Funciona do mesmo jeito:

1. Filtre:

```
Operation is Process Profiling
```

2. Duplo clique
3. Event Properties
4. Campo **Parent PID**

---

## 🧠 Por que TCP / File / Registry confundem?

Porque esses eventos:

* Acontecem **depois** da criação do processo
* Não registram quem criou o processo
* São ações normais durante execução

📌 Eles existem para **análise comportamental**, não para **origem do processo**.

---

## 🧠 Checklist mental (grave isso)

Sempre que o desafio pedir:

> Parent PID
> Processo pai
> Quem executou
> Origem do malware

✔️ Filtro por **Process Name**
✔️ Filtro por **Process Create / Profiling**
✔️ Abrir **Event Properties**
✔️ Ler **Parent PID**
