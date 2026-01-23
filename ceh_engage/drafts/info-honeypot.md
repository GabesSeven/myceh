# 🧠 CONTEXTO DO DESAFIO (o que realmente aconteceu)

📌 **Cenário**

* Um atacante interceptou tráfego **HTTP**
* A vítima fez login em uma aplicação web
* O tráfego **não estava criptografado (sem HTTPS)**
* O atacante capturou o tráfego (sniffing)
* O analista recebeu o `.pcapng` para análise

👉 **Vulnerabilidade explorada**
❌ Uso de **HTTP em vez de HTTPS**
➡️ Credenciais transmitidas **em texto puro**

---

# 🔍 O ATAQUE EM SI (bem direto)

* Login via formulário HTML
* Método HTTP: **POST**
* Tipo de conteúdo: `application/x-www-form-urlencoded`
* Usuário e senha enviados **literalmente no corpo da requisição**

📌 Não tem exploit, shellcode ou brute-force
➡️ É **passive sniffing**

---

# 🧪 EXPLICANDO SUA SOLUÇÃO PASSO A PASSO

---

## 1️⃣ Filtro aplicado

```wireshark
http.request.method == POST
```

### Por que isso funciona tão bem?

* Login **quase sempre** usa POST
* POST carrega dados no **corpo da requisição**
* GET normalmente só carrega parâmetros na URL

📌 Esse filtro:

* Remove imagens, JS, CSS
* Remove respostas do servidor
* Deixa só **envio de dados sensíveis**

✔️ Ótima escolha.

---

## 2️⃣ Pacote identificado

```
POST /login.aspx HTTP/1.1
```

Isso indica:

* Página de login
* Aplicação web (provavelmente ASP.NET)
* Formulário sendo enviado

---

## 3️⃣ Content-Type

```
application/x-www-form-urlencoded
```

📌 Significa:

* Dados enviados como:

  ```
  campo=valor&campo2=valor2
  ```
* Totalmente **legível em texto plano**

---

## 4️⃣ Decodificação automática do Wireshark (chave do desafio)

O Wireshark reconhece automaticamente:

```
HTML Form URL Encoded
```

E extrai:

```
txtusername = lee
txtpwd      = test
```

💥 Aqui está o “golpe”:

* **Sem criptografia**
* **Sem hash**
* **Sem encoding**
* Literalmente texto puro

---

## 🧾 FORMATO DA RESPOSTA

Enunciado:

```
(Format: aaa/aaaa)
```

Você entregou:

```
lee/test
```

✔️ 100% correto.

---

# 🧠 O QUE FOI EXPLORADO (linguagem de prova)

> *The attacker exploited insecure HTTP communication, allowing interception of credentials transmitted in cleartext via an HTTP POST request.*

Essa frase resolve metade das questões discursivas.

---

# ⚡ OTIMIZAÇÕES (modo prova CEH)

Agora vamos ao **modo ninja** 🥷

---

## 🔥 Filtro ainda mais direto (melhor)

```wireshark
http.request.method == POST && frame contains "txt"
```

Ou:

```wireshark
http contains "username" || http contains "password"
```

📌 Útil quando:

* Os campos não se chamam `user` / `pass`
* Você não sabe o endpoint

---

## 🔥 Outra forma (quando POST não ajuda)

```wireshark
tcp.port == 80 && http
```

Depois:

* Botão direito no pacote
* **Follow → HTTP Stream**

📌 Isso mostra:

* Requisição + resposta
* Corpo completo
* Ideal quando o Wireshark não decodifica o formulário

---

## 🔥 Filtro universal (CEH gosta)

```wireshark
http.request && !(http.response)
```

Mostra **toda requisição enviada pelo cliente**.

---

# 🧠 E se fosse HTTPS?

📌 Você **não veria isso**:

* POST estaria criptografado
* Campos ilegíveis
* Só veria handshake TLS

➡️ Esse desafio **existe exatamente para mostrar por que HTTPS é obrigatório**

---

# 🧠 Checklist mental (para Part 3)

✔️ HTTP
✔️ POST
✔️ application/x-www-form-urlencoded
✔️ Form fields visíveis
✔️ Credenciais em claro

👉 = **Sniffing de credenciais**


---

## 🧱 FORMATO GERAL DE UM LOG DO COWRIE

Antes de ir linha a linha, guarda este molde mental:

```
[TIMESTAMP] [MÓDULO, SESSÃO, IP_ORIGEM] MENSAGEM
```

Nem todas as linhas têm exatamente os três campos (módulo, sessão, IP), mas o padrão geral é esse.

---

# 🧩 LINHA 1 — Conexão encerrada rapidamente

```
2024-09-11T01:28:11.805001Z 
[HoneyPotSSHTransport,1,172.30.10.99] 
Connection lost after 0 seconds
```

### 🔍 Campo por campo

### 1️⃣ Timestamp

```
2024-09-11T01:28:11.805001Z
```

* Data e hora UTC
* Quando o evento ocorreu

---

### 2️⃣ Módulo

```
HoneyPotSSHTransport
```

📌 Significa:

* Camada de **transporte SSH**
* Responsável por abrir/fechar sessões SSH
* Ainda **antes de autenticação**

👉 Isso indica **tentativa de conexão**, não login ainda.

---

### 3️⃣ ID da sessão

```
1
```

* Identificador interno da conexão
* Útil para correlacionar eventos da mesma tentativa

---

### 4️⃣ IP de origem

```
172.30.10.99
```

🚨 **Esse é o atacante**

---

### 5️⃣ Mensagem

```
Connection lost after 0 seconds
```

📌 Interpretação:

* A conexão foi aberta e fechada quase imediatamente
* Comum em:

  * Port scanning
  * Scripts automatizados
  * Testes de banner

💡 **Comportamento típico de reconhecimento**, não de usuário humano.

---

# 🧩 LINHA 2 — Nova conexão SSH estabelecida

```
2024-09-11T01:29:11.805001Z 
[cowrie.ssh.factory.CowrieSSHFactory] 
New connection: 172.30.10.99:35929 (102.168.10.111:2222) 
[session: 33295034a52]
```

Essa linha é **muito importante**.

---

### 1️⃣ Timestamp

```
2024-09-11T01:29:11.805001Z
```

Um minuto depois da linha anterior → **persistência do atacante**

---

### 2️⃣ Módulo

```
cowrie.ssh.factory.CowrieSSHFactory
```

📌 O que é isso:

* Componente que **cria novas sessões SSH**
* Aqui a conexão **foi aceita**

---

### 3️⃣ IP e porta do atacante

```
172.30.10.99:35929
```

📌 Significa:

* IP atacante: `172.30.10.99`
* Porta de origem: `35929` (porta alta, aleatória)

✔️ Normal em conexões de cliente

---

### 4️⃣ IP e porta do honeypot

```
(102.168.10.111:2222)
```

📌 Interpretação:

* IP do honeypot
* Porta **2222**, não 22

⚠️ Cowrie normalmente roda:

* Porta 2222 externamente
* Simula porta 22 internamente

Isso evita conflito com SSH real do sistema.

---

### 5️⃣ Session ID

```
[session: 33295034a52]
```

📌 Importância:

* Identificador único da sessão
* Todos os eventos dessa conexão terão esse ID

---

# 🧩 LINHA 3 — Banner do cliente SSH

```
2024-09-11T01:28:11.933069Z 
[HoneyPotSSHTransport,2,172.30.10.99] 
Remote SSH version: SSH-2.0-PuTTy_Realese_0.76
```

Aqui começa a **identificação do atacante**.

---

### 🔍 Campo chave

```
Remote SSH version: SSH-2.0-PuTTy_Realese_0.76
```

📌 Isso é o **banner SSH do cliente**

Significa:

* O atacante está usando:

  * **PuTTY**
  * Versão 0.76
* Protocolo SSH v2

---

### 🧠 O que isso revela

| Informação | Significado                            |
| ---------- | -------------------------------------- |
| PuTTY      | Cliente SSH popular no Windows         |
| Versão     | Pode indicar SO e ferramentas          |
| Manual     | Possivelmente humano                   |
| Fake       | Alguns malwares falsificam esse banner |

💡 Em CEH, isso é chamado de:

> **Fingerprinting do cliente SSH**

---

# 🧩 LINHA 4 — Fingerprint criptográfico (HASSH)

```
2024-09-11T01:28:11.933069Z 
[HoneyPotSSHTransport,2,172.30.10.99] 
SSH client hassh fingerprint: 5b7713a9ef2d162b16ea018fa8d40f02
```

Essa é 🔥 avançada.

---

## 🧬 O que é HASSH?

**HASSH** =

> *Hash of SSH client handshake*

📌 Ele gera um **hash único** baseado em:

* Algoritmos suportados
* Métodos de criptografia
* Chaves
* Compressão

👉 Funciona como:

* “Fingerprint de navegador”, mas para SSH

---

### 📌 Por que isso importa?

* Identifica **ferramentas específicas**
* Detecta:

  * Bots
  * Frameworks de ataque
  * Scripts automatizados
* Mesmo se o IP mudar, o **HASSH pode ser o mesmo**

💡 Usado em:

* Threat Intelligence
* Detecção de campanhas
* Correlação de ataques

---

# 🧠 LIGAÇÃO ENTRE AS LINHAS (linha do tempo)

| Evento  | O que aconteceu       |
| ------- | --------------------- |
| Linha 1 | Conexão curta → scan  |
| Linha 2 | Conexão persistente   |
| Linha 3 | Banner SSH enviado    |
| Linha 4 | Fingerprint capturado |

👉 Isso mostra **tentativa real de acesso SSH**, não só scan.

---

# 🎯 CONCLUSÃO FINAL (estilo prova)

> *The Cowrie SSH honeypot detected multiple SSH connection attempts originating from IP address 172.30.10.99. The attacker initiated connections, revealed the SSH client banner (PuTTY 0.76), and exposed a unique HASSH fingerprint, indicating an SSH-based reconnaissance or access attempt.*
