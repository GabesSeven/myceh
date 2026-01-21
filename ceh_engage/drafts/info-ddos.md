# 🗂️ O papel de CADA arquivo no desafio

O erro comum é tentar tirar **toda a resposta de um arquivo só**.
Na prática (e nesse lab), **cada arquivo tem uma função diferente**.

---

## 1️⃣ `report export.txt` → **VISÃO MACRO (QUEM MAIS ATACOU)**

### 📌 Estrutura:

```text
No.
Time
Outgoing bytes
Incoming bytes
Local IP Address
Local Port
Remote IP Address
Remote Port
```

### 🧠 Para que ele serve?

Esse arquivo é o **resumo estatístico** do Anti-DDoS Guardian.

👉 Ele responde exatamente isso:

> **Qual IP remoto gerou mais tráfego contra o alvo**

### 🎯 Campo mais importante para o desafio

* **Remote IP Address**
* **Outgoing bytes** (do ponto de vista do atacante)
* Às vezes **Incoming bytes** (resposta do alvo)

📌 Em DDoS:

* Quem tem **maior Outgoing bytes** = atacante principal

👉 **Esse arquivo é o que define a resposta final do desafio.**

---

## 2️⃣ `rec001.txt` → **CONFIRMAÇÃO DE VOLUME / COMPORTAMENTO**

### 📌 Conteúdo:

```text
Skipped 77 packets
22:48:46 An incoming packet (Allowed)
Protocol: TCP
Source port: 59880
Destination port: 80
```

### 🧠 O que isso mostra?

* Logs em **tempo real**
* Muitos pacotes sendo:

  * Recebidos
  * Permitidos
  * Em alta frequência

📌 A frase **“Skipped X packets”** é CRÍTICA:

* A ferramenta não consegue nem registrar tudo
* Volume alto demais

👉 Isso é **sintoma clássico de DoS/DDoS**

⚠️ Mas:

* Ele **não é ideal para ranking**
* Serve para **corroborar** o ataque

---

## 3️⃣ `rec002.txt` → **CONTEXTO DO ATAQUE (COMO FOI FEITO)**

### 📌 Conteúdo:

```http
GET / HTTP/1.1
Host: 192.168.10.135
```

### 🧠 O que isso indica?

* Tráfego **HTTP**
* Requests repetitivos
* Mesmo Host
* Mesmo padrão

👉 Isso caracteriza:

> **HTTP Flood (L7 DDoS)**

📌 Mesmo sendo HTTP:

* O ataque ainda é classificado como **DDoS**
* Só que em **camada de aplicação**

---

# 🔗 Como cruzar os três arquivos (lógica correta)

```text
rec002.txt → tipo do ataque (HTTP flood)
rec001.txt → volume excessivo de pacotes
report export.txt → QUEM atacou mais
```

📌 O desafio pede:

> **attacker IP which has transmitted more number of packets**

👉 Isso só pode ser respondido com:
✅ `report export.txt`

---

# 🧠 Como extrair o IP atacante corretamente (PowerShell)

### 🔍 Ver quem tem mais bytes

```powershell
Get-Content '.\report export.txt'
```

Observe:

* Qual **Remote IP Address**
* Tem o **maior Outgoing bytes**

Esse IP = **atacante principal**

---

## ⚡ Forma ainda melhor (se houver várias linhas por IP)

```powershell
Get-Content '.\report export.txt' |
Select-String '192.168' |
Group-Object |
Sort-Object Count -Descending
```

Ou manualmente:

* Compare Outgoing bytes
* Escolha o maior

---

# 🧠 Por que o CEH dividiu em 3 arquivos?

Porque ele quer testar se você entende:

| Arquivo           | Avalia              |
| ----------------- | ------------------- |
| report export.txt | Análise estatística |
| rec001.txt        | Detecção de flood   |
| rec002.txt        | Tipo de ataque      |

👉 Isso simula um **relatório real de SOC**, não um exercício de Wireshark.

---

# 📋 Como você explicaria isso na prova (resposta perfeita)

> *The Anti-DDoS Guardian report was analysed to identify the remote IP address that transmitted the highest number of packets. Based on the outgoing traffic statistics, the IP address **192.168.10.222** was identified as the primary attacker. The rec001 and rec002 logs further confirmed the presence of a high-volume HTTP flood attack.*

---

# ✅ Conclusão final (bem objetiva)

* **report export.txt** → define o IP atacante
* **rec001.txt** → prova excesso de pacotes
* **rec002.txt** → mostra HTTP flood
* IP com mais **Outgoing bytes** = resposta