# 🔐 O que significa **AS-REP**

**AS-REP** = **Authentication Service Reply**

📌 Em português:

> **Resposta do Serviço de Autenticação**

Ela faz parte do protocolo **Kerberos**.

---

# 🧠 Onde o AS-REP aparece no Kerberos

O Kerberos tem três entidades principais:

* Cliente
* **AS (Authentication Service)** – no Domain Controller
* TGS (Ticket Granting Service)

O fluxo inicial é:

```
1️⃣ AS-REQ  → Authentication Service Request
2️⃣ AS-REP  → Authentication Service Reply
```

Ou seja:

* **AS-REQ** = pedido de autenticação
* **AS-REP** = resposta do DC

---

# 🧩 O que vem dentro do AS-REP

O AS-REP contém:

* Um **Ticket Granting Ticket (TGT)**
* Dados criptografados com a **senha do usuário**

📌 Importante:

* Essa criptografia usa a **chave derivada da senha**
* Por isso o AS-REP pode virar um **hash crackeável**

---

# ❗ Por que o AS-REP é explorável

### Situação normal (segura):

* Usuário faz **pre-authentication**
* Prova que sabe a senha
* DC só envia AS-REP após validar

### Situação vulnerável:

* Usuário tem **“Do not require Kerberos preauthentication”**
* DC envia AS-REP **sem validar**
* Qualquer um pode solicitar

👉 **Esse AS-REP vira alvo de ataque**

---

# 🔥 Daí nasce o nome do ataque

### **AS-REP Roasting**

* **AS-REP** → resposta Kerberos
* **Roasting** → “torrar” o hash offline

📌 Ou seja:

> *Coletar AS-REP de usuários vulneráveis e quebrar suas senhas offline.*

---

# 🧠 Como lembrar fácil

```text
AS = Authentication Service
REP = Reply
AS-REP = resposta do DC no Kerberos
```

Ou mentalmente:

> “AS-REP é o pacote que traz a senha criptografada”

---

# 📋 Relação com o ataque

| Termo           | Significado            |
| --------------- | ---------------------- |
| AS-REQ          | Pedido de autenticação |
| AS-REP          | Resposta do DC         |
| AS-REP Roasting | Quebra do AS-REP       |


---

# 🔐 Comando 1 — **GetNPUsers.py** (o ataque AS-REP Roasting)

```bash
GetNPUsers.py SKILL.CEH/ -no-pass -usersfile ~/users.txt -dc-ip 192.168.0.222
```

Esse comando **NÃO quebra senha**.
Ele **apenas COLETA hashes Kerberos** explorando usuários sem pre-authentication.

---

## 🧠 O que é o GetNPUsers.py

* Script da suíte **Impacket**
* Explora **AS-REP Roasting**
* Faz requisições **AS-REQ** para o DC
* Recebe **AS-REP** de usuários vulneráveis

👉 Ele conversa diretamente com o **Kerberos (porta 88)**.

---

## 🔍 Parâmetro por parâmetro

---

### 🔹 `SKILL.CEH/`

📌 **Domínio alvo**

Significa:

```text
Domínio: SKILL.CEH
Usuários: pertencem a esse domínio
```

👉 Sem isso, o DC não sabe **onde procurar os usuários**.

📌 O `/` no final indica:

> “Vou fornecer usuários separadamente”

---

### 🔹 `-no-pass`

📌 **Não usar autenticação**

Isso diz ao script:

> “Não tenho senha, não tente logar”

🔐 Importante:

* Esse ataque **funciona justamente sem senha**
* O script envia **AS-REQ sem pre-authentication**

👉 É isso que ativa o AS-REP Roasting.

---

### 🔹 `-usersfile ~/users.txt`

📌 **Lista de usuários candidatos**

Exemplo de `users.txt`:

```text
Administrator
Joshua
Maria
```

O script:

1. Lê cada nome
2. Pergunta ao DC:

   > “Esse usuário existe?”
3. Se existir **e** não exigir preauth → retorna hash

👉 Isso evita:

* Brute-force de senha
* Bloqueio de conta

---

### 🔹 `-dc-ip 192.168.0.222`

📌 **IP do Domain Controller**

Evita:

* Dependência de DNS
* Redirecionamento errado
* Ambientes mal configurados

👉 Comunicação direta com o **KDC (Kerberos Distribution Center)**.

---

## 🔄 Fluxo interno do GetNPUsers.py

```text
users.txt
↓
AS-REQ (sem preauth)
↓
DC verifica:
  ├─ usuário existe?
  ├─ preauth desativado?
↓
Se SIM → envia AS-REP
↓
AS-REP contém hash Kerberos
↓
Script imprime:
Joshua@SKILL.CEH:<hash>
```

---

# 🔓 Comando 2 — **John the Ripper** (quebra OFFLINE)

```bash
john --wordlist=~/rockyou.txt hash_founded.txt
```

Esse comando **NÃO conversa com o DC**.
Ele trabalha **100% offline**.

---

## 🧠 O que o John faz

* Ferramenta de **password cracking**
* Usa força bruta / dicionário
* Compara hashes localmente

---

## 🔍 Parâmetro por parâmetro

---

### 🔹 `john`

Executa o **John the Ripper**

---

### 🔹 `--wordlist=~/rockyou.txt`

📌 **Lista de senhas**

O John vai:

1. Ler cada palavra do rockyou
2. Aplicar função de hash Kerberos
3. Comparar com o hash coletado

📌 Por que rockyou?

* Senhas reais vazadas
* Alta taxa de sucesso
* Muito usado em provas CEH

---

### 🔹 `hash_founded.txt`

📌 Arquivo com o hash Kerberos

Formato típico:

```text
Joshua@SKILL.CEH:$krb5asrep$23$...
```

👉 O John detecta automaticamente:

* Tipo de hash
* Algoritmo
* Modo de ataque

---

## 🔄 Fluxo interno do John

```text
Hash Kerberos
↓
Senha candidata (rockyou)
↓
Deriva chave Kerberos
↓
Compara
↓
MATCH → senha encontrada
```

---

## 🧠 Por que isso funciona offline?

Porque:

* O AS-REP já veio criptografado
* A verificação é matemática
* Não precisa falar com o DC novamente

---

# 🧠 Como explicar isso numa prova (resposta perfeita)

> *The GetNPUsers.py tool was used to perform an AS-REP Roasting attack by requesting Kerberos AS-REP responses for users that do not require pre-authentication. The extracted Kerberos hash was then cracked offline using John the Ripper with the rockyou wordlist, revealing the password c3ll0@123.*

---

# 📌 Resumo mental definitivo

```text
GetNPUsers.py
→ coleta hash (online, sem senha)

John
→ quebra hash (offline, dicionário)
```

---

# ✅ Resultado final

* Usuário vulnerável: **Joshua**
* Hash Kerberos obtido
* Senha quebrada: **c3ll0@123**
