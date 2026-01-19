# 🧠 O que o desafio está pedindo (em termos simples)

> **Find the IP address of the Domain Controller machine**

Ele quer que você **identifique qual host da rede 192.168.0.0/24 é um Domain Controller (DC)**
e entregue **o IP desse host**.

📌 **Não é**:

* “qual máquina tem Windows”
* “qual tem porta 389 aberta”
* “qual tem SMB”

É **qual máquina exerce o papel de DC**.

---

# 🧠 O que define um Domain Controller

Um **DC (Active Directory)** é um **Windows Server** que roda **Active Directory Domain Services**.

Normalmente ele expõe **um conjunto bem característico de serviços**:

### Portas típicas de DC

| Serviço             | Porta       |
| ------------------- | ----------- |
| DNS                 | 53          |
| Kerberos            | 88          |
| LDAP                | 389         |
| LDAPs               | 636         |
| SMB                 | 445         |
| RPC Endpoint Mapper | 135         |
| Global Catalog      | 3268 / 3269 |

⚠️ **Nenhuma porta isolada define um DC**
➡️ É o **conjunto**.

---

# 🧠 O que o desafio está testando

Esse desafio testa se você sabe:

* O que é um Domain Controller
* Que **DC ≠ qualquer Windows**
* Que DCs **quase sempre são DNS**
* Que DCs têm **LDAP + Kerberos**
* Que você precisa **correlacionar serviços**

---

# 🧠 O raciocínio correto (metodologia)

### 1️⃣ Identificar hosts vivos na rede

Antes de qualquer coisa:

> “Quais máquinas existem na 192.168.0.0/24?”

(ARP / ping scan)

---

### 2️⃣ Identificar hosts Windows

DC **só existe em Windows Server**.

Indícios:

* Porta 445 aberta
* SMB responde
* TTL típico de Windows (128)

---

### 3️⃣ Ver quem roda serviços de DC

Agora o pulo do gato:

Procure por host que tenha **ao mesmo tempo**:

* 53 (DNS)
* 88 (Kerberos)
* 389 (LDAP)
* 445 (SMB)

📌 **Isso praticamente grita “Domain Controller”**.

---

### 4️⃣ Confirmar pelo banner / serviço

Exemplos que confirmam:

* `ldapsearch` retornando `dc=...`
* `nmap` identificando `Microsoft Windows Active Directory LDAP`
* DNS apontando SRV records (`_ldap._tcp.dc._msdcs`)

---

# 🧠 O que NÃO fazer

❌ Procurar “porta 445 aberta” apenas
❌ Assumir que o primeiro Windows é DC
❌ Fazer full scan sem interpretar

---

# 🧠 Resposta esperada

O desafio **não quer explicação**, só:

```text
192.168.0.X
```

Mas o **avaliador espera** que você saiba **por que aquele IP é o DC**.

---

# 🧠 Exemplo de raciocínio (sem comandos)

> “Among the discovered hosts, only one system exposed LDAP, Kerberos, and DNS services simultaneously, indicating an Active Directory Domain Controller. The identified IP address is …”

---

# 🔥 Resumo rápido

| Pergunta           | Resposta              |
| ------------------ | --------------------- |
| O que é DC?        | Windows Server com AD |
| Como identificar?  | Conjunto de serviços  |
| Porta única basta? | ❌ Não                 |
| DNS é pista forte? | ✅ Sim                 |
| LDAP + Kerberos?   | 🚩 DC                 |


Ótima observação — isso é **exatamente o ponto onde muita gente se confunde**.
Vamos esclarecer **o que isso significa**, **o que NÃO significa** e **qual o próximo passo lógico**.

---

## 📌 O que significa `445/tcp open microsoft-ds`

### Tecnicamente

* **Porta 445** = **SMB sobre TCP**
* Serviço: **Microsoft-DS**
* Usado por:

  * Windows (workstation)
  * Windows Server
  * Domain Controller
  * File Server
  * Às vezes Samba (Linux)

👉 **Conclusão importante**:

> **SMB aberto ≠ Domain Controller**

---

## 📌 O que isso diz sobre essas máquinas

Esses IPs:

```
192.168.10.101
192.168.10.144
192.168.10.222
(+ 1 que você mencionou antes)
```

Significam:

* São **máquinas que expõem SMB**
* Muito provavelmente:

  * Windows workstations (usuários)
  * Windows Server
  * OU Samba (menos comum em labs AD)

📌 **Ainda não dá pra saber qual é o DC**.

---

## 🧠 Por que aparecem várias?

Porque em **ambiente Active Directory**:

* Quase todo Windows:

  * Usa SMB
  * Se autentica no DC
  * Acessa shares
* Então **muitos hosts têm 445 aberto**

---

## 🧠 Correlação final

| IP   | 445 | 88 | 389 | 53 |
| ---- | --- | -- | --- | -- |
| .101 | ✔️  | ❌  | ❌   | ❌  |
| .144 | ✔️  | ✔️ | ✔️  | ✔️ |
| .222 | ✔️  | ❌  | ❌   | ❌  |

➡️ **192.168.10.144 = Domain Controller**

(Exemplo ilustrativo)

---

## 🧠 Forma ainda mais limpa (confirmar)

Se quiser **prova definitiva**:

```bash
nmap -p 389 -sV 192.168.10.144
```

Banner típico:

```text
Microsoft Windows Active Directory LDAP
```

---

## 🧠 Resumo mental (guarde isso)

* 445 → **Windows-like**
* 445 + 88 + 389 → **Domain Controller**
* Muitos SMBs ≠ muitos DCs

---

### 🎯 O que o desafio QUER

* **NetBIOS Domain Name**
* Informação típica de:
  * SMB
  * NetBIOS
  * Windows AD

---

### ✅ Como isso apareceu no seu scan

No output você teve algo como:

```
Domain: SKILL.CEH.COM
Workgroup: SKILL
```

📌 **NetBIOS Domain Name = `SKILL.CEH`**
(sem `.com` no final, exatamente como o desafio pede)

👉 Isso vem de:

* Porta **139 / 445**
* Enumeração SMB
* Detectada automaticamente com `-sV`


## 🎯 O que é DNS Tree Name?

É o **nome DNS completo do domínio AD**, ex:

```
skill.ceh.com
```

---

### ✅ Onde isso aparece

No seu scan apareceu:

```
Microsoft Windows Active Directory LDAP
Domain: SKILL.CEH.COM
```

📌 **DNS Tree Name = `SKILL.CEH.COM`**

👉 Isso vem de:

* Porta **389 (LDAP)**
* Banner LDAP do Active Directory

### ❗ CEH NÃO separa por técnica — separa por CONCEITO

Um único scan pode revelar:

| Informação     | Origem            |
| -------------- | ----------------- |
| Host up        | Host discovery    |
| NetBIOS domain | SMB               |
| DNS Tree Name  | LDAP              |
| OS             | Service detection |
| DC             | Portas + banners  |

👉 **O lab foi feito para você perceber isso.**


Excelente pergunta — isso aqui é **fundamental para entender Windows/AD de verdade**, não só passar no lab. Vamos destrinchar **conceitualmente** e **tecnicamente**, sem atalhos.

---

# 1️⃣ O que é **NetBIOS Domain**?

## 🧠 Origem (histórica)

**NetBIOS** (Network Basic Input/Output System) é um sistema **antigo**, criado antes do DNS existir, para permitir que computadores Windows se descobrissem e se comunicassem **dentro da LAN** usando **nomes curtos**, não IPs.

👉 Ele nasceu nos anos 80/90, **pré-DNS**.

---

## 📛 O que é um NetBIOS Domain Name

É o **nome lógico curto** usado por máquinas Windows para:

* Autenticação
* Compartilhamento SMB
* Descoberta de serviços
* Logon em domínio

Exemplo:

```
NetBIOS Domain: SKILL
```

Ou no formato do CEH:

```
SKILL.CEH
```

⚠️ **Limitações**

* Máx. **15 caracteres**
* Não suporta hierarquia
* Não é global
* Funciona só na LAN

---

## 🧠 Como ele é usado hoje

Mesmo sendo antigo, o NetBIOS **NÃO morreu** porque:

* SMB ainda depende dele em vários cenários
* Muitas APIs internas do Windows usam NetBIOS
* Backward compatibility com sistemas legados

👉 Por isso ele **ainda aparece em scans modernos**.

---

# 2️⃣ O que é **DNS Tree Name**?

Agora entramos no **Active Directory moderno**.

## 🌐 DNS no Active Directory

Active Directory **DEPENDE de DNS** para funcionar.

Sem DNS:

* Não há localização de DC
* Não há Kerberos
* Não há autenticação moderna

---

## 🌳 DNS Tree Name

É o **nome DNS completo do domínio AD**, estruturado hierarquicamente.

Exemplo:

```
skill.ceh.com
```

Isso representa:

* Um domínio DNS válido
* Integrado ao AD
* Resolvido globalmente

---

# 3️⃣ Por que o **LDAP mostra o DNS Tree Name**?

### 🔑 Porque o LDAP **é o banco de dados do AD**

Active Directory **é literalmente um diretório LDAP**.

Quando você consulta o LDAP do DC, ele responde:

* Qual domínio ele gerencia
* Qual floresta ele pertence
* Qual namespace DNS ele usa

Por isso aparece no banner:

```
Microsoft Windows Active Directory LDAP
Domain: SKILL.CEH.COM
```

📌 Isso não é “informação extra” — é **informação estrutural obrigatória**.

---


# 5️⃣ Por que o Nmap consegue ver isso “sem autenticação”?

Porque:

* LDAP expõe informações **públicas do domínio**
* SMB anuncia o domínio para permitir logon
* Isso é **by design** no Windows

👉 Por isso DCs são **alvos de fingerprinting**.

---

# 6️⃣ Onde cada informação aparece tecnicamente

| Serviço  | Porta | Informação         |
| -------- | ----- | ------------------ |
| NetBIOS  | 139   | NetBIOS domain     |
| SMB      | 445   | Workgroup / Domain |
| LDAP     | 389   | DNS Tree / Forest  |
| Kerberos | 88    | Realm (DNS-based)  |

---

# 7️⃣ Por que isso é importante em pentest / CEH

Porque só olhando banners você consegue:

* Identificar DC
* Saber o domínio
* Planejar ataques AD (Kerberoasting, AS-REP, LDAP enum)

Sem autenticação.
