## **1️⃣ Tipos de registros DNS**

### **A (Address Record)**

* **O que é:** Mapeia um **nome de domínio para um endereço IPv4**.
* **Exemplo:** `example.com → 93.184.216.34`
* **Consulta com dig:**

```bash
dig A example.com +short
```

* **Quando usar:**

  * Descobrir o **IP principal de um domínio**
  * Reconhecimento e scan de hosts

---

### **AAAA (IPv6 Address Record)**

* **O que é:** Igual ao registro A, mas para **endereços IPv6**.
* **Exemplo:** `example.com → 2606:2800:220:1:248:1893:25c8:1946`
* **Consulta com dig:**

```bash
dig AAAA example.com +short
```

* **Quando usar:**

  * Auditoria de redes modernas com IPv6
  * Descobrir possíveis pontos de entrada

---

### **MX (Mail Exchange Record)**

* **O que é:** Indica os **servidores de email** responsáveis por receber mensagens do domínio.
* **Exemplo:**

```
example.com MX 10 mail.example.com
```

* `10` = prioridade
* **Consulta com dig:**

```bash
dig MX example.com +short
```

* **Quando usar:**

  * Reconhecimento de servidores de email
  * Testes de phishing, spoofing ou email enumeration

---

### **NS (Name Server Record)**

* **O que é:** Indica os **servidores DNS autoritativos** do domínio.
* **Exemplo:**

```
example.com NS ns1.example.com
example.com NS ns2.example.com
```

* **Consulta com dig:**

```bash
dig NS example.com +short
```

* **Quando usar:**

  * Mapear quem **controla o DNS do domínio**
  * Verificar possíveis vulnerabilidades de DNS (zone transfer, subdomain takeover)

---

### **TXT (Text Record)**

* **O que é:** Permite armazenar **qualquer texto** no DNS.
* Muitas vezes usado para:

  * SPF, DKIM, DMARC (autenticação de email)
  * Verificações de domínio (ex.: Google, Office365)
* **Exemplo:**

```
example.com TXT "v=spf1 include:_spf.google.com ~all"
```

* **Consulta com dig:**

```bash
dig TXT example.com +short
```

* **Quando usar:**

  * Coletar informações de configuração
  * Reconhecimento de email e segurança do domínio

---

## **2️⃣ Possível otimização nos comandos `dig`**

Seu comando original foi:

```bash
dig NS certifiedhacker.com +short
```

Algumas formas de **otimizar ou estender**:

1. **Todos os tipos de registro de uma vez**:

```bash
for type in A AAAA MX NS TXT; do
  echo "=== $type ==="
  dig $type certifiedhacker.com +short
done
```

* **Benefício:**

  * Um único comando lista todos os registros importantes para reconnaissance

---

2. **Resolver IPs dos NS automaticamente**:

```bash
dig NS certifiedhacker.com +short | xargs dig +short
```

* Retorna os **IPs dos name servers**, útil para pentest ou scan direto

---

3. **Checar autoridade e SOA**:

```bash
dig certifiedhacker.com NS +noall +authority
```

* Mostra **quais NS realmente respondem autoritativamente**

---

4. **Ferramenta alternativa: `host`**

```bash
host -t NS certifiedhacker.com
host -t MX certifiedhacker.com
host -t TXT certifiedhacker.com
```

* Mais simples, legível, funciona bem em scripts rápidos

---

💡 **Resumo rápido sobre tipos:**

| Tipo | O que retorna                | Uso                                  |
| ---- | ---------------------------- | ------------------------------------ |
| A    | IPv4 do domínio              | Scanning, pentest, recon de host     |
| AAAA | IPv6 do domínio              | Recon IPv6, auditoria moderna        |
| MX   | Servidores de email          | Phishing, spoofing, enum email       |
| NS   | Servidores DNS               | Zone transfer, takeover, DNS recon   |
| TXT  | Texto (SPF/DKIM/DMARC/infos) | Segurança email, verificação domínio |

---

## **O que significa “servidores DNS autoritativos”**

1. **Definição simples:**

Um **servidor DNS autoritativo** é aquele que **tem a autoridade oficial sobre um domínio**.

* Ele **conhece de fato todos os registros DNS do domínio** (A, MX, TXT, etc.)
* Diferente de um **servidor DNS recursivo**, que só “pergunta para outros servidores” até encontrar a resposta.

---

2. **Exemplo do mundo real:**

Imagine o domínio `certifiedhacker.com`:

* O **NS record** diz:

```
NS ns1.bluehost.com
NS ns2.bluehost.com
```

* Isso significa que os **servidores `ns1.bluehost.com` e `ns2.bluehost.com` são autoritativos**, ou seja:

  * Se você perguntar para eles “qual é o IP de [www.certifiedhacker.com?”](http://www.certifiedhacker.com?”), eles **dão a resposta oficial**.
  * Servidores DNS de outras redes podem ter **cópias cacheadas**, mas a informação oficial vem **desses autoritativos**.

---

3. **Por que isso importa em pentest / CEH:**

* **Zone transfer**:

  * Se o servidor autoritativo estiver mal configurado, você pode baixar **todos os registros do domínio** usando `dig AXFR @ns1.bluehost.com certifiedhacker.com`.
* **Subdomain takeover / recon**:

  * Saber os NS autoritativos permite identificar servidores ou serviços que **estão diretamente sob controle do domínio**.
* **Evita dados falsos do cache**:

  * Servidores recursivos podem ter registros desatualizados.
  * Perguntar direto ao autoritativo garante informação **real e atual**.
