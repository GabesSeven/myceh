# 🧠 CONTEXTO GERAL DOS DESAFIOS

Você está atuando como **Web AppSec / Pentester**, e os dois desafios giram em torno de:

* **histórico de vulnerabilidades (CVEs)**
* **controles defensivos ausentes**
* **análise passiva (sem ataque agressivo)**

Ferramenta escolhida: **OWASP ZAP**
👉 Excelente escolha — é exatamente o que a EC-Council espera aqui.

---

# 🧩 Challenge 9 — Ataque associado aos CVEs mais antigos

## 📌 O que a questão quer de verdade

> *“Identify the attack category of the oldest CVEs affected the website”*

Isso **não** significa:

* listar CVEs específicos
* nem explorar a falha

Significa:
✅ **entender QUAL TIPO DE ATAQUE aparece primeiro no histórico de falhas do site**

Ou seja:

> “Qual classe de ataque é recorrente / antiga nesse site?”

---

## 🔍 Como você descobriu isso (corretamente)

No OWASP ZAP:

1. **Scan automático**
2. Análise dos **Alerts**
3. Alertas do tipo:

   ```
   User Controllable HTML Element Attribute
   ```
4. Descrição citando explicitamente:

   ```
   Cross-Site Scripting (XSS)
   ```

📌 **XSS é historicamente uma das vulnerabilidades mais antigas da web**

* presente desde os primórdios do HTML dinâmico
* aparece nos primeiros CVEs web (anos 2000)

---

## ✅ Resposta correta (formato esperado)

```
cross-site scripting (XSS)
```

📎 Mesmo se o site tiver SQLi, CSRF etc., **o alerta mais antigo e recorrente foi XSS**, então é isso que a banca quer.

---

# 🧩 Challenge 10 — Política de segurança ausente

## 📌 O que a questão quer

> *“Identify the type of security policies is missing to detect and mitigate XSS and SQL Injection attacks”*

Aqui não é ataque, é **defesa**.

A pergunta é:

> *Qual mecanismo de segurança deveria existir, mas NÃO existe?*

---

## 🔍 Sua análise no ZAP

Alert encontrado:

```
Content Security Policy (CSP) Header Not Set
```

* Tipo: **Passive**
* Plugin ID: 10038

📌 CSP é um **header HTTP defensivo**

* não bloqueia SQLi diretamente
* **mitiga fortemente XSS**
* impede execução de JS injetado
* reduz impacto de payloads maliciosos

---

## ✅ Resposta correta

```
Content Security Policy
```

💡 A banca aceita CSP porque:

* é padrão moderno
* é política de segurança
* aparece claramente no ZAP

---

# ⚙️ OWASP ZAP — Explicação da ferramenta (o que você usou)

## 🧰 O que é o OWASP ZAP

**Zed Attack Proxy**

* Proxy de interceptação
* Scanner automatizado
* Scanner passivo
* Ferramenta OWASP Top 10

Usado para:

* encontrar falhas web
* validar headers
* detectar XSS, SQLi, CSRF
* revisar políticas de segurança

---

## 🔹 Funcionalidades principais (importante pra prova)

### 1️⃣ Automated Scan

* Crawl + análise automática
* Ideal para labs CEH
* Não exige configuração profunda

---

### 2️⃣ Passive Scan

* **Não envia payload**
* Analisa respostas HTTP
* Detecta:

  * CSP ausente
  * headers inseguros
  * cookies fracos
  * XSS refletido básico

📌 Seus desafios **usam majoritariamente Passive Scan**

---

### 3️⃣ Alerts

Classificados por:

* High
* Medium
* Low
* Informational

Cada alerta traz:

* Descrição
* Evidência
* CWE
* OWASP Top 10
* Solução sugerida

---

### 4️⃣ Headers Analysis

ZAP verifica:

* CSP
* X-Frame-Options
* X-XSS-Protection
* X-Content-Type-Options

👉 Exatamente o que caiu no Challenge 10.

---

### 5️⃣ Attack Categories (importante pro Challenge 9)

ZAP classifica falhas como:

* XSS
* SQL Injection
* Path Traversal
* Insecure Headers
* Authentication Issues

Você usou isso **implicitamente**, e está certo.

---

# 🚀 OTIMIZAÇÕES (se quiser ir mais direto)

### 🔹 Para Challenge 9 (mais rápido)

Você poderia focar direto em:

* Alerts relacionados a **XSS**
* Sem rodar scan agressivo
* Apenas Passive + Alerts

---

### 🔹 Para Challenge 10 (ultra objetivo)

Ver só:

* `Response Headers`
* Se existe `Content-Security-Policy`

Sem scan completo.

---

# 🔴 CVE-2020-11022

### 📌 O que é

Uma **vulnerabilidade de Cross-Site Scripting (XSS)** no **jQuery** (antes da versão 3.5.0).

---

### 🧠 Causa técnica

O jQuery permitia que **HTML não confiável** fosse interpretado como código executável ao usar funções como:

```js
.html()
.append()
.before()
.after()
```

Se dados do usuário fossem passados diretamente para essas funções → **XSS**.

---

### 💥 Impacto

* Execução de JavaScript malicioso
* Roubo de cookies
* Sequestro de sessão
* Keylogging

---

### 🧪 Exemplo simplificado

```js
$("#div").html("<img src=x onerror=alert(1)>")
```

---

### 🎯 Classificação

* **Tipo:** Cross-Site Scripting
* **Gravidade:** Alta
* **Categoria CEH:** Client-side attack

---

# 🔴 CVE-2020-11023

### 📌 O que é

Outra **XSS no jQuery**, muito parecida com a anterior, mas **em outro caminho de parsing**.

---

### 🧠 Diferença em relação à 11022

* Explora **manipulação de atributos HTML**
* Bypass de sanitização
* Ataques mais “silenciosos”

---

### 💥 Impacto

Mesmos efeitos:

* Execução arbitrária de JS
* Sessão comprometida
* Phishing via DOM

---

### 🎯 Classificação

* **Tipo:** Cross-Site Scripting
* **Relacionada diretamente à CVE-2020-11022**

📌 **Na prova:** se aparecer uma, pense automaticamente em **XSS via jQuery**.

---

# 🔴 CVE-2015-9251

### 📌 O que é

Uma **XSS MUITO antiga** (2015) também relacionada ao **jQuery**.

---

### 🧠 Causa técnica

O jQuery aceitava **URLs do tipo `javascript:`** ao usar:

```js
jQuery.ajax()
```

Isso permitia:

```js
$.ajax("javascript:alert(1)")
```

😬 Resultado: XSS.

---

### 💥 Impacto

* Execução de código
* Ataques persistentes
* Muito explorada em apps antigos

---

### 🎯 Importância histórica

Essa CVE é frequentemente citada como:

> **Uma das XSS mais antigas e exploradas do jQuery**

Perfeita para **Challenge 9 da Part 3**.

---

## 🧠 CONEXÃO DIRETA COM SEU DESAFIO

| CVE            | Tipo |
| -------------- | ---- |
| CVE-2020-11022 | XSS  |
| CVE-2020-11023 | XSS  |
| CVE-2015-9251  | XSS  |

📌 **Todas levam à mesma resposta:**

```
cross-site scripting (XSS)
```

---

## 🧠 POR QUE ISSO CAI NA CEH?

Porque:

* jQuery está em **milhões de sites**
* XSS é **OWASP Top 10 recorrente**
* CVEs antigas = **arquiteturas legadas**
* CSP ausente = vulnerável

---

## 🧩 LIGAÇÃO COM O DESAFIO 10

| Vulnerabilidade | Defesa                  |
| --------------- | ----------------------- |
| XSS             | Content Security Policy |
| JS Injection    | CSP                     |
| DOM-based XSS   | CSP                     |

---

## 🧠 FRASE DE PROVA (SE PEDIR DESCRITIVO)

> *The CVEs are related to Cross-Site Scripting (XSS) vulnerabilities in jQuery that allow execution of arbitrary JavaScript code.*