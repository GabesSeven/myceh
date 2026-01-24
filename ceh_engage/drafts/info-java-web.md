## 📌 Contexto do desafio

> *You have identified a vulnerable web application running on a Linux server at port 8080.*

Algumas pistas **bem importantes** já aparecem aqui:

### 🔍 Pistas-chave do enunciado

* **Linux server**
* **Porta 8080**
* **JSP / Servlet**
* **Web application**

Esses quatro elementos juntos praticamente **gritam** uma coisa 👇

---

## 🧠 JSP / Servlet → quem hospeda isso?

### JSP (JavaServer Pages) e Servlets:

* São tecnologias **Java**
* Não rodam em Apache puro
* Precisam de um **Servlet Container**

### Exemplos de Servlet Containers:

| Tecnologia         | Usa JSP/Servlet |
| ------------------ | --------------- |
| Apache Tomcat      | ✅               |
| JBoss / WildFly    | ✅               |
| WebLogic           | ✅               |
| WebSphere          | ✅               |
| Apache HTTP Server | ❌               |
| Nginx              | ❌               |

👉 **O mais comum, principalmente na porta 8080, é o Apache Tomcat**

---

## 🔎 Análise do que você fez

### 1️⃣ `whatweb`

```bash
whatweb http://172.30.10.99:8080
```

✔️ Ótimo para fingerprinting rápido
✔️ Detecta frameworks, headers e tecnologias
⚠️ Às vezes não mostra a versão completa

---

### 2️⃣ `nmap -sV`

```bash
nmap -p 8080 172.30.10.99 -sV --open
```

📌 Aqui está o **ponto-chave da resposta**:

```
8080/tcp open  http  Apache Tomcat/Coyote JSP engine 1.1
```

Isso nos diz:

* **Apache Tomcat** → Servlet Container
* **Coyote** → HTTP Connector do Tomcat
* **JSP engine** → confirma JSP/Servlet
* **Porta 8080** → padrão do Tomcat

---

## ✅ Resposta esperada pelo desafio

Formato pedido:

```
Aaaaaa*Aaaaaa*Aaaaaa*AAA*aaaaaa*N*N
```

Correspondência direta com o banner:

```
Apache*Tomcat*Coyote*JSP*engine*1*1
```

✔️ Sua identificação está **100% correta**

---

## 🧩 O que o desafio realmente testa?

Esse desafio **não é sobre exploração**, é sobre:

✅ **Service Fingerprinting**
✅ **Reconhecer tecnologias Java Web**
✅ **Associar porta + stack correta**
✅ **Saber que JSP ≠ Apache HTTP Server**

Em CEH isso cai MUITO.

---

## 🚀 Otimizações (práticas e para prova)

### 🔹 1️⃣ Nmap mais focado (mais rápido)

```bash
nmap -p 8080 -sV --version-light 172.30.10.99
```

✔️ Mais rápido
✔️ Menos ruído
✔️ Ideal em prova

---

### 🔹 2️⃣ Script NSE específico para HTTP

```bash
nmap -p 8080 --script http-title,http-server-header 172.30.10.99
```

Você pode ver:

* Headers
* Títulos
* Pistas de framework

---

### 🔹 3️⃣ Curl direto no header (bem CEH-like)

```bash
curl -I http://172.30.10.99:8080
```

Normalmente retorna algo como:

```
Server: Apache-Coyote/1.1
```

Só isso já mata o desafio 😄

---

### 🔹 4️⃣ WhatWeb com agressividade

```bash
whatweb -a 3 http://172.30.10.99:8080
```

Mais fingerprints, mais certeza.

---

## ⚠️ Erro comum (que você NÃO cometeu)

❌ Responder apenas:

```
Apache
```

Isso estaria **errado**, porque:

* Apache HTTP Server ≠ Servlet Container
* JSP não roda nativamente no Apache

