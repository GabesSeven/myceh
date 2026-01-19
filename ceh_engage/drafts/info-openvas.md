# 🔍 OpenVAS / GVM no Pentest (CEH – visão prática)

## O que é o OpenVAS?

OpenVAS (hoje **Greenbone Vulnerability Management – GVM**) é um **scanner de vulnerabilidades** que:

* Detecta **falhas conhecidas (CVEs, misconfigs, weak services)**
* Correlaciona:

  * Porta
  * Serviço
  * Versão
  * Configuração
* Usa **NVTs (Network Vulnerability Tests)** atualizados constantemente

📌 No ciclo de pentest (CEH):

```
Recon → Scan → Enum → Vulnerability Analysis → Exploit
                ↑
             OpenVAS
```

---

# 🧠 Conceitos-chave que o CEH cobra

## Severity (Severidade)

Baseada em **CVSS**:

| Severidade | CVSS       |
| ---------- | ---------- |
| Low        | 0.1 – 3.9  |
| Medium     | 4.0 – 6.9  |
| High       | 7.0 – 8.9  |
| Critical   | 9.0 – 10.0 |

---

## QoD – Quality of Detection

> **Confiança do scanner naquela vulnerabilidade**

| QoD    | Significado                          |
| ------ | ------------------------------------ |
| 30–50% | Detecção fraca (banner / heurística) |
| 60–70% | Provável                             |
| 80–90% | Alta confiança                       |
| 100%   | Confirmado (exploit / autenticação)  |

📌 **O desafio 14 pede exatamente isso**.

---

# 🧪 Desafio 14 — Linux host + QoD (Medium)

## 🎯 Objetivo

> Encontrar **QoD (%)** de uma vulnerabilidade **Medium** em um **host Linux** dentro de `192.168.10.0/24`

---

### 5️⃣ Analisar Resultados (Results)

#### Filtros:

* **Severity:** Medium
* **OS:** Linux

📌 Agora você:

* Clica em qualquer vulnerabilidade Medium
* Observa o campo **QoD**

🔎 Resultado encontrado:

```
QoD: 70%
```

✅ **Resposta do desafio 14:**
**70**

---

# 🧪 Desafio 15 — Vulnerabilidade FTP (host específico)

## 🎯 Objetivo

> Identificar **qual vulnerabilidade relacionada a FTP** existe no host
> `192.168.10.144`

---

## 🔧 Passo a passo otimizado

### 1️⃣ Criar Target específico

* **Name:** FTP-192.168.10.144
* **Host:** `192.168.10.144`

📌 Por quê?

* Evita ruído
* Scan mais rápido
* Resposta direta pro desafio

---

### 2️⃣ Criar nova Task

* **Scan Config:** Full and fast
* **Target:** FTP-192.168.10.144

---

### 3️⃣ Executar o Scan

Aguardar finalização.

---

### 4️⃣ Filtrar Resultados

#### Use filtros:

* **Port:** 21
* **Service:** FTP
* **Severity:** Medium / High

---

### 5️⃣ Vulnerabilidade encontrada

```text
FTP Unencrypted Cleartext Login
```

📌 O que isso significa:

* Credenciais trafegam em **texto puro**
* Sniffing trivial (tcpdump, Wireshark)
* Ataques MITM viáveis

---

## ✅ Resposta do desafio 15

```
FTP Unencrypted Cleartext Login
```

---

# 🧠 Por que o OpenVAS encontrou isso?

* Serviço FTP ativo
* Sem:

  * FTPS
  * TLS
  * SSH (SFTP)
* Banner revela uso inseguro

---

# 🧩 Mapeamento CEH / Pentest Real

| Item            | CEH             | Mundo real            |
| --------------- | --------------- | --------------------- |
| QoD             | Pergunta direta | Confiança do finding  |
| Medium severity | Prova           | Prioridade média      |
| FTP cleartext   | Teoria          | Achado clássico       |
| OpenVAS         | Ferramenta CEH  | GVM padrão enterprise |

---

# 📌 Resumo ultra-sintetizado (pra revisão)

```
OpenVAS:
- Scanner de vulnerabilidades
- Usa NVTs
- Classifica por Severity e QoD

Desafio 14:
- Filtrar Medium
- Ler QoD → 70%

Desafio 15:
- Filtrar FTP
- Vulnerabilidade → FTP Unencrypted Cleartext Login
```
