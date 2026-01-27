# 🧠 CONTEXTO DO DESAFIO (O “POR QUÊ”)

### 📱 Cenário

* Um **dispositivo Android comprometido**
* Suspeita de estar sendo usado para **DoS (Denial of Service)**
* Ataque direcionado a **servidor interno**
* Evidência disponível: **And_Dos.pcapng**

🎯 Seu objetivo **NÃO** é:

* identificar IP
* identificar porta
* identificar protocolo

🎯 Seu objetivo é:

> **determinar o nível de severidade / impacto potencial do ataque**

📌 Isso é **triagem de incidente**, algo muito comum em SOC, CSIRT e resposta a incidentes.

---

# 🔍 POR QUE “EXPERT INFO” É O CAMINHO CERTO

O enunciado já entrega a pista:

> **“perform deep down Expert Info analysis”**

Ou seja:

* Não é filtro
* Não é estatística
* Não é conversa
* É **interpretação semântica do tráfego**

O CEH quer saber se você:
✅ entende **alertas do Wireshark**
✅ sabe diferenciar **Note x Warning x Error**
✅ consegue traduzir isso em **impacto de negócio**

---

# 🧰 FERRAMENTA: WIRESHARK – EXPERT INFORMATION

## Caminho que você seguiu (correto):

```text
Analyze → Expert Information
```

### O que é o **Expert Info**

É um mecanismo interno do Wireshark que:

* Analisa padrões de tráfego
* Detecta comportamentos anômalos
* Classifica problemas por **nível de severidade**

📌 Ele não “detecta ataques” como um IDS,
mas **indica sintomas técnicos** de problemas.

---

# 🚦 NÍVEIS DE SEVERIDADE NO WIRESHARK

O Wireshark classifica eventos assim:

| Nível        | Significado            |
| ------------ | ---------------------- |
| **Chat**     | Informação irrelevante |
| **Note**     | Comportamento incomum  |
| **Warning**  | Potencial problema     |
| **Error**    | Falha grave            |
| **Critical** | Impacto severo         |

---

## 🚨 O que significa **WARNING** neste contexto

No contexto de **DoS**:

**Warning indica:**

* Volume anormal de pacotes
* Retransmissões excessivas
* Pacotes fora de ordem
* Possível degradação de serviço
* **Ataque em andamento, mas sem colapso total**

📌 Ou seja:

> **O ataque existe, mas ainda não derrubou o serviço completamente**

---

# ✅ POR QUE “WARNING” É A RESPOSTA CERTA

O desafio pede:

> **severity level / potential impact**

Não pede:

* “ataque bem-sucedido”
* “serviço fora do ar”
* “critical failure”

📌 Logo:

* **Error / Critical** → só se o serviço tivesse quebrado
* **Note** → seria apenas ruído
* **Warning** → ataque real, impacto moderado

💬 **Resposta correta**

```
Warning
```

---

# 🧠 O QUE O CEH QUER TESTAR AQUI

Esse exercício avalia se você sabe:

✅ interpretar **alertas de ferramentas**
✅ não confundir **sintoma com impacto**
✅ classificar incidentes corretamente
✅ pensar como analista, não como atacante

📌 Em um SOC real:

* Nem todo ataque é crítico
* Classificar errado gera:

  * pânico desnecessário
  * incidentes mal priorizados

---

# ⚙️ OTIMIZAÇÕES (SEM SAIR DO WIRESHARK)

Você fez certo, mas dá pra aprofundar ainda mais **sem fugir do escopo**.

---

## 🔹 Filtro auxiliar para confirmar DoS

```wireshark
udp || tcp.analysis.retransmission
```

ou

```wireshark
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

📌 Isso ajuda a correlacionar:

* Warning + padrão de flood

---

## 🔹 Expert Info com foco só em Warning+

No próprio Expert Info:

* Clique em **Warning**
* Ignore Chat e Note
* Veja **protocolos afetados**

---

## 🔹 Ver correlação temporal

```text
Statistics → IO Graphs
```

Se houver:

* pico abrupto
* tráfego contínuo

👉 confirma DoS de baixa/média intensidade

---

# 🧠 Frase perfeita para prova CEH

> **A Warning level in Wireshark Expert Info indicates abnormal traffic patterns that may cause service degradation but not complete failure.**
