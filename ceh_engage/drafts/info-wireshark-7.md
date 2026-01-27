# 🧠 CONTEXTO DO DESAFIO (O “POR QUÊ”)

### 🏭 Cenário

* A CEHORG usa **IoT e sensores** para logística / supply chain
* Sensores publicam dados (ex: umidade, temperatura)
* Comunicação feita via **MQTT**
* Um alerta foi disparado: **High_humidity**

🎯 Sua missão:

> **extrair o valor de alerta (%) contido na mensagem MQTT**

📌 Isso simula:

* monitoramento industrial
* segurança em ambientes OT/IoT
* análise de tráfego de sensores comprometidos ou mal configurados

---

# 🧩 O QUE É MQTT (RÁPIDO, MAS FUNDAMENTAL)

**MQTT (Message Queuing Telemetry Transport)** é:

* protocolo **leve**
* baseado em **publish / subscribe**
* muito usado em **IoT**
* roda geralmente sobre **TCP (porta 1883)**

📌 Componentes principais:

* **Publisher** → sensor (ex: umidade)
* **Broker** → servidor MQTT
* **Subscriber** → sistema de monitoramento

---

# 🔍 EXPLICAÇÃO DO SEU FLUXO (PASSO A PASSO)

## 1️⃣ Abrir o arquivo

```bash
wireshark ~/MQTT.pcapng
```

📌 Você entra no modo de **análise forense**, não em tempo real.

---

## 2️⃣ Filtrar apenas MQTT

```wireshark
mqtt
```

🎯 Por quê?

* Remove ruído (ARP, TCP handshake, DNS…)
* Mostra apenas **mensagens IoT**
* Facilita identificar **Publish**

📌 Extremamente correto para esse desafio.

---

## 3️⃣ Identificar a mensagem relevante

```text
Publish Message (id=2) [High_humidity]
```

📌 MQTT **Publish** é onde os dados vivem.
📌 O tópico `High_humidity` indica:

* evento
* alerta
* condição fora do normal

---

## 4️⃣ Seguir o fluxo TCP

```text
Follow → TCP Stream
```

🎯 Por quê?

* MQTT carrega payload dentro do TCP
* Wireshark mostra o **conteúdo completo da mensagem**
* Remove fragmentação

📌 Aqui você vê o **payload real**.

---

## 5️⃣ Extração do valor

```text
High_humidity..Alert for rise in humidity(50 percentage)
```

🎯 Informação clara:

* alerta de umidade
* **50%**

💬 **Resposta correta**

```
50
```

---

# ✅ POR QUE SUA RESOLUÇÃO ESTÁ CERTA

✔ Usou filtro correto
✔ Identificou mensagem MQTT
✔ Analisou payload
✔ Não confundiu metadado com conteúdo

📌 Exatamente o que a banca espera.

---

# ⚙️ FORMAS DE OTIMIZAR (SEM COMPLICAR)

Você fez certo, mas há **atalhos mais rápidos**.

---

## 🔹 Alternativa 1: Sem Follow TCP Stream

Clique direto no pacote MQTT:

```text
Packet Details → MQTT → Message → Payload
```

📌 Muitas vezes o texto aparece **direto ali**.

---

## 🔹 Alternativa 2: Filtro ainda mais específico

```wireshark
mqtt.msgtype == 3
```

📌 `3` = **PUBLISH**

* elimina CONNECT, SUBSCRIBE, PING

---

## 🔹 Alternativa 3: Buscar direto por string

```wireshark
frame contains "High_humidity"
```

📌 Útil em pcaps grandes.

---

# 🧠 O QUE O CEH ESTÁ TESTANDO AQUI

Esse exercício avalia se você sabe:

✅ identificar protocolos IoT
✅ entender publish/subscribe
✅ extrair dados de payload
✅ analisar mensagens em texto claro
✅ usar Wireshark além de HTTP/TCP

📌 Muito alinhado com:

* segurança industrial
* ICS/SCADA
* ataques a sensores