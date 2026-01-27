# 🧠 O QUE É *TOPIC LENGTH* NO MQTT

No **MQTT**, toda mensagem **PUBLISH** contém:

```
[ Fixed Header ]
[ Variable Header ]
[ Payload ]
```

Dentro do **Variable Header** existe obrigatoriamente:

```
Topic Name Length (2 bytes)
Topic Name (N bytes)
```

👉 **Topic Length** =
📏 **quantidade de bytes do nome do tópico**, **não** é:

* tamanho da mensagem
* tamanho do payload
* tamanho do alerta

É **somente o comprimento do nome do tópico MQTT**.

---

# 🔎 EXEMPLO PRÁTICO

Se o tópico for:

```
High_temperature
```

Vamos contar:

| Letra | Contagem |
| ----- | -------- |
| H     | 1        |
| i     | 2        |
| g     | 3        |
| h     | 4        |
| _     | 5        |
| t     | 6        |
| e     | 7        |
| m     | 8        |
| p     | 9        |
| e     | 10       |
| r     | 11       |
| a     | 12       |
| t     | 13       |
| u     | 14       |
| r     | 15       |
| e     | 16       |

➡️ **Topic Length = 16**

📌 Isso é o valor lógico, mas **na prova você deve confirmar no pacote**, não assumir.

---

# 🧪 COMO ENCONTRAR O *TOPIC LENGTH* NO WIRESHARK

## 1️⃣ Abrir o pcap

```bash
wireshark ~/MQTT.pcapng
```

---

## 2️⃣ Filtrar MQTT

```wireshark
mqtt
```

---

## 3️⃣ Localizar o pacote certo

Procure algo como:

```
Publish Message [High_temperature]
```

---

## 4️⃣ Expandir os detalhes do pacote

No painel **Packet Details**:

```
MQ Telemetry Transport Protocol
 └── Message Type: PUBLISH
     └── Topic Length: 16
     └── Topic Name: High_temperature
```

🎯 **É esse campo que a questão quer.**

---

# 📌 POR QUE O CEH COBRA ISSO?

Esse exercício testa se você:

✅ entende estrutura interna de protocolos
✅ sabe analisar **Variable Header**, não só payload
✅ consegue ler **campos binários de protocolo**
✅ não confunde dado lógico com metadado

Isso é **forense de protocolo**, não “printar tela”.

---

# ⚠️ PEGADINHAS COMUNS (PROVA)

❌ Contar caracteres sem validar no Wireshark
❌ Confundir com:

* Payload length
* Message length
* Remaining Length
  ❌ Usar valor do alerta (ex: 50%)

📌 **Sempre vale o que está no campo MQTT.**

---

# 🧠 RESUMO FINAL (ESTILO CEH)

* MQTT PUBLISH contém **Topic Length**
* Campo fica no **Variable Header**
* Mede o tamanho do **nome do tópico**
* Para `High_temperature` → **16**
* Resposta no formato NN

```
16
```
