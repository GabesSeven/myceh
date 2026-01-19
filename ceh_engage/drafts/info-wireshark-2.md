# 🎯 O que o desafio realmente pede

> **Determine the UDP based application layer protocol**
> **Note: Check for target Destination port**

📌 Tradução prática:

* É **DoS**
* É **UDP flood**
* O protocolo **não está no payload**, está **implícito pela porta de destino**
* O CEH quer que você **associe porta UDP → aplicação**

Formato:

```
Aaaaa Aaaaaaa Aaaaaaaa
```

---

# 🧠 Lógica correta de investigação (visão macro)

```text
PCAP
↓
Muito tráfego UDP
↓
Mesmo destino
↓
Mesma porta de destino
↓
Mapear porta → aplicação conhecida
```

👉 Você seguiu exatamente isso.

---

# 🔍 Por que cada passo funciona

---

## 1️⃣ Identificar que é um ataque de flood

Você observou algo como:

```
9850 → 26000 Len=0
```

📌 Isso indica:

* Muitos pacotes
* Mesmo destino
* Payload vazio ou mínimo
* UDP (sem handshake)

👉 **Padrão clássico de UDP flood**

---

## 2️⃣ Focar no protocolo UDP

Filtro correto:

```wireshark
udp
```

Depois refinar:

```wireshark
udp.dstport == 26000
```

📌 Isso elimina:

* Tráfego TCP
* DNS, DHCP, etc.
* Qualquer ruído fora do ataque

---

## 3️⃣ Por que olhar a **porta de destino**

O próprio desafio avisa:

> **Check for target Destination port**

Porque em UDP flood:

* A aplicação alvo é identificada **pela porta**
* O payload geralmente é irrelevante ou inexistente

👉 Aqui, **26000/UDP** é a assinatura.

---

## 4️⃣ Mapeamento da porta 26000/UDP

A porta **26000/UDP** é **comumente associada a**:

```
Quake Arena Server
(Quake III Arena)
```

📌 Muito usado em:

* Labs CEH
* Exemplos clássicos de UDP flood
* Ataques a servidores de jogos

👉 Por isso o nome aparece quando você pesquisa:

> “26000 udp protocol”

---

# ✅ Resposta correta do desafio

```
Quake Arena Server
```

✔ 3 palavras
✔ Capitalização compatível
✔ Exatamente o que o CEH espera

---

# ⚡ Como otimizar ainda mais no Wireshark

## 🥇 Caminho MAIS RÁPIDO (sem Google)

### 📊 Statistics → Conversations → UDP

Você veria:

* Um destino dominante
* Porta **26000** disparada

👉 Em **2 cliques** você já sabe a porta-alvo.

---

## 🥈 Statistics → Endpoints → UDP

Mostra:

* IP atacado
* Volume absurdo de pacotes
* Porta associada

---

## 🥉 IO Graph (visual)

```text
Statistics → IO Graphs
```

* Mostra pico absurdo de UDP
* Confirma flood visualmente
* Reforça que é DoS, não tráfego legítimo

---

## 🥈 Decode As (didático, mas não necessário)

Você pode:

* Botão direito no pacote
* **Decode As…**
* Ver que não há protocolo superior válido

👉 Reforça que a **aplicação é inferida pela porta**, não pelo conteúdo.

---

# 🧠 Por que o CEH escolhe Quake Arena

* UDP
* Porta fixa
* Sem criptografia
* Histórico real de UDP flood
* Fácil de identificar em PCAP

👉 Eles testam **conhecimento de portas + análise de tráfego**, não reverse engineering.

---

# 🧠 Checklist mental CEH (guarda isso)

```text
PCAP
↓
UDP flood?
↓
Qual porta de destino?
↓
Mapear porta → aplicação
↓
Responder nome do protocolo
```

---

# ❌ Erros comuns (que você NÃO cometeu)

* ❌ Procurar assinatura no payload
* ❌ Analisar TCP
* ❌ Ignorar a dica “Destination port”
* ❌ Responder “UDP Flood” (isso é o tipo de ataque, não o protocolo)


---

# 🎮 O que é **Quake Arena Server**?

**Quake Arena Server** é o **servidor multiplayer do jogo Quake III Arena**, um jogo de tiro em primeira pessoa muito popular no fim dos anos 90 e início dos anos 2000.

Tecnicamente, ele é:

* Um **servidor de aplicação**
* Baseado em **UDP**
* Com **porta padrão 26000/UDP**

---

# 🧠 Por que ele aparece em desafios de DoS?

Porque o **protocolo do Quake III Arena** tem características ideais para **UDP flood**:

### 🔹 1. Usa UDP puro

* Sem handshake
* Sem controle de sessão
* Servidor responde rápido ou tenta processar pacotes inválidos

👉 Perfeito para sobrecarregar CPU/banda.

---

### 🔹 2. Porta fixa e conhecida

```
26000/UDP
```

* Facilita ataques automatizados
* Ferramentas antigas de stress test já vinham prontas

---

### 🔹 3. Histórico real de ataques

Nos anos 2000:

* Muitos servidores de jogos foram alvo de DoS
* Quake III era um dos alvos mais comuns

👉 Por isso virou **exemplo clássico em segurança**.

---

# 🔍 Do ponto de vista de rede (o que você viu no PCAP)

Você observou:

```
Src Port: 9850 → Dst Port: 26000
Len=0
```

Isso significa:

* O atacante **não está jogando**
* Está só mandando pacotes vazios
* Tentando consumir recursos do servidor

👉 Isso é **UDP Flood direcionado à porta do Quake Arena**.

---

# 🧠 Importante: isso NÃO significa que o alvo roda Quake

Esse é um ponto sutil, mas essencial.

❗ **O desafio NÃO diz que o servidor era um servidor de jogo.**

Ele diz:

> “Determine the UDP based application layer protocol which attacker employed”

Ou seja:

* O atacante **simulou tráfego de Quake**
* Usou **a porta e padrão do protocolo**
* Para causar DoS

👉 Mesmo que o serviço real nem exista.

---

# 📌 Analogia simples

Imagine:

* Porta 80 → HTTP
* Alguém faz flood na porta 80
* Mesmo que não haja site, você chama de **HTTP flood**

Aqui é a mesma coisa:

* Porta 26000 → Quake Arena
* Flood nessa porta → **Quake Arena Server protocol abuse**

---

# 🧠 Por que o CEH cobra isso?

Porque eles querem testar se você:

* Reconhece protocolos **pela porta**
* Entende **camada de aplicação**
* Sabe diferenciar:

  * Tipo de ataque (UDP flood)
  * Protocolo explorado (Quake Arena Server)

---

# 📋 Resumo mental definitivo

```text
Quake Arena Server
= protocolo de jogo
= UDP
= porta 26000
= historicamente usado em DoS
```