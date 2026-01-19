# 🎯 O que o desafio realmente pede

> **Determine the IP address of the attacker trying to attack the target server through UDP**

📌 Pontos-chave:

* Ataque **DDoS**
* Protocolo **UDP**
* O atacante é quem **envia** o volume anormal de pacotes
* A resposta é **o IP de origem**

---

# 🧠 Lógica geral correta (visão macro)

```text
PCAP
↓
Filtrar UDP
↓
Identificar fluxo dominante
↓
Quem envia mais pacotes?
↓
Esse IP = atacante
```

👉 Você seguiu exatamente esse raciocínio.

---

# 🔍 Por que cada passo funciona

---

## 1️⃣ Abrir o PCAP no Wireshark

```bash
wireshark DD_attack.pcapng
```

📌 Você precisa da **visão temporal completa** do tráfego.

---

## 2️⃣ Aplicar filtro `udp`

```wireshark
udp
```

### 🧠 Por quê?

* O desafio **define explicitamente UDP**
* Remove:

  * TCP
  * ARP
  * DNS (se não UDP flood)
  * Outros ruídos

👉 Reduz o dataset **drasticamente**.

---

## 3️⃣ Statistics → Conversations

### 🧠 Por quê?

Essa tela mostra:

* Quem fala com quem
* Volume de pacotes
* Bytes transmitidos

Em ataques DDoS:

* Um IP ou grupo envia **muito mais pacotes**
* O alvo geralmente só responde pouco ou nada

👉 Conversações revelam isso **instantaneamente**.

---

## 4️⃣ Interpretar “Address A → 192.168.10.144”

No contexto do Wireshark:

* **Address A** = origem do tráfego
* **Address B** = destino

Se:

* Address A → muitos pacotes UDP
* Address B → servidor Ubuntu

➡️ **Address A é o atacante**

---

# ⚡ Como otimizar ainda mais (menos cliques)

## 🥇 Método mais rápido possível (30 segundos)

### 📊 Statistics → Endpoints → UDP

Você verá:

* Lista de IPs
* Contagem absurda de pacotes em um IP

👉 Esse IP = atacante

---

## 🥈 IO Graph (confirmação visual)

```text
Statistics → IO Graphs
```

* Linha UDP explode em determinado momento
* Clique no ponto → identifica IP ativo

---

## 🥉 Display filter direto (manual)

```wireshark
udp && ip.src == 192.168.10.144
```

Veja:

* Enxurrada de pacotes
* Confirma o ataque

---

# 🧠 Por que o CEH escolhe esse método

Porque ele testa se você:

* Entende **origem vs destino**
* Sabe usar **estatísticas**, não só filtros
* Consegue identificar ataque **sem payload**

---

# ❌ Erros comuns (que você evitou)

* ❌ Confundir atacante com vítima
* ❌ Olhar só para destino
* ❌ Analisar payload
* ❌ Procurar assinatura de aplicação

---

# 🧠 Checklist mental CEH (guarda isso)

```text
Ataque UDP?
↓
Filtrar UDP
↓
Conversations / Endpoints
↓
Quem envia mais?
↓
IP atacante
```

---

# 🧠 Conclusão

* Sua lógica foi **perfeita**
* Você usou a ferramenta certa
* Estatísticas são **mais rápidas que inspeção manual**
* Esse desafio mede **análise de tráfego sob ataque**

---

## ✅ Resposta correta

```
192.168.10.144
```

---

# 🔍 O que significa **192.168.10.144 enviando ~1000 pacotes para portas 49000–49999**

## 🧠 Interpretação direta

Isso caracteriza um:

> **UDP Flood com varredura de portas altas (ephemeral ports)**

Ou, em termos mais práticos:

* Um host **disparando pacotes UDP em alta taxa**
* Para **múltiplas portas**
* Sem handshake
* Sem resposta esperada

👉 Isso **não é tráfego legítimo**.

---

# 🎯 Por que portas 49000–49999?

## 📌 Portas efêmeras

* Intervalo típico de portas **dinâmicas**
* Usadas temporariamente por aplicações
* Geralmente **não têm serviço escutando**

👉 Mandar tráfego para essas portas:

* Força o SO a processar pacotes inúteis
* Gera:

  * Consumo de CPU
  * Tabelas de estado
  * ICMP Port Unreachable (em alguns casos)

---

# ⚠️ Assinatura clássica de ataque UDP

| Comportamento | Normal   | Ataque     |
| ------------- | -------- | ---------- |
| Porta destino | Fixa     | Aleatória  |
| Volume        | Baixo    | Muito alto |
| Resposta      | Esperada | Nenhuma    |
| Intervalo     | Regular  | Rajadas    |

👉 O padrão **49000–49999** + **~1000 pacotes** é **ruído artificial**.

---

# 🔬 Como confirmar isso tecnicamente (Wireshark)

### 🔹 Filtro ideal

```wireshark
udp && ip.src == 192.168.10.144 && udp.dstport >= 49000 && udp.dstport <= 49999
```

Você verá:

* Fluxo contínuo
* Pacotes pequenos ou vazios
* Sem respostas consistentes

---

### 🔹 Em Statistics → Conversations

* Muitas conversas
* Poucos bytes por conversa
* Tempo curto

👉 Clássico flood.

---

# 🧠 Isso é DDoS ou DoS?

Tecnicamente:

* **DoS** → 1 atacante
* **DDoS** → múltiplos atacantes

📌 O desafio chama de DDoS porque:

* É genérico
* CEH usa o termo de forma **didática**
* Nem sempre há múltiplos IPs no lab

👉 Na prática do lab:

> **É um UDP flood (DoS)**

---

# 🧪 Por que o payload não importa aqui?

Porque:

* UDP flood **não precisa payload**
* O impacto vem do **volume**, não do conteúdo

---

# 🧠 O que o CEH está avaliando nesse desafio

Você identificou TODOS os pontos certos:

✔ IP de origem
✔ Protocolo UDP
✔ Volume anormal
✔ Múltiplas portas
✔ Padrão de flood

👉 Isso mostra **entendimento real**, não só execução de ferramenta.

---

# 📋 Como você explicaria isso em uma prova (modelo perfeito)

> *The attacker (192.168.10.144) generated a high volume of UDP packets targeting multiple high-range ephemeral ports (49000–49999), which is a typical signature of a UDP flood attack intended to exhaust system and network resources of the target server.*

---

# ✅ Conclusão definitiva

* **192.168.10.144 é o atacante**
* O ataque é **UDP Flood**
* Portas altas = estratégia de exaustão
* Volume confirma o ataque
