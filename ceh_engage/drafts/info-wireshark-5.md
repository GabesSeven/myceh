# 🎯 O que o desafio realmente quer

> **Determine the attacker IP machine which is targeting the RPC service**

Pontos-chave:

* Serviço **RPC**
* Protocolo **TCP**
* Porta **135**
* Identificar **quem ataca**, não quem é atacado

---

# 🧠 Lógica da sua busca (visão correta)

```text
PCAP
↓
Isolar RPC
↓
Identificar fluxo dominante
↓
Quem inicia/concentra conexões?
↓
IP atacante
```

Você fez exatamente isso.

---

# 🔍 Por que cada passo funciona

---

## 1️⃣ Abrir o PCAP

```bash
wireshark PyD_attack.pcapng
```

📌 Permite:

* Análise temporal
* Correlação de pacotes
* Estatísticas de fluxo

---

## 2️⃣ Filtro: `tcp.port == 135`

```wireshark
tcp.port == 135
```

### 🧠 Por quê?

* **RPC Endpoint Mapper** usa **porta 135/TCP**
* Todo acesso RPC começa por ela
* Ataques RPC **sempre passam por aqui**

👉 Elimina ruído de:

* HTTP
* DNS
* SMB
* Outros serviços

---

## 3️⃣ Statistics → Conversations

### 🧠 Por quê?

Porque ataques:

* Geram **muitas tentativas**
* Criam **conversações repetitivas**
* Iniciam conexões sem sucesso

👉 O atacante aparece como:

* Origem dominante
* Muitas conexões curtas
* Pouca resposta válida

---

## 4️⃣ “Address A → 172.30.10.99”

* **Address A** = origem
* Origem concentrando tráfego RPC
* Destino = máquina alvo

➡️ **Address A = atacante**

---

# ⚡ Formas mais otimizadas (nível prova)

## 🥇 Statistics → Endpoints → TCP

* Ordene por **Packets**
* RPC flood aparece instantaneamente

---

## 🥈 Filtro ainda mais específico

```wireshark
tcp.port == 135 && tcp.flags.syn == 1 && tcp.flags.ack == 0
```

📌 Mostra:

* Tentativas de conexão
* Varredura ou brute-force RPC

---

## 🥉 Identificar ataque via falha

```wireshark
tcp.port == 135 && tcp.flags.reset == 1
```

📌 Muitos RST = conexões rejeitadas = ataque.

---

# 🧠 O que é RPC (de verdade)

## 📌 RPC – Remote Procedure Call

É um mecanismo que permite:

> Um programa executar funções em outro computador **como se fossem locais**

### Usado para:

* Active Directory
* Serviços Windows
* Administração remota
* DCOM
* WMI

---

## 🚪 Porta 135 – Endpoint Mapper

* Porta inicial do RPC
* Diz **qual porta dinâmica** o serviço real usa
* Sem ela, RPC não funciona

---

# ⚠️ Por que RPC é alvo comum de ataques?

### 1️⃣ Presente em quase todo Windows

* DCs
* Servidores
* Workstations

---

### 2️⃣ Histórico de vulnerabilidades

Exemplos famosos:

* Blaster (MS03-026)
* DCOM exploits
* Worms

---

### 3️⃣ Permite:

* Enumeração de serviços
* Execução remota
* Movimento lateral

👉 **Alvo clássico em pentest e malware**

---

# 🧪 Por que RPC aparece nesse cenário PyD_attack?

O nome do arquivo já dá pista:

> **PyD_attack**

Normalmente indica:

* Script Python
* Ataque automatizado
* Exploração RPC ou DCOM

📌 Ataques comuns:

* Varredura RPC
* Exploit de DCOM
* Tentativa de enumeração de endpoints

---

# 🧠 Relação RPC + CEH

O CEH quer ver se você:

* Reconhece serviço **pela porta**
* Entende **superfície de ataque**
* Sabe identificar atacante por **fluxo**

---

# 📋 Como explicar isso na prova (modelo ideal)

> *The attacker IP 172.30.10.99 generated multiple TCP connection attempts to port 135, which is used by the RPC Endpoint Mapper service. The high volume of RPC connection attempts indicates an attack targeting the RPC service of the target machine.*

---

# ✅ Resposta correta

```
172.30.10.99
```

---

# 🧠 Resumo mental definitivo

```text
RPC
= porta 135
= Endpoint Mapper
= alvo comum
= ataque = muitas tentativas
= origem dominante = atacante
```

---

# 🧠 Antes de tudo: como funciona uma conexão TCP (30 segundos)

O TCP usa o **3-way handshake**:

```
1) SYN        → "posso conectar?"
2) SYN + ACK  → "pode"
3) ACK        → "ok, conectei"
```

Qualquer coisa fora desse fluxo normal **já é sinal** de algo errado ou automatizado.

---

# 🥈 Filtro 1

```wireshark
tcp.port == 135 && tcp.flags.syn == 1 && tcp.flags.ack == 0
```

## 🔍 O que esse filtro pega

Pacotes TCP que:

* Têm **SYN ligado**
* Não têm **ACK**
* Destino ou origem porta **135 (RPC)**

---

## 🧠 Por que isso indica ataque?

### 🔹 SYN sem ACK = tentativa inicial

Esse pacote é:

> “Oi, porta 135, você está aí?”

👉 Todo scan, brute-force ou exploit **começa com SYN**.

---

### 🔹 ACK = 0 → conexão ainda não existe

* Não há sessão estabelecida
* Não há comunicação legítima em andamento

👉 Muitas tentativas assim significam:

* **Varredura**
* **Brute-force**
* **Exploit automático**

---

## 🎯 No contexto de RPC

* RPC é serviço sensível
* Normalmente acessado por poucos hosts legítimos
* **Muitos SYN seguidos = comportamento anômalo**

---

## 📌 Exemplo prático

| Situação    | Normal | Ataque    |
| ----------- | ------ | --------- |
| SYN isolado | Sim    | Sim       |
| Muitos SYN  | Não    | Sim       |
| SYN sem ACK | Raro   | Frequente |

---

## 🧠 Conclusão do filtro 🥈

> Esse filtro mostra **quem está tentando iniciar conexões RPC**, mesmo sem sucesso.

👉 **Origem dominante = atacante**

---

# 🥉 Filtro 2

```wireshark
tcp.port == 135 && tcp.flags.reset == 1
```

---

## 🔍 O que esse filtro pega

Pacotes TCP com flag **RST (Reset)** ativada.

---

## 🧠 O que é RST?

RST significa:

> “Essa conexão não deveria existir — vou encerrar agora.”

Ele aparece quando:

* Porta fechada
* Serviço rejeita conexão
* Firewall derruba sessão
* Stack TCP detecta algo inválido

---

## 🧠 Por que muitos RST indicam ataque?

### 🔹 Em tráfego normal:

* RST aparece **raramente**
* Normalmente por erro pontual

---

### 🔹 Em ataque:

* Scanner manda SYN
* Serviço recusa
* Sistema responde com RST
* Isso se repete **centenas ou milhares de vezes**

👉 Resultado: **enxurrada de RST**

---

## 🎯 No contexto de RPC

* Porta 135 é altamente protegida
* Tentativas indevidas são rejeitadas
* Isso gera muitos resets

---

## 📌 Padrão clássico

```text
SYN → RST
SYN → RST
SYN → RST
```

👉 Assinatura de:

* Scan agressivo
* Tentativa de exploração
* Ataque automatizado

---

## 🧠 Conclusão do filtro 🥉

> Esse filtro mostra **conexões RPC rejeitadas**, geralmente causadas por ataque.

---

# 🔥 Por que esses dois filtros juntos são poderosos

| Filtro      | Mostra                |
| ----------- | --------------------- |
| SYN sem ACK | Tentativa de ataque   |
| RST         | Rejeição da tentativa |

👉 Juntos, eles provam:

* Quem atacou
* Que o ataque falhou (ou foi bloqueado)
* Que não era tráfego legítimo

---

# 🧠 Como o CEH pensa quando cria a questão

Eles querem que você entenda:

* TCP não é “porta aberta ou fechada”
* Ataques têm **padrões de flags**
* Wireshark ≠ só payload

---

# 📋 Como explicar isso numa prova (modelo perfeito)

> *The filter tcp.flags.syn == 1 && tcp.flags.ack == 0 identifies initial TCP connection attempts to the RPC service. A high number of such packets indicates scanning or brute-force attempts. The presence of multiple TCP RST packets further confirms that these attempts were rejected, indicating an attack against the RPC service.*

---

# 🧠 Resumo mental definitivo

```text
SYN sem ACK = tentativa
RST = rejeição
Muitos = ataque
RPC (135) = alvo crítico
```

Excelente pergunta — **isso aqui é entendimento de TCP de verdade**, não “receita de Wireshark”. Vamos desmontar **bit a bit** para ficar impossível esquecer.

---

# 🧠 Antes de tudo: como funciona uma conexão TCP (30 segundos)

O TCP usa o **3-way handshake**:

```
1) SYN        → "posso conectar?"
2) SYN + ACK  → "pode"
3) ACK        → "ok, conectei"
```

Qualquer coisa fora desse fluxo normal **já é sinal** de algo errado ou automatizado.

---

# 🥈 Filtro 1

```wireshark
tcp.port == 135 && tcp.flags.syn == 1 && tcp.flags.ack == 0
```

## 🔍 O que esse filtro pega

Pacotes TCP que:

* Têm **SYN ligado**
* Não têm **ACK**
* Destino ou origem porta **135 (RPC)**

---

## 🧠 Por que isso indica ataque?

### 🔹 SYN sem ACK = tentativa inicial

Esse pacote é:

> “Oi, porta 135, você está aí?”

👉 Todo scan, brute-force ou exploit **começa com SYN**.

---

### 🔹 ACK = 0 → conexão ainda não existe

* Não há sessão estabelecida
* Não há comunicação legítima em andamento

👉 Muitas tentativas assim significam:

* **Varredura**
* **Brute-force**
* **Exploit automático**

---

## 🎯 No contexto de RPC

* RPC é serviço sensível
* Normalmente acessado por poucos hosts legítimos
* **Muitos SYN seguidos = comportamento anômalo**

---

## 📌 Exemplo prático

| Situação    | Normal | Ataque    |
| ----------- | ------ | --------- |
| SYN isolado | Sim    | Sim       |
| Muitos SYN  | Não    | Sim       |
| SYN sem ACK | Raro   | Frequente |

---

## 🧠 Conclusão do filtro 🥈

> Esse filtro mostra **quem está tentando iniciar conexões RPC**, mesmo sem sucesso.

👉 **Origem dominante = atacante**

---

# 🥉 Filtro 2

```wireshark
tcp.port == 135 && tcp.flags.reset == 1
```

---

## 🔍 O que esse filtro pega

Pacotes TCP com flag **RST (Reset)** ativada.

---

## 🧠 O que é RST?

RST significa:

> “Essa conexão não deveria existir — vou encerrar agora.”

Ele aparece quando:

* Porta fechada
* Serviço rejeita conexão
* Firewall derruba sessão
* Stack TCP detecta algo inválido

---

## 🧠 Por que muitos RST indicam ataque?

### 🔹 Em tráfego normal:

* RST aparece **raramente**
* Normalmente por erro pontual

---

### 🔹 Em ataque:

* Scanner manda SYN
* Serviço recusa
* Sistema responde com RST
* Isso se repete **centenas ou milhares de vezes**

👉 Resultado: **enxurrada de RST**

---

## 🎯 No contexto de RPC

* Porta 135 é altamente protegida
* Tentativas indevidas são rejeitadas
* Isso gera muitos resets

---

## 📌 Padrão clássico

```text
SYN → RST
SYN → RST
SYN → RST
```

👉 Assinatura de:

* Scan agressivo
* Tentativa de exploração
* Ataque automatizado

---

## 🧠 Conclusão do filtro 🥉

> Esse filtro mostra **conexões RPC rejeitadas**, geralmente causadas por ataque.

---

# 🔥 Por que esses dois filtros juntos são poderosos

| Filtro      | Mostra                |
| ----------- | --------------------- |
| SYN sem ACK | Tentativa de ataque   |
| RST         | Rejeição da tentativa |

👉 Juntos, eles provam:

* Quem atacou
* Que o ataque falhou (ou foi bloqueado)
* Que não era tráfego legítimo

---

# 🧠 Como o CEH pensa quando cria a questão

Eles querem que você entenda:

* TCP não é “porta aberta ou fechada”
* Ataques têm **padrões de flags**
* Wireshark ≠ só payload

---

# 📋 Como explicar isso numa prova (modelo perfeito)

> *The filter tcp.flags.syn == 1 && tcp.flags.ack == 0 identifies initial TCP connection attempts to the RPC service. A high number of such packets indicates scanning or brute-force attempts. The presence of multiple TCP RST packets further confirms that these attempts were rejected, indicating an attack against the RPC service.*

---

# 🧠 Resumo mental definitivo

```text
SYN sem ACK = tentativa
RST = rejeição
Muitos = ataque
RPC (135) = alvo crítico
```

---

# 🧠 Como funcionam as TCP Flags (visão rápida)

O campo **TCP Flags** é um conjunto de bits. Cada flag pode estar:

* **0** → desligada
* **1** → ligada

No Wireshark:

```text
tcp.flags.<flag> == 0 ou 1
```

---

# 🚩 Lista completa das TCP Flags

| Flag    | Nome                      | Valor             |
| ------- | ------------------------- | ----------------- |
| **FIN** | Finish                    | `tcp.flags.fin`   |
| **SYN** | Synchronize               | `tcp.flags.syn`   |
| **RST** | Reset                     | `tcp.flags.reset` |
| **PSH** | Push                      | `tcp.flags.push`  |
| **ACK** | Acknowledge               | `tcp.flags.ack`   |
| **URG** | Urgent                    | `tcp.flags.urg`   |
| **ECE** | ECN Echo                  | `tcp.flags.ece`   |
| **CWR** | Congestion Window Reduced | `tcp.flags.cwr`   |
| **NS**  | ECN Nonce Sum             | `tcp.flags.ns`    |

---

# 🎯 Valores possíveis para `tcp.flags.syn`

Tecnicamente, só existem **dois valores**:

```text
tcp.flags.syn == 1   → SYN ligado
tcp.flags.syn == 0   → SYN desligado
```

Mas o poder está na **combinação com outras flags**.

---

# 🔥 Combinações comuns envolvendo SYN (as importantes de verdade)

## 1️⃣ SYN puro (início de conexão)

```wireshark
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

📌 Significa:

* Tentativa inicial de conexão
* Scan
* Brute-force
* Exploit attempt

---

## 2️⃣ SYN + ACK (resposta do servidor)

```wireshark
tcp.flags.syn == 1 && tcp.flags.ack == 1
```

📌 Significa:

* Porta aberta
* Serviço escutando
* Resposta legítima

---

## 3️⃣ ACK puro (conexão estabelecida)

```wireshark
tcp.flags.ack == 1 && tcp.flags.syn == 0
```

📌 Significa:

* Tráfego normal
* Sessão ativa
* Transferência de dados

---

## 4️⃣ SYN + FIN (suspeito)

```wireshark
tcp.flags.syn == 1 && tcp.flags.fin == 1
```

📌 Significa:

* Pacote **anômalo**
* Assinatura de scan furtivo
* Comportamento inválido segundo RFC

👉 Normalmente usado para:

* Evasão de firewall
* Fingerprinting

---

## 5️⃣ SYN + RST (raríssimo / inválido)

```wireshark
tcp.flags.syn == 1 && tcp.flags.reset == 1
```

📌 Significa:

* Pacote malformado
* Ferramenta defeituosa
* Tentativa de evasão

---

# 🧪 Combinações clássicas de ataque (CEH adora)

| Tipo      | Filtro                                                            |
| --------- | ----------------------------------------------------------------- |
| SYN scan  | `tcp.flags.syn == 1 && tcp.flags.ack == 0`                        |
| FIN scan  | `tcp.flags.fin == 1 && tcp.flags.ack == 0`                        |
| NULL scan | `tcp.flags == 0`                                                  |
| XMAS scan | `tcp.flags.fin == 1 && tcp.flags.push == 1 && tcp.flags.urg == 1` |

---

# 🧠 Extra: Flags em valor decimal (baixo nível)

Às vezes você verá algo como:

```text
Flags: 0x002 (SYN)
```

Tabela rápida:

| Flag | Hex   |
| ---- | ----- |
| FIN  | 0x001 |
| SYN  | 0x002 |
| RST  | 0x004 |
| PSH  | 0x008 |
| ACK  | 0x010 |
| URG  | 0x020 |

Exemplo:

```text
0x012 = SYN + ACK
```

---

# 🧠 Como pensar em prova (atalho mental)

```text
SYN = tentativa
SYN+ACK = porta aberta
RST = rejeição
Muitas tentativas = ataque
```

---

# ✅ Resumo final

* `tcp.flags.syn` só pode ser **0 ou 1**
* O que importa são as **combinações**
* SYN isolado = início / scan
* SYN + ACK = resposta válida
* SYN + FIN / SYN + RST = anomalia
