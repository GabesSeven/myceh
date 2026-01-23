# 🎯 PART III – Challenge 1

**Identificar a máquina vítima de um ataque de Session Hijacking**

---

## 📘 O que o desafio está pedindo (de verdade)

> Um atacante tentou **session hijacking** contra uma máquina da subnet `172.30.10.0/24`.
> Você recebeu um **PCAP capturado da vítima**.
> Determine **qual IP foi o alvo do ataque**.

📌 Palavras-chave importantes:

* *session hijacking*
* *victim machine*
* *packet capture*
* *RST*

---

# 🧠 O que é Session Hijacking (resumo rápido)

Session hijacking ocorre quando o atacante tenta:

* Interceptar uma sessão TCP válida
* Forçar a dessicronização da sessão
* Assumir o controle da comunicação

Uma técnica muito comum envolve:

* **Injeção de pacotes TCP RST**
* Forçar a vítima a **derrubar a conexão**
* Abrir espaço para o atacante assumir a sessão

---

# 🧪 Sua abordagem

### 📂 Arquivo analisado

```
$_Jack.pcapng
```

---

## 🔎 Filtro usado

```wireshark
tcp.flags.reset == 1
```

### O que esse filtro faz:

* Mostra **pacotes TCP com flag RST**
* Indica **reset de conexão**
* Muito comum em:

  * Session hijacking
  * TCP desync
  * Ataques de interrupção de sessão

📌 Excelente escolha para esse cenário.

---

## 📤 Resultado observado

```text
Source → 172.30.10.200
```

---

# 🧠 Interpretação correta (ponto-chave)

⚠️ Aqui está o detalhe que confunde muita gente:

### ❗ Quem envia RST nem sempre é o atacante

No contexto de **session hijacking**:

* O atacante injeta pacotes malformados
* A **vítima reage**
* A vítima envia **RST** para encerrar a sessão inconsistente

📌 Portanto:

> **O IP que aparece enviando RST é, muitas vezes, a VÍTIMA**

✔️ Isso bate com o enunciado:

> *“packet capture file obtained from the victim machine”*

---

# ✅ Resposta final

```
172.30.10.200
```

✔️ IP correto
✔️ Lógica correta
✔️ Interpretação correta

---

# 🚀 Como otimizar / refinar a análise

## 🥇 1️⃣ Confirmar que o IP é o alvo (Destination analysis)

Use também:

```wireshark
tcp.flags.reset == 1 && ip.dst == 172.30.10.200
```

📌 Se muitos pacotes chegam **até esse IP**, ele é o alvo.

---

## 🥈 2️⃣ Ver sequência de sessão quebrada

```wireshark
tcp.analysis.retransmission || tcp.analysis.out_of_order
```

📌 Session hijacking geralmente gera:

* Retransmissions
* Out-of-order packets
* ACKs inválidos

---

## 🥉 3️⃣ Usar Conversations (forma mais limpa)

📍 Wireshark:

```
Statistics → Conversations → TCP
```

* Ordenar por:

  * RST
  * Packets
* Ver qual IP:

  * Encerra sessões abruptamente

📌 Em prova CEH, isso é **muito rápido**.

---

## 🧠 4️⃣ Filtro ainda mais específico (nível avançado)

```wireshark
tcp.flags.reset == 1 && tcp.len == 0
```

📌 RSTs maliciosos geralmente:

* Não carregam payload
* São pacotes “secos”

---

# ❗ Limitação do seu método (importante saber)

Seu método funciona **quando**:

* O PCAP é da vítima
* O ataque envolve RST injection

Pode falhar se:

* O ataque for por cookie hijacking
* O ataque for HTTP-level
* O atacante estiver dentro da LAN usando ARP spoofing

📌 Mas para **esse desafio**, o método é perfeito.

---

# 🧠 Resumo mental (cola de prova)

* Session hijacking → quebra de sessão
* Técnica comum → TCP RST
* Filtro → `tcp.flags.reset == 1`
* IP que reage → geralmente a vítima
* Capture vindo da vítima → confirme o source

> **RST em excesso = sessão sob ataque**