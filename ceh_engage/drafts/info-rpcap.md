# 🎯 PART II – Challenge 13

**Identificar máquina com Remote Packet Capture (rpcap) habilitado**

---

## 📘 Enunciado (traduzido mentalmente)

> Você deve escanear a rede para identificar a funcionalidade de **captura remota de pacotes** habilitada, usada para analisar tráfego remotamente.
> Determine o **IP da máquina** que está rodando o **serviço rpcap**.

📌 Palavra-chave do desafio:

> **remote packet capture**

---

# 🧠 O que é rpcap?

**rpcap = Remote Packet Capture**

É um serviço que permite:

* Capturar tráfego de rede **remotamente**
* Usado por ferramentas como:

  * Wireshark
  * Tcpdump remoto
  * Npcap (Windows)

📌 Ele é extremamente sensível do ponto de vista de segurança:

* Permite espionagem de tráfego
* Pode capturar:

  * Senhas
  * Sessões
  * Credenciais
  * Dados internos

---

# 🔐 Porta padrão do rpcap

| Serviço | Porta        |
| ------- | ------------ |
| rpcap   | **2002/TCP** |

📌 Isso **cai em prova CEH** diretamente.

---

# 🧠 O raciocínio que a CEH espera

1️⃣ Captura remota de pacotes
2️⃣ → Serviço rpcap
3️⃣ → Porta padrão 2002/TCP
4️⃣ → Scan na subnet
5️⃣ → IP com a porta aberta = resposta

---

# ✅ Seu comando (correto)

```bash
nmap -p 2002 192.168.10.0/24
```

### Resultado:

```text
2002/tcp open globe
```

📌 **globe** é apenas o nome antigo/alternativo atribuído à porta 2002 no banco de serviços do Nmap.

➡️ **O importante é a porta, não o nome**

---

# 🧠 O que significa `open globe`

* `open` → serviço ativo
* `globe` → rótulo do serviço (não confiável)

📌 CEH **não avalia nome do serviço**, avalia:
✔️ Porta
✔️ Contexto
✔️ Função

---

# 🎯 Conclusão do desafio

> **O IP que respondeu com a porta 2002 aberta é a máquina com rpcap habilitado.**

Esse IP é a **resposta final**.

---

# 🚀 Como otimizar / refinar o scan (nível CEH+)

## 🥇 1️⃣ Mostrar apenas hosts com a porta aberta

```bash
nmap -p 2002 --open 192.168.10.0/24
```

📌 Remove ruído visual.

---

## 🥈 2️⃣ Detectar serviço explicitamente

```bash
nmap -p 2002 -sV 192.168.10.0/24
```

Possível retorno:

```text
2002/tcp open  rpcap
```

📌 Ajuda em relatório técnico.

---

## 🥉 3️⃣ Scan mais rápido (prova)

```bash
nmap -p 2002 -T4 --open 192.168.10.0/24
```

📌 Ideal em ambiente de exame.

---

## 🧠 4️⃣ Scan apenas em hosts vivos (ultra otimizado)

```bash
nmap -sn 192.168.10.0/24 -oG - | awk '/Up/{print $2}' > hosts.txt
nmap -p 2002 --open -iL hosts.txt
```

📌 Fluxo profissional real.

---

# 🔴 Por que rpcap é perigoso?

Se mal configurado:

* Qualquer atacante pode:

  * Espionar tráfego
  * Roubar credenciais
  * Fazer lateral movement
  * Mapear a rede

📌 Em ambientes reais, **rpcap deve ser desabilitado ou restrito**.

---

# 🧠 CEH – Pegadinhas comuns

❌ Scanar todas as portas (demora)
❌ Procurar por “wireshark” no banner
❌ Ignorar que rpcap tem porta fixa
❌ Confundir com NetFlow (2055)

✔️ Você fez o correto: **scan dirigido**
