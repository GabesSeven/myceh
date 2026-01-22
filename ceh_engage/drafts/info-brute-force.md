# 🎯 Objetivo

Testar **todas as combinações possíveis** em RDP **sem perder credenciais válidas** nem disparar bloqueios.

Comando atual:

```bash
hydra -L ~/users.txt -P ~/rockyou.txt 192.168.10.222 rdp
```

Funciona, mas **não é o ideal**.

---

## ⚠️ PROBLEMAS DESSE COMANDO “PURO”

1. Threads padrão podem ser **altas demais**
2. Hydra pode **parar após sucesso**
3. Pouca visibilidade do que está acontecendo
4. RDP responde mal a brute-force agressivo
5. Pode gerar **falso negativo**

---

# ✅ COMANDO OTIMIZADO (RECOMENDADO – CEH)

```bash
hydra -L ~/users.txt -P ~/rockyou.txt 192.168.10.222 rdp \
-u \
-V \
-t 4 \
-f
```

Agora vamos destrinchar **cada otimização**.

---

# 🧠 EXPLICAÇÃO DAS OTIMIZAÇÕES

## 🔹 `-u` → continue após sucesso

Por padrão, o Hydra **pode parar o módulo** após encontrar uma credencial válida.

📌 Esse flag garante:

> "continue testando outras combinações"

Essencial quando **sabemos que há mais de uma credencial válida**.

---

## 🔹 `-V` → verbose

Mostra **todas as tentativas**:

```text
[ATTEMPT] user:pass
```

📌 Útil para:

* Diagnóstico
* Ver se está travando
* Ver se está pulando usuários

---

## 🔹 `-t 4` → número de threads

⚠️ **Muito importante para RDP**

| Serviço | Threads recomendadas |
| ------- | -------------------- |
| SSH     | 8–16                 |
| FTP     | 16                   |
| HTTP    | 16–32                |
| **RDP** | **2–4**              |

Mais que isso:

* Reset de conexão
* Timeout
* Hydra “acha” que senha está errada

---

## 🔹 `-f` → stop após encontrar um par (opcional)

⚠️ **Use apenas se você quiser o primeiro resultado**.

Se você quer **TODOS**, **não use** `-f`.

---

# 🔥 COMANDO FINAL (TODAS AS CREDENCIAIS)

```bash
hydra -L ~/users.txt -P ~/rockyou.txt 192.168.10.222 rdp -u -V -t 4
```

---

# ⚡ EXTRA: EVITAR BLOQUEIO (IMPORTANTE EM LABS)

Se o alvo é sensível:

```bash
hydra -L ~/users.txt -P ~/rockyou.txt 192.168.10.222 rdp -u -V -t 2 -w 5
```

| Flag   | Função                 |
| ------ | ---------------------- |
| `-w 5` | espera 5s por resposta |
| `-t 2` | menos paralelismo      |

---

# 🧠 OTIMIZAÇÃO REAL (ANTES DO HYDRA)

Antes de brute-force, **reduza o escopo**:

### 🔍 Enumerar usuários válidos (se possível)

* SMB
* LDAP
* Kerberos
* RDP NLA banner

Quanto menor `users.txt`, melhor o Hydra funciona.

---

# 🛑 VERDADE IMPORTANTE (nível prova)

> Mesmo com Hydra otimizado, RDP pode aceitar login apenas de contas específicas, portanto apenas um conjunto de credenciais pode ser válido.

---

# 📌 RESUMO FINAL (grave isso)

```text
-L → lista de usuários
-P → lista de senhas
-u → continuar após sucesso
-t 4 → ideal para RDP
-V → debug visual
```


---

# 🧠 O que é Remote Packet Capture (rpcap)

**rpcap (Remote Packet Capture Protocol)** é um **protocolo de rede** que permite **capturar pacotes de uma interface de rede que está em OUTRA máquina**, como se você estivesse rodando o Wireshark localmente nela.

📌 Em resumo:

> **rpcap permite sniffing remoto de tráfego de rede**

---

# 🧩 Onde o rpcap se encaixa

Ele faz parte do ecossistema:

* **libpcap** (Linux / Unix)
* **WinPcap / Npcap** (Windows)
* **Wireshark**
* **tcpdump remoto**

📌 Sem rpcap, o Wireshark **não consegue capturar tráfego remotamente**.

---

# 🧱 Arquitetura do rpcap

## 🖥️ Modelo Cliente–Servidor

```
[ Wireshark ]  --->  [ rpcap daemon ]  --->  [ Interface de rede ]
      Cliente             Servidor              eth0 / wlan0
```

### Componentes:

| Papel         | Função                  |
| ------------- | ----------------------- |
| **Cliente**   | Wireshark / tcpdump     |
| **Servidor**  | rpcap daemon            |
| **Interface** | NIC que será monitorada |

---

# 🔌 Porta padrão

| Serviço | Porta        |
| ------- | ------------ |
| rpcap   | **2002/TCP** |

📌 Porta fixa → fácil de identificar via scan
📌 Exatamente por isso cai em prova CEH

---

# ⚙️ Como funciona tecnicamente

1️⃣ O cliente se conecta ao servidor rpcap
2️⃣ O servidor lista as interfaces disponíveis
3️⃣ O cliente escolhe qual interface capturar
4️⃣ O servidor começa a enviar os pacotes
5️⃣ O cliente analisa os pacotes em tempo real

📌 Tudo isso acontece **via TCP**.

---

# 🔐 Autenticação no rpcap

O rpcap **PODE** usar autenticação, mas:

* ❌ Muitas instalações **não usam**
* ❌ Muitas aceitam conexão sem senha
* ❌ Algumas usam **credenciais fracas**

### Modos possíveis:

* Sem autenticação (muito comum)
* Usuário/senha em texto claro
* NTLM (em Windows)

📌 Em ambientes mal configurados = **risco altíssimo**

---

# 🚨 Por que rpcap é extremamente perigoso

Se um atacante encontra rpcap aberto:

### Ele pode:

* Capturar senhas em texto claro
* Roubar cookies de sessão
* Fazer MITM passivo
* Espionar comunicações internas
* Obter hashes, tokens e credenciais

📌 **É pior que um serviço web vulnerável**, porque:

* Não deixa logs claros
* Atua passivamente
* É difícil de detectar

---

# 🎯 rpcap no contexto de ataques

## 🟥 Fase do ataque onde rpcap aparece

| Fase              | Uso                      |
| ----------------- | ------------------------ |
| Recon             | Descobrir rpcap ativo    |
| Sniffing          | Capturar tráfego         |
| Credential Access | Roubo de senhas          |
| Lateral Movement  | Captura de autenticações |
| Persistence       | Monitoramento contínuo   |

📌 rpcap é uma ferramenta de **pós-comprometimento**.

---

# 🔎 Como identificar rpcap na rede

## 🥇 Scan direcionado (CEH)

```bash
nmap -p 2002 --open 192.168.10.0/24
```

## 🥈 Detectar serviço

```bash
nmap -p 2002 -sV 192.168.10.0/24
```

## 🥉 Banner grabbing

```bash
nc <IP> 2002
```

---

# 🧪 Exemplo prático (Wireshark)

No Wireshark:

1️⃣ Capture → Options
2️⃣ Manage Interfaces
3️⃣ Remote Interfaces
4️⃣ Inserir IP remoto
5️⃣ Se rpcap estiver aberto → interfaces aparecem

📌 Isso **sem login** em muitos ambientes de laboratório.

---

# 🆚 rpcap vs outros métodos

| Tecnologia | Função                  | Porta |
| ---------- | ----------------------- | ----- |
| rpcap      | Sniffing remoto         | 2002  |
| NetFlow    | Estatísticas de tráfego | 2055  |
| SPAN       | Espelhamento físico     | —     |
| tcpdump    | Sniffing local          | —     |

📌 rpcap é o **único** que permite sniffing remoto **sem acesso físico**.

---

# 🧠 CEH – Como a prova cobra

### Perguntas típicas:

* “Which service allows remote packet capture?”
* “Identify the machine running rpcap service”
* “Which port is used by rpcap?”

📌 Respostas:

* **Remote Packet Capture**
* **rpcap**
* **Port 2002**

---

# 🔒 Mitigações (visão defensiva)

* Desabilitar rpcap se não necessário
* Restringir acesso por firewall
* Usar autenticação forte
* Monitorar porta 2002
* IDS/IPS para sniffing suspeito