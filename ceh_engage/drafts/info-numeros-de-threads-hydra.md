# 🔐 Hydra + SMB: tuning correto

## Seu comando

```bash
hydra -L ~/users.txt -P ~/rockyou.txt 192.168.10.101 smb -u -t 4 -w 3
```

### O que cada parâmetro faz (foco no SMB)

* `-L ~/users.txt`
  → lista de usuários

* `-P ~/rockyou.txt`
  → wordlist de senhas

* `smb`
  → módulo SMB (porta 445)

* `-u`
  → tenta **todas as senhas para um usuário antes de passar ao próximo**
  ✅ ideal para SMB (evita lockout rápido)

* `-t 4`
  → **4 threads simultâneas**

* `-w 3`
  → espera 3 segundos por resposta

---

## 🎯 Esse `-t 4` é o melhor valor para SMB?

👉 **Sim, é um valor seguro e recomendado**

### Por quê?

SMB:

* é **stateful**
* cria sessão
* pode aplicar **account lockout**
* servidores Windows costumam **detectar brute force agressivo**

### Regra prática (guarda isso):

| Serviço   | Threads recomendadas |
| --------- | -------------------- |
| FTP       | 8–16                 |
| SSH       | 4–8                  |
| **SMB**   | **2–4 (máx 6)**      |
| HTTP form | 16+                  |

📌 Para CEH / prova:

> **-t 4 é perfeito**
