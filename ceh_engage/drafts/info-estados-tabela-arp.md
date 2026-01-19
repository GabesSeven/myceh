# 🧠 Estados da Neighbor Table (`ip neigh`)

---

## 🟢 **REACHABLE**

### O que significa

O vizinho **foi confirmado recentemente** como acessível.

### Como o kernel chegou aqui

* Recebeu **ARP Reply** válido (IPv4)
* Recebeu **Neighbor Advertisement** (IPv6)
* Ou houve tráfego confirmado recente

### Comportamento

* Nenhum ARP enviado
* Entrada confiável

### Inferência prática

✔ Host **online agora**
✔ MAC/IP válidos
✔ Comunicação ativa

---

## 🟡 **STALE**

### O que significa

O kernel **conhece o MAC**, mas **não confirmou recentemente**.

### Como chega aqui

* Timer de `REACHABLE` expirou
* Host pode ainda estar online

### Comportamento

* Nenhum ARP enviado ainda
* Só reage se você tentar usar

### Inferência prática

⚠️ Host **pode estar online**
⚠️ Última confirmação antiga

---

## 🟠 **DELAY**

### O que significa

O kernel **vai testar**, mas **ainda está esperando**.

### Como chega aqui

* Você tentou enviar tráfego para um `STALE`
* Kernel aguarda alguns ms antes de ARP

### Comportamento

* Espera (`delay_first_probe_time`)
* Se não houver confirmação → `PROBE`

### Inferência prática

⏳ Tentativa de revalidação em andamento

---

## 🔵 **PROBE**

### O que significa

O kernel **está enviando ARP requests ativamente**.

### Como chega aqui

* `DELAY` expirou
* ARP sendo retransmitido

### Comportamento

* Envia vários ARP Requests
* Se responder → `REACHABLE`
* Se não → `FAILED`

### Inferência prática

📡 Host **não respondeu ainda**
📡 Pode estar offline ou filtrando ARP

---

## 🔴 **FAILED**

### O que significa

O kernel **tentou e falhou** em validar o vizinho.

### Como chega aqui

* `PROBE` sem resposta
* Timeout total atingido

### Comportamento

* Entrada considerada inválida
* Novo tráfego força novo ARP

### Inferência prática

❌ Host **offline**
❌ IP inexistente
❌ Firewall / ARP filtering

---

## ⚪ **INCOMPLETE**

### O que significa

O kernel **não conhece o MAC ainda**.

### Como chega aqui

* ARP Request enviado
* Nenhuma resposta recebida ainda

### Comportamento

* Aguardando ARP Reply

### Inferência prática

❓ Host **pode existir ou não**
❓ Ainda sem resposta

---

# 🔁 Fluxo real de estados (importante)

```text
INCOMPLETE
     ↓ reply
REACHABLE
     ↓ timeout
STALE
     ↓ uso
DELAY
     ↓
PROBE
     ↓ reply           ↓ timeout
REACHABLE         FAILED
```

---

# 🧠 Resumo ultra-rápido

| Estado     | Interpretação humana |
| ---------- | -------------------- |
| REACHABLE  | Online agora         |
| STALE      | Visto antes          |
| DELAY      | Vai testar           |
| PROBE      | Testando             |
| FAILED     | Não respondeu        |
| INCOMPLETE | Aguardando resposta  |
