# 🧠 CONTEXTO DO EXERCÍCIO (O “POR QUÊ”)

### 📱 Cenário

> Uma funcionária chamada **Ruby** pode ter sido alvo de **phishing por ligação telefônica (vishing)**
> O log de chamadas foi extraído de um **dispositivo Android**
> Você deve analisar o **histórico bruto de chamadas**
> O objetivo é identificar **qual ligação é maliciosa** e informar **o número suspeito**

📌 Isso simula investigações reais de:

* fraude bancária
* roubo de identidade
* engenharia social
* golpes por telefone (vishing)

---

## 🎯 O que você está procurando, na prática

Uma ligação que:

* Não é comum
* Tem **conteúdo suspeito**
* Solicita **dados sensíveis** (SSN, banco, verificação de identidade)
* Pode vir de número desconhecido ou repetido

👉 O exercício **não é sobre o número mais frequente**,
é sobre **o número mais perigoso**.

---

# 🧰 FERRAMENTAS USADAS E POR QUE

Você usou **ferramentas UNIX clássicas de análise de logs**.
Isso é EXATAMENTE o que um analista faria em produção.

Vamos por partes.

---

## 1️⃣ Visualização do log bruto

```bash
cat call_log_dump.log.txt
```

📌 O que isso faz:

* Mostra todas as entradas do log
* Permite entender o **formato do arquivo**

Exemplo de linha:

```text
+1 (555) 678-9012,+1 (555) 987-6543,Incoming,Hi mam call World bank cloud you please verify you SSN number.
```

📌 Campos separados por vírgula (CSV):

1. Número de origem
2. Número de destino
3. Tipo da chamada
4. (às vezes duração ou status)
5. Conteúdo / mensagem associada

---

## 2️⃣ `cut -d',' -f5`

```bash
cut -d',' -f5 call_log_dump.log.txt
```

### O que esse comando faz:

* `-d','` → define vírgula como delimitador
* `-f5` → extrai o **campo 5**
* Ou seja: **o conteúdo da chamada / mensagem**

📌 Aqui você isolou **o texto falado/enviado**, que é onde o phishing aparece.

💡 Isso é crucial:

> **Phishing é detectado pelo conteúdo, não pelo número apenas**

---

## 3️⃣ Contagem de mensagens únicas

```bash
cut -d',' -f5 call_log_dump.log.txt | sort | uniq | wc -l
```

### O que isso responde:

* Quantos **conteúdos diferentes** existem no log

📌 Em investigação:

* mensagens repetidas = campanha automatizada
* mensagens únicas = contato legítimo ou ataque direcionado

---

## 4️⃣ Frequência de mensagens

```bash
cut -d',' -f5 call_log_dump.log.txt | sort | uniq | sort -nr
```

Aqui você tenta identificar:

* mensagens que se repetem
* padrões comuns de ataque

📌 Golpes normalmente:

* reutilizam o mesmo script
* usam frases prontas

---

## 5️⃣ Filtro direto por número suspeito

```bash
grep 678- call_log_dump.log.txt
```

📌 Isso:

* localiza todas as ocorrências do número
* permite correlacionar **número ↔ conteúdo**

💥 Foi aqui que você achou a mensagem crítica.

---

## 6️⃣ Filtro por chamadas desconhecidas

```bash
grep "Unknown" call_log_dump.log.txt
```

📌 Em investigação real:

* chamadas “Unknown”, “Private” ou “Blocked”
* são altamente suspeitas

Mesmo que **nesse exercício específico** o golpe não veio como “Unknown”,
esse passo é **boa prática profissional**.

---

# 🚨 IDENTIFICAÇÃO DO PHISHING (O MOMENTO-CHAVE)

Mensagem encontrada:

```text
Hi mam call World bank cloud you please verify you SSN number.
```

### 🚩 Red flags clássicos:

* Banco (World Bank)
* Pedido de verificação
* Solicitação de **SSN**
* Linguagem mal escrita
* Urgência implícita

📌 Isso é **VISHING PURO** (voice phishing).

---

## 📞 Número associado ao golpe

```text
+1 (555) 678-9012
```

✅ **Resposta correta**

```
+1 (555) 678-9012
```

---

# 🧠 O QUE ESSE EXERCÍCIO REALMENTE TESTA

Ele testa se você sabe:

✅ Ler logs brutos
✅ Entender estrutura CSV
✅ Usar filtros simples para análise rápida
✅ Identificar engenharia social pelo conteúdo
✅ Separar ruído de evidência real

📌 Não é sobre “quem ligou mais”
É sobre **quem tentou roubar informação**

---

# ⚙️ OTIMIZAÇÕES DO SEU FLUXO

Você fez certo, mas dá pra deixar mais cirúrgico.

---

### 🔹 Extração direta do número suspeito

```bash
grep -i "ssn\|bank\|verify" call_log_dump.log.txt
```

Ou ainda melhor:

```bash
grep -iE "ssn|bank|verify" call_log_dump.log.txt | cut -d',' -f1 | sort | uniq
```

💥 Retorna direto:

```text
+1 (555) 678-9012
```

---

### 🔹 Contar quantas vezes cada número aparece

```bash
cut -d',' -f1 call_log_dump.log.txt | sort | uniq -c | sort -nr
```

---

# 📌 POR QUE ESSE EXERCÍCIO EXISTE NO CEH?

Porque hoje:

* ataques não são só malware
* **engenharia social é o vetor nº 1**
* logs simples revelam ataques graves
* analistas precisam **pensar como investigadores**, não como script kiddies