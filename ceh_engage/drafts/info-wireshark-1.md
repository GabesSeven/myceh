# 🎯 O que o desafio realmente pede

> **Determine the credentials obtained**

Ou seja:

* Usuário
* Senha
* Extraídos **de tráfego capturado**
* Não é ataque ativo, é **análise forense de rede**

Formato pedido:

```
aaaa/aaaaa
```

➡️ `kety/apple`

---

# 🧠 A lógica geral (visão macro)

```text
Credenciais web
↓
Normalmente enviadas via POST
↓
Formulário HTML
↓
application/x-www-form-urlencoded
↓
Campos username/password
```

Você seguiu exatamente esse raciocínio — isso é **o fluxo correto**.

---

# 🔍 Por que cada passo funciona

---

## 1️⃣ Filtrar por `http.request.method == POST`

### 🧠 Por quê?

* **GET** → dados ficam na URL (menos comum para login)
* **POST** → dados vão no corpo da requisição (padrão para login)

👉 99% dos logins web **não usam GET**

📌 Esse filtro reduz:

* Imagens
* CSS
* JS
* Tráfego irrelevante

---

## 2️⃣ Identificar `application/x-www-form-urlencoded`

### 🧠 Por quê?

Esse é o **formato clássico** de envio de formulário HTML.

Exemplo real:

```
txtusername=kety&txtpwd=apple
```

👉 Se o site não usa HTTPS, **tudo fica em texto puro**.

---

## 3️⃣ Inspecionar “HTML Form URL Encoded”

### 🧠 Por quê?

Wireshark **decodifica automaticamente**:

* Parâmetros
* Chaves
* Valores

Isso evita:

* Ler payload hexadecimal
* Fazer decode manual

---

## 4️⃣ Identificar os campos de credenciais

```text
txtusername = kety
txtpwd = apple
```

📌 Os nomes dos campos:

* Variam por aplicação
* Mas quase sempre indicam função (`user`, `login`, `pwd`, etc.)

👉 O CEH **sempre deixa isso explícito**, não tenta confundir.

---

# ⚡ Como otimizar ainda mais (menos cliques)

## 🥇 Filtro mais específico

```wireshark
http.request.method == "POST" && http contains "pwd"
```

Ou:

```wireshark
http contains "username" || http contains "password"
```

📌 Vai direto nos pacotes relevantes.

---

## 🥈 Seguir fluxo HTTP

Clique com botão direito no pacote →
**Follow → HTTP Stream**

👉 Você vê:

* Requisição
* Resposta
* Credenciais no contexto

🔥 Esse é o método **mais rápido visualmente**.

---

## 🥉 Estatísticas (visão geral)

```text
Statistics → Conversations → TCP
```

👉 Identifica:

* Quem falou com quem
* Porta 80
* Host `moviescope.com`

Depois filtra só esse fluxo.

---

# 🧠 Por que isso funciona (do ponto de vista de segurança)

* O site **não usa HTTPS**
* Credenciais trafegam em **texto claro**
* Um sniffer passivo consegue capturar tudo

👉 Isso demonstra:

> “Lack of transport layer encryption”

---

# 🧾 Como o CEH espera a resposta

Sem explicação, só:

```
kety/apple
```

---

# 🧠 Checklist mental CEH (guarda isso)

```text
PCAP → HTTP → POST → Form → username/password
```

---

# ❌ Erros comuns (você evitou)

* ❌ Filtrar por GET
* ❌ Procurar FTP/SMTP
* ❌ Analisar TLS (quando não há HTTPS)
* ❌ Ignorar o body da requisição
