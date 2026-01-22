# 🎯 PART II – Challenge 14

**Extração de dados ocultos via esteganografia**

---

## 📘 Enunciado (interpretado corretamente)

> Um ataque interno ocorreu e dados confidenciais foram **sniffados e ocultados (encrypted + hidden)** dentro de uma imagem chamada `stealth.jpeg`.
> Você deve **extrair os dados ocultos** usando **steghide** e identificar o **valor da cotação**.

📌 Palavras-chave críticas:

* **hidden data**
* **image file**
* **steghide**
* **passphrase fornecida**

---

# 🧠 O que está sendo explorado aqui?

👉 **Esteganografia**

> Esteganografia é a técnica de **ocultar informações dentro de outro arquivo**, de forma que **ninguém perceba que há dados ali**.

📌 Diferente de criptografia:

* **Criptografia** → esconde o conteúdo
* **Esteganografia** → esconde a existência

Neste desafio:

* O arquivo **parece** apenas uma imagem
* Mas **contém um arquivo oculto**
* Protegido por **senha**

---

# 🛠️ Ferramenta usada: `steghide`

## O que é steghide?

* Ferramenta de esteganografia
* Suporta:

  * JPEG
  * BMP
  * WAV
  * AU
* Pode:

  * Embed (esconder)
  * Extract (extrair)
* Pode usar **senha (passphrase)**

📌 Extremamente comum em:

* Malware
* Insider threats
* Exfiltração de dados
* CTFs
* CEH

---

# 🧪 Seu fluxo (correto)

```bash
steghide extract -sf ~/Desktop/stealth.jpeg
```

### O que cada parte faz:

| Parâmetro      | Explicação                                            |
| -------------- | ----------------------------------------------------- |
| `extract`      | Modo de extração                                      |
| `-sf`          | **S**tego **F**ile (arquivo que contém dados ocultos) |
| `stealth.jpeg` | Arquivo “inocente”                                    |

📌 Ao rodar:

* Steghide detecta dados ocultos
* Solicita senha

---

### 🔐 Senha fornecida no desafio

```text
azerty@123
```

📌 Sem a senha correta:

* Extração falha
* Mesmo que o arquivo exista

---

# 📂 Resultado da extração

```bash
open hidden.txt
```

Conteúdo:

```text
Tender quote for techiquest event 2024: 3965222
```

---

# ✅ Resposta final do desafio

📌 **Tender quotation value**:

> **3965222**

✔️ Formato correto
✔️ Valor correto
✔️ Técnica correta

---

# 🧠 O que o atacante fez (cenário real)

1️⃣ Sniffou dados sensíveis
2️⃣ Salvou em um arquivo texto
3️⃣ Ocultou dentro de uma imagem JPEG
4️⃣ Aplicou senha
5️⃣ Transferiu a imagem (parece inofensiva)

📌 Isso é **exfiltração furtiva de dados**.

---

# 🚀 Otimizações e melhorias (nível CEH+)

## 🥇 1️⃣ Verificar se há dados ocultos antes

```bash
steghide info stealth.jpeg
```

📌 Mostra:

* Se há dados embutidos
* Tipo de criptografia
* Se precisa de senha

---

## 🥈 2️⃣ Extrair já definindo nome do arquivo

```bash
steghide extract -sf stealth.jpeg -xf output.txt
```

📌 Útil para automação.

---

## 🥉 3️⃣ Modo silencioso (scripts)

```bash
steghide extract -sf stealth.jpeg -p azerty@123 -q
```

📌 Ideal para:

* Provas
* Laboratórios
* Scripts

---

## 🧠 Fluxo otimizado ideal (resumo)

```bash
cd ~/Desktop
steghide info stealth.jpeg
steghide extract -sf stealth.jpeg -p azerty@123
cat hidden.txt
```

---

# ❗ Pegadinhas comuns da prova CEH

❌ Usar `binwalk` (não funciona aqui)
❌ Procurar strings na imagem
❌ Abrir no hex editor sem motivo
❌ Esquecer a senha fornecida
❌ Confundir esteganografia com criptografia

✔️ Você seguiu o **caminho exato que a prova espera**

---

# 🧠 Comparação rápida (pra fixar)

| Técnica        | Esconde o quê? |
| -------------- | -------------- |
| Criptografia   | Conteúdo       |
| Esteganografia | Existência     |
| Ofuscação      | Legibilidade   |


---

## 🔎 `hidden.txt` é o nome padrão?

### ❌ Não exatamente “padrão fixo”

O **steghide não cria sempre `hidden.txt` por padrão**.

👉 O que acontece é o seguinte:

* O **nome do arquivo extraído é o MESMO nome** do arquivo que foi **originalmente escondido**.
* No seu desafio, quem criou o arquivo oculto **escondeu um arquivo chamado `hidden.txt`**.
* Por isso, ao extrair, ele reaparece com esse nome.

📌 Ou seja:

> **`hidden.txt` não é um nome default do steghide — ele vem do atacante.**

---

## 🧠 Como o steghide decide o nome do arquivo extraído

Quando alguém usa:

```bash
steghide embed -cf imagem.jpg -ef segredo.txt
```

O steghide:

* Guarda o conteúdo de `segredo.txt`
* Guarda **metadados**, incluindo:

  * Nome do arquivo (`segredo.txt`)
  * Tamanho
  * Algoritmo de criptografia

Quando você extrai:

```bash
steghide extract -sf imagem.jpg
```

Ele:

* Reconstrói o arquivo
* **Restaura o nome original**

📌 No seu caso:

```
hidden.txt  ← esse era o nome original
```

---

## 🧪 Prova prática (para fixar)

### 1️⃣ Esconder um arquivo

```bash
echo "segredo" > teste.txt
steghide embed -cf img.jpg -ef teste.txt -p senha123
```

### 2️⃣ Extrair

```bash
steghide extract -sf img.jpg -p senha123
```

📌 Resultado:

```text
wrote extracted data to "teste.txt"
```

➡️ O nome vem do **arquivo embedado**, não do steghide.

---

## 🔧 Como FORÇAR outro nome ao extrair

Se você quiser **mudar o nome do arquivo extraído**, use `-xf`:

```bash
steghide extract -sf stealth.jpeg -xf resultado.txt
```

📌 Mesmo que o original fosse `hidden.txt`, agora será:

```text
resultado.txt
```

---

## 🔇 O que faz a flag `-q` no steghide

`-q` significa **quiet mode** (modo silencioso).

📌 Ela **suprime a saída padrão** do comando, ou seja:

* Não mostra mensagens informativas
* Não imprime avisos
* Só mostra **erros críticos** (se houver)

---

## 🧪 Comparação prática

### 🔊 Sem `-q`

```bash
steghide extract -sf stealth.jpeg -p azerty@123
```

Saída típica:

```text
wrote extracted data to "hidden.txt"
```

---

### 🔇 Com `-q`

```bash
steghide extract -sf stealth.jpeg -p azerty@123 -q
```

Saída:

```text
(nada)
```

📌 Mas o arquivo **é extraído normalmente**.

---

## 🎯 Por que isso é útil?

### 🧠 1️⃣ Em automação / scripts

Evita poluir o output:

```bash
steghide extract -sf stealth.jpeg -p azerty@123 -q
cat hidden.txt
```

---

### 🧪 2️⃣ Em CTFs / CEH Labs

* Menos ruído
* Mais foco no resultado

---

### 🔐 3️⃣ OPSEC / Red Team

* Menos logs visíveis
* Execução mais discreta

---

## ❗ O que `-q` NÃO faz

❌ Não acelera o processo
❌ Não ignora erros
❌ Não pula senha
❌ Não oculta falhas

📌 Se a senha estiver errada, o comando **falha normalmente**.
