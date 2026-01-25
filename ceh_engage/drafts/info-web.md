O **WPScan** é uma **ferramenta de segurança (pentest)** focada **exclusivamente em sites WordPress** 👀💥
Ela é usada pra **identificar vulnerabilidades**, plugins inseguros e más configurações.

### 🧠 Em resumo

👉 **WPScan = scanner de vulnerabilidades para WordPress**

Ele analisa um site WP e responde coisas como:

* Quais **plugins e temas** estão instalados
* Se eles têm **falhas conhecidas**
* Versão do WordPress
* Usuários válidos
* Configurações inseguras
* Vulnerabilidades públicas (CVEs)

---

## 🔎 O que o WPScan consegue descobrir

Alguns exemplos reais:

* 📦 **Plugins vulneráveis**
* 🎨 **Temas com falhas**
* 🧩 Versão exata do WordPress
* 👤 Enumeração de usuários (`admin`, `editor`, etc.)
* 🔐 Se XML-RPC está ativo (alvo clássico de brute force)
* ⚠️ Falhas conhecidas como:

  * SQL Injection
  * XSS
  * LFI
  * Auth bypass

---

## 🛠️ Como ele funciona por baixo dos panos

* Faz **fingerprinting**
* Analisa **respostas HTTP**
* Usa **assinaturas de plugins/temas**
* Consulta um **banco de dados de vulnerabilidades** mantido pela comunidade WPScan

---

## 💻 Exemplo de uso básico

```bash
wpscan --url https://site-alvo.com
```

### Com enumeração de plugins e usuários:

```bash
wpscan --url https://site-alvo.com --enumerate p,u
```

Legenda:

* `p` = plugins
* `u` = usuários

---

## 🔑 API Token (importante)

O WPScan usa uma API própria pra buscar vulnerabilidades atualizadas.

```bash
wpscan --api-token SUA_API_KEY
```

Sem token → ele funciona, mas com menos resultados.

---

## ⚠️ É legal usar?

🚨 **Atenção**:

* ✔️ **Legal**: em site seu, ambiente de teste, laboratório (HTB, TryHackMe)
* ❌ **Ilegal**: usar em sites sem autorização

Isso pode ser considerado **crime** dependendo do país.
