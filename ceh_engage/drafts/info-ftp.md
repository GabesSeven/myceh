# 🔐 Desafio 15 — *FTP Unencrypted Cleartext Login*

## O que isso significa em um pentest de verdade?

---

## 1️⃣ Interpretação técnica direta

A vulnerabilidade:

```
FTP Unencrypted Cleartext Login
```

significa que:

* O serviço **FTP (porta 21)** está ativo
* **Usuário e senha são transmitidos em texto claro**
* Não há:

  * TLS (FTPS)
  * SSH (SFTP)
* Qualquer tráfego de autenticação pode ser **capturado e lido**

📌 Isso NÃO é um bug de software, é uma **falha de configuração** (*misconfiguration*).

---

## 2️⃣ Onde isso entra no processo de pentest (metodologia)

### Mapeamento no ciclo clássico:

```
Recon
 → Scan (OpenVAS)
   → Vulnerability Analysis   ← VOCÊ ESTÁ AQUI
     → Exploitation
       → Post-exploitation
```

O OpenVAS respondeu:

> *Existe um vetor de ataque viável se eu conseguir observar o tráfego.*

---

## 3️⃣ Impacto prático (mundo real)

### 🎯 Vetores de ataque habilitados por essa falha:

#### 🔹 Sniffing de credenciais

* Ferramentas:

  * Wireshark
  * tcpdump
  * Ettercap
* Basta:

  * Estar na mesma rede
  * Ou realizar MITM

Resultado:

```
USER admin
PASS senha123
```

---

#### 🔹 Ataque Man-in-the-Middle (MITM)

* ARP Spoofing
* DHCP poisoning
* DNS spoofing

➡️ Permite capturar:

* Credenciais FTP
* Sessões
* Arquivos transferidos

---

#### 🔹 Acesso não autorizado

* Credenciais capturadas podem ser reutilizadas:

  * No próprio FTP
  * Em SSH
  * Em aplicações internas
* **Password reuse** é comum

---

## 4️⃣ Por que isso é classificado como *Medium*?

| Critério          | Avaliação     |
| ----------------- | ------------- |
| Complexidade      | Baixa         |
| Impacto           | Médio         |
| Exploração remota | Não direta    |
| Pré-requisito     | Acesso à rede |

📌 **Não é Critical**, porque:

* Requer posição na rede
* Não é RCE direto

📌 **Não é Low**, porque:

* Compromete confidencialidade
* Facilita lateral movement

---

## 5️⃣ QoD 70% — o que isso quer dizer aqui?

```
QoD: 70%
```

Significa que o OpenVAS:

* Detectou:

  * Serviço FTP ativo
  * Falta de TLS
* Com base em:

  * Banner
  * Testes de protocolo
* Alta confiança, mas **sem autenticação real**

✔️ Para CEH:

> QoD ≥ 70% = finding válido

---

## 6️⃣ O que um pentester faria a seguir? (pós-finding)

### 🔥 Próximos passos realistas:

#### 1️⃣ Confirmar manualmente

```bash
ftp 192.168.10.144
```

#### 2️⃣ Capturar tráfego

```bash
tcpdump -i eth0 port 21
```

ou Wireshark:

```
ftp
```

---

#### 3️⃣ Testar credenciais fracas / reutilizadas

```bash
hydra -l admin -P passwords.txt ftp://192.168.10.144
```

---

#### 4️⃣ Enumerar arquivos sensíveis

```bash
ls
get backup.sql
```

---

## 7️⃣ Impacto estratégico no relatório de pentest

No relatório final, isso seria descrito como:

### 📌 Finding

**FTP Unencrypted Cleartext Login**

### 📌 Impact

* Possível interceptação de credenciais
* Comprometimento de contas
* Exposição de dados

### 📌 Recommendation

* Desabilitar FTP
* Migrar para:

  * SFTP
  * FTPS
* Forçar criptografia
