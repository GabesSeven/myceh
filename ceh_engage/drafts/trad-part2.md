# **CEH Engage – Parte II**

## **Descrição**

A **Parte 2 do CEH Engage** abrange os módulos de:

* **System Hacking**
* **Malware Threats**
* **Sniffing**
* **Social Engineering**
* **Denial-of-Service (DoS)**

Nesta etapa, você deve **explorar as vulnerabilidades identificadas na parte anterior** e utilizar diversas técnicas de exploração de **rede, sistema e fator humano** para obter acesso aos sistemas alvo.

Você deverá:

* Realizar **escalonamento de privilégios horizontal e vertical**
* Instalar **aplicações e utilitários maliciosos** para manter acesso
* **Limpar logs** para evitar detecção
* Criar e utilizar **malwares**
* Analisar **amostras de malware** encontradas nos sistemas

Todas as informações descobertas nesta fase devem ser documentadas para uso na próxima etapa do ciclo de hacking ético.

> **Nota:** Tente esta parte apenas após concluir os **primeiros 10 módulos** do programa CEH.

---

## **Desafios – Parte II**

### **Desafio 1**

Você foi designado para realizar um **ataque de força bruta** contra uma máquina Linux da sub-rede `192.168.10.0/24` e quebrar as **credenciais FTP do usuário `nick`**.

Um arquivo com informações de exploração foi salvo no **diretório home do servidor FTP**.
Determine a **homepage do fabricante (vendor homepage)** da vulnerabilidade FTP especificada no arquivo.

**Formato:**
`aaaaa://aaa.aaaaaaaa.aaa/`

---

### **Desafio 2**

Um invasor realizou **sniffing de rede** em uma máquina da sub-rede `192.168.10.0/24` e obteve **credenciais de login** do site `moviescope.com` utilizando captura remota de pacotes no Wireshark.

Analise o arquivo `Mscredremote.pcapng`, localizado na pasta **Downloads** da **EH Workstation-1**, e determine as **credenciais obtidas**.

**Formato:**
`aaaa/aaaaa`

---

### **Desafio 3**

Você foi designado para analisar o arquivo de captura `ServerDoS.pcapng`, localizado na pasta **Downloads** da **EH Workstation-2**.

Determine o **protocolo da camada de aplicação baseado em UDP** que o atacante utilizou para inundar a máquina alvo.

> **Nota:** Verifique a **porta de destino**.

**Formato:**
`Aaaaa Aaaaaaa Aaaaaaaa`

---

### **Desafio 4**

Um ataque **DDoS severo** ocorreu em uma organização, degradando o desempenho de um servidor **Ubuntu** na rede `SKILL.CEH`.

Analise o arquivo `DD_attack.pcapng`, armazenado na pasta **Documents** da **EH Workstation-2**, e determine o **endereço IP do atacante** que realizou o ataque via UDP.

**Formato:**
`NNN.NNN.NN.NNN`

---

### **Desafio 5**

Analise o arquivo `PyD_attack.pcapng`, localizado na pasta **Downloads** da **EH Workstation-2**.

Determine o **IP do atacante** que está direcionando o ataque ao **serviço RPC** da máquina alvo.

**Formato:**
`NNN.NN.NN.NN`

---

### **Desafio 6**

Um analista de incidentes identificou um ataque DDoS severo e gerou um relatório usando a ferramenta **Anti-DDoS Guardian**.

Os relatórios estão em:
`C:\Users\Admin\Documents\Anti-DDoS` na **EH Workstation-1**.

Determine o **IP do atacante** que transmitiu o **maior número de pacotes** para a máquina alvo.

**Formato:**
`NNN.NNN.NN.NNN`

---

### **Desafio 7**

Você deve analisar o **Domain Controller** do ambiente alvo e realizar um **ataque AS-REP Roasting** nas contas de usuários.

Determine a **senha do usuário vulnerável** cujas credenciais foram obtidas.

> Use `users.txt` e `rockyou.txt` localizados no diretório home do atacante.

**Formato:**
`aNaaN*NNN`

---

### **Desafio 8**

Uma máquina cliente no domínio possui uma **vulnerabilidade de SQL Server mal configurado**.

Explore a vulnerabilidade, recupere o arquivo `MSS.txt` localizado em **Public Downloads** e determine o **tamanho do arquivo em bytes**.

**Formato:**
`N`

---

### **Desafio 9**

Quebre as **credenciais RDP** do usuário `Maurice` na sub-rede `192.168.10.0/24`.

Determine a senha.

**Formato:**
`Aaaaaaa@NNNN`

---

### **Desafio 10**

Realize **varredura de malware** no arquivo `Tools.rar`, localizado na pasta **Downloads** da **EH Workstation-2**.

Determine os **últimos quatro dígitos do hash SHA-256** do arquivo.

**Formato:**
`aNNN`

---

### **Desafio 11**

Analise o arquivo de log `Logfile.PML`, localizado na pasta **Pictures** da **EH Workstation-2**.

Determine o **Parent PID** do processo malicioso `H3ll0.exe`.

**Formato:**
`NNNN`

---

### **Desafio 12**

Analise o executável ELF `Tornado.elf`, localizado na pasta **Downloads** da **EH Workstation-2**.

Determine o **valor de entropia do arquivo**, com duas casas decimais.

**Formato:**
`N*NN`

---

### **Desafio 13**

Escaneie as sub-redes alvo para identificar a funcionalidade de **captura remota de pacotes (rpcap)**.

Determine o **IP da máquina** que utiliza o serviço rpcap.

**Formato:**
`NNN.NNN.NN.NNN`

---

### **Desafio 14**

Um ataque interno resultou na captura de dados confidenciais, que foram **ocultados e criptografados** em uma imagem `stealth.jpeg`.

Utilize a ferramenta **steghide** para extrair os dados ocultos.

> Senha: `azerty@123`

Determine o **valor da cotação** (tender quotation).

**Formato:**
`NNNNNNN`

---

### **Desafio 15**

Utilize a ferramenta **searchsploit** e determine o **caminho da vulnerabilidade AirDrop 2.0**.

**Formato:**
`aaaaaaa/aaa/NNNNN.a`