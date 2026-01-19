# **CEH Engage – Parte IV**

## **Descrição**

A **Parte 4 do CEH Engage** abrange os seguintes módulos do CEH:

* **Hacking de Redes Wireless**
* **Hacking de Plataformas Mobile**
* **Hacking de IoT e OT**
* **Cloud Computing**
* **Criptografia**

Nesta etapa, você deverá **analisar capturas de pacotes wireless**, utilizar **diferentes vetores de ataque para explorar dispositivos móveis** e **auditar sistemas e redes IoT e OT** em busca de ameaças conhecidas.

Todas as informações descobertas nesta fase devem ser **registradas**, pois representam a conclusão do ciclo prático do CEH Engage.

> **Nota:** Tente esta parte **somente após concluir todos os 20 módulos** do programa CEH.

---

## **Desafios – Parte IV**

---

### **Desafio 1**

Um dispositivo móvel de um funcionário da **CEHORG** foi comprometido, resultando na criação de uma **mensagem criptografada** chamada `BCtetx.txt` no sistema operacional **Android**.

A **senha necessária para descriptografar o arquivo** está salva na **EH Workstation-1**.

Como hacker ético, sua tarefa é **descriptografar o arquivo utilizando a senha** e informar o **conteúdo extraído**.

> **Nota:** O arquivo de senha `pawned.txt` está armazenado na pasta **Documents**.

**Formato:**
`*aaaaAN*NaN`

---

### **Desafio 2**

Um dispositivo Android comprometido é suspeito de conter **aplicações maliciosas**.

Como hacker ético, você deve **identificar e extrair todos os arquivos APK instalados**.

Dentro desses APKs, você deve **localizar e extrair um valor CRC específico que termina com “614c”**.
Esse valor CRC é considerado um componente crucial para a investigação de uma grande violação de segurança.

Determine o **valor completo do CRC**.

**Formato:**
`NNaaNNNa`

---

### **Desafio 3**

Um arquivo ZIP contendo **imagens redundantes de uma assinatura física** foi comprometido (`signature.zip`) e armazenado na pasta **Documents** da **EH Workstation-1**.

Seu papel como hacker ético é realizar uma **análise forense** do conteúdo do arquivo para identificar a **imagem cujo hash MD5 termina com a sequência “24CCB”**.

Determine o **nome original do arquivo da assinatura**.

**Formato:**
`aN*aaa`

---

### **Desafio 4**

Como analista de cibersegurança, você está investigando uma **possível campanha de phishing** direcionada a **Ruby**, uma funcionária de uma empresa de tecnologia local.

Você tem acesso ao **registro de chamadas (call log)** de Ruby dos últimos dias, armazenado em um **dispositivo Android** dentro da sub-rede `192.168.10.0/24`.

Identifique a **chamada com maior probabilidade de ser uma tentativa de phishing** e informe o **número de telefone suspeito**.

**Formato:**
`+N (NNN) NNN-NNNN`

---

### **Desafio 5**

Um dispositivo móvel de um funcionário foi comprometido e é suspeito de estar sendo utilizado para lançar um **ataque de Negação de Serviço (DoS)** contra um dos servidores internos da empresa.

Sua tarefa é realizar uma **análise detalhada da captura de rede** `And_Dos.pcapng`, localizada na pasta **Documents** da **EH Workstation-2**, e identificar o **nível de severidade / impacto potencial do ataque**.

> Execute uma **análise profunda usando o Expert Info**.

**Formato:**
`Aaaaaaa`

---

### **Desafio 6**

A CEHORG gerencia diversos dispositivos e sensores **IoT** para monitorar sua **cadeia logística**.

Você deve analisar o arquivo `MQTT.pcapng`, localizado no **diretório Home** da **EH Workstation-2**.

Analise o pacote que contém a mensagem **“High_humidity”** e determine o **percentual de alerta** especificado na mensagem.

**Formato:**
`NN`

---

### **Desafio 7**

Um invasor enviou um arquivo `cryt-128-06encr.hex` contendo a **senha de um arquivo de ransomware**, localizado na pasta **Documents** da **EH Workstation-2**.

Você deve **descriptografar o arquivo utilizando a ferramenta cryp**.

Realize a **criptoanálise**, identifique:

* O **algoritmo de criptografia utilizado**
* O **texto oculto**

> **Nota:** Verifique o nome do arquivo para identificar o **tamanho da chave** e observe que o conteúdo está em **formato hexadecimal**.

**Formato:**
`Aaaaaaa/**aa**aA*a`

---

### **Desafio 8**

Um volume **VeraCrypt** chamado `MyVeracrypt` está armazenado na pasta **Documents** da **EH Workstation-1**.

Você foi designado para **descriptografar o volume** e determinar o **número de arquivos armazenados dentro da pasta do volume**.

> **Dica:** Senha: `veratest`

**Formato:**
`N`

---

### **Desafio 9**

Um ex-funcionário da CEHORG é suspeito de ter realizado um **ataque interno (insider attack)**.

Utilizando a ferramenta **PhoneSploit**, recupere o **dump de contatos** do telefone Android do funcionário e identifique o **código do país** do contato chamado **“Maddy”**.

> **Nota:** Use a opção **‘N’** no PhoneSploit para avançar para a próxima página.

**Formato:**
`NN`

---

### **Desafio 10**

A CEHORG utiliza diversos sensores e dispositivos IoT para monitoramento.

Utilizando novamente o arquivo `MQTT.pcapng`, localizado no **diretório Home** da **EH Workstation-2**, analise o pacote que contém a mensagem **“High_temperature”** e determine o **tamanho do tópico (topic length)**.

**Formato:**
`NN`

---

### **Desafio 11**

Um ex-funcionário da CEHORG é suspeito de realizar um **ataque interno**.

Você deve obter o **KEYCODE-5** utilizado no telefone móvel do funcionário.

> **Nota:** Use a opção **‘N’** no PhoneSploit para navegar entre as páginas.

**Formato:**
`Aaaaa*Aaaaaa`

---

### **Desafio 12**

Um funcionário da CEHORG adquiriu secretamente um **ID de acesso confidencial** por meio de um aplicativo da empresa.

Essas informações foram salvas na pasta **Music** do telefone Android do funcionário.

Você foi designado para **acessar o arquivo e excluí-lo de forma furtiva**, informando o **conteúdo da conta presente no arquivo**.

> **Nota:** Informe **apenas os valores numéricos**.

**Formato:**
`NNNNNNNN`

---

### **Desafio 13**

Um atacante comprometeu um dispositivo Android de um funcionário da CEHORG e iniciou um **ataque LOIC** a partir do dispositivo.

Você obteve uma **captura de tela do ataque**, coletada por um aplicativo em segundo plano.

Utilizando o **PhoneSploit**, recupere a imagem e determine o **número de pacotes HTTP enviados por segundo**.

**Formato:**
`NN`

---

### **Desafio 14**

Você recebeu uma pasta chamada **“Archive”** de um fornecedor e suspeita que os arquivos tenham sido **adulterados durante a transmissão**.

Os **hashes originais** dos arquivos estão armazenados em `FileHashes.txt`, localizado na pasta **Documents** da **EH Workstation-2**.

Compare os **hashes MD5** e determine **qual arquivo foi adulterado**.

> **Nota:**
>
> * Exclua a **extensão do arquivo** na resposta
> * A resposta é **case-sensitive**

**Formato:**
`Aaaaaa`

---

### **Desafio 15**

Um volume **VeraCrypt** chamado `secret` está armazenado na pasta **Documents** da **EH Workstation-2**.

Você deve **descriptografar o volume** e determinar o **número de arquivos armazenados dentro dele**.

> **Dica:** Senha: `test`

**Formato:**
`N`