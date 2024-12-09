# PlayBook

# Scans

## Ping

```powershell
ping <ip address>
```

## NMap

```powershell
nmap -sV 10.10.11.214 -o nmap-sV.txt
```

```jsx
nmap -Pn 10.10.11.214 -o nmap-pn.txt
```

```jsx

```

```jsx
nmap -sV -Pn -sC 10.10.11.214 -p 50000-55555 -oN nmap-sV-Pn-sC.txt
```

 

```bash
sudo nmap -sC -sV -O -A  10.10.11.16 -oA nmap-sC-sV-O-A.txt -v

```

perform a simple host discovery scan on a network range
nmap -sn 192.168.1.0/24
perform an OS detection scan on a specific host
nmap -O 192.168.1.1
perform a service and version detection scan on a specific host
nmap -sV 192.168.1.1
perform a more in-depth scan on a specific host
nmap -A 192.168.1.1

nmap 10.10.11.189 -p 1-65535 -T5

## Whatweb Scan

$ whatweb 10.10.11.13

## ping:

-c: This flag specifies the number of packets to send. For example, to send 5 packets, you would use:
ping -c 5 [google.com](http://google.com/)
-i: This flag specifies the interval between sending packets, in seconds. For example, to send packets every 2 seconds, you would use:
ping -i 2 [google.com](http://google.com/)
-w: This flag specifies the deadline for waiting for a response, in seconds. For example, to wait for 10 seconds for a response, you would use:
ping -w 10 [google.com](http://google.com/)
-s: This flag specifies the size of the packets to send, in bytes. For example, to send packets of 1000 bytes, you would use:
ping -s 1000 [google.com](http://google.com/)
-v: This flag increases the verbosity of the output, providing more detailed information about each packet. For example, to enable verbose output, you would use:
ping -v [google.com](http://google.com/)
-n: This flag disables hostname resolution, which can speed up the ping command if you only care about the IP address. For example, to disable hostname resolution, you would use:
ping -n 8.8.8.8

## Wpscan:

//test
Basic scan of a WordPress site:
wpscan --url [https://example.com/](https://example.com/)
Enumerate plugins and themes installed on the site:
wpscan --url [https://example.com/](https://example.com/) --enumerate p,t
Perform a password attack using a custom wordlist:
wpscan --url [https://example.com/](https://example.com/) --passwords /path/to/wordlist.txt
Scan a site with an invalid SSL certificate:
wpscan --url [https://example.com/](https://example.com/) --disable-tls-checks
Specify a custom path to the WordPress content directory:
wpscan --url [https://example.com/](https://example.com/) --wp-content-dir wp-content/custom/
Check for vulnerabilities in a specific WordPress version:
wpscan --url [https://example.com/](https://example.com/) --wp-version 5.8
Set a random user agent string for the scan:
wpscan --url [https://example.com/](https://example.com/) --random-agent

## crackmapexec

```bash

crackmapexec smb solarlab.htb -u Guest -p "" --shares
```

- **`crackmapexec`**: Dies ist ein Befehlszeilen-Dienstprogramm, das für die Post-Exploitation und Enumeration in Windows-Netzwerken verwendet wird. Es wird hauptsächlich verwendet, um Netzwerkschwachstellen zu identifizieren und auszunutzen.
- **`smb`**: Dies gibt das Protokoll an, das verwendet werden soll, in diesem Fall Server Message Block (SMB). SMB ist ein Netzwerkdateifreigabeprotokoll, das hauptsächlich zum Bereitstellen gemeinsamen Zugriffs auf Dateien, Drucker und serielle Anschlüsse verwendet wird.
- **`solarlab.htb`**: Dies ist der Hostname oder die IP-Adresse der Zielmaschine. In diesem Fall scheint die Zielmaschine "solarlab" zu heißen, mit der Domain ".htb", was darauf hinweisen könnte, dass sie Teil eines fiktiven Netzwerks oder einer Laborumgebung ist.
- **`u Gast`**: Dies gibt den Benutzernamen an, der für die Authentifizierung verwendet werden soll. In diesem Fall versucht es, sich als Gastbenutzer zu authentifizieren.
- **`p ""`**: Dies gibt das Passwort an, das für die Authentifizierung verwendet werden soll. In diesem Fall handelt es sich um ein leeres Passwort, angegeben durch **`""`**.
- **`-shares`**: Dieser Parameter fordert das Tool auf, die verfügbaren Freigaben auf der Zielmaschine aufzulisten, sobald es authentifiziert ist.

# Host bearbeiten

sudo nano  /etc/hosts

10.10.11.230      cozyhosting.htb

# TTY Spawn

TTY Spawn Shell -> Pythonversionbeachten die auch dem systhemläuft

Often during pen tests you may obtain a shell without having tty, yet wish to interact further with the system. Here are some commands which will allow you to spawn a tty shell. Obviously some of this will depend on the system environment and installed packages.
All the steps to stabilize your shell
The first step:

python3 -c 'import pty;pty.spawn("/bin/bash")'

Which uses Python to spawn a better-featured bash shell. At this point, our shell will look a bit prettier, but we still won’t be able to use tab autocomplete or the arrow keys.
Step two is:

export TERM=xterm

This will give us access to term commands such as clear.
Finally (and most importantly) we will background the shell using

Ctrl + Z

Back in our own terminal we use

stty raw -echo; fg

This does two things: first, it turns off our own terminal echo which gives us access to tab autocompletes, the arrow keys, and Ctrl + C to kill processes

stty rows 38 columns 116

# Netcat Listener

nc -lvp [port]
Where:

nc is the command for netcat.
-l flag means that netcat should listen for incoming connections.
-v flag means that netcat should be verbose and display information about the connection.
-p [port] flag means that netcat should listen on the specified port.

## Netstat??

gitb die aktuellen Active Internet connections (servers and established)

netstat -lantp

# Hochladen von Daten

Wget 

# WebServer

python3 -m http.server 8765

# Metasploit Framework??

# Burp Suite??

-FoxyProxy Browser Addon

nicht gebraucht da eigentn brausen enthöt

Subdomain suchen:

> sudo apt install seclists
    > wfuzz -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u [http://permx.htb/](http://permx.htb/) -H 'Host: FUZZ.permx.htb' -t 50 --hc 302

# directory bruteforce?

dirsearch -u <xxx> -e php -w /usr/share/wordlists/wfuzz/general/common.txt -r

dirsearch -o dirsearch.out -u <xxx>

## Gostbuster

Ersellen einer Wordliste

cewl -d 0 -m 4 -w words_runner -v --lowercase --with-numbers [http://runner.htb](http://runner.htb/)

Wordlist erzeugen:
cewl -d 0 -m 4 -w words_runner -v --lowercase --with-numbers [http://runner.htb](http://runner.htb/)

Wordlist benutzen

gobuster vhost -o gobuster-subdomain_words.txt -u [http://runner.htb/](http://runner.htb/) -w words_runner --append-domain -k -t 200

gobuster dns -d permx.htb -w ~/wordlists/subdomains.txt 

gobuster vhost -o gobuster-subdomain_words.txt -u [http://runner.htb/](http://runner.htb/) -w words_runner --append-domain -k -t 200

- Scan a website (`-u http://192.168.0.155/`) for directories using a wordlist (`-w /usr/share/wordlists/dirb/common.txt`) and print the full URLs of discovered paths (`-e`):gobuster dir -c html.pdf,php,txt -u <[http://xxxyxxxxyxyxyyxxyx.de/](http://pilgrimage.htb/)> -o gobuster-out -w /usr/share/wordlists/dirb/common.txt
    
    Gobuster ist ein kostenloses, Open-Source-Tool, das zur Schwachstellensuche in Webservern verwendet wird. Es ist ein Brute-Force-Wordlist-Scanner, der eine Liste von Wörtern und Phrasen verwendet, um auf Dateien und Verzeichnisse zuzugreifen, die normalerweise nicht über die Weboberfläche sichtbar sind.
    
    Gobuster kann mit einer Vielzahl von Optionen verwendet werden, um eine Vielzahl von Schwachstellen zu identifizieren. Einige der häufigsten Verwendungszwecke von Gobuster sind:
    
    - Dateien und Verzeichnisse finden, die nicht über die Weboberfläche sichtbar sind
    - Schwachstellen in Dateinamenskonventionen identifizieren
    - Schwachstellen in Verzeichnisstrukturen identifizieren
    - Schwachstellen in Webserverkonfigurationen identifizieren
    
    Um Gobuster zu verwenden, müssen Sie die Gobuster-Binärdatei herunterladen und in Ihr Verzeichnis ausführen. Sobald Sie Gobuster installiert haben, können Sie es mit dem folgenden Befehl ausführen:
    
    `gobuster dir -w /usr/share/wordlists/dirb/common.txt -u https://example.com`
    
    Dieser Befehl führt Gobuster dazu auf, die URL https://example.com zu scannen und alle Dateien und Verzeichnisse zu finden, die in der Wortliste /usr/share/wordlists/dirb/common.txt enthalten sind.
    
    Gobuster kann auch mit einer Vielzahl anderer Optionen verwendet werden, um die Scantiefe, die Scangeschwindigkeit und die Art der zu scannenden Dateien zu steuern. Weitere Informationen zu den Gobuster-Optionen finden Sie in der Gobuster-Dokumentation.
    
    Hier ist ein Beispiel für die Ausgabe von Gobuster:
    
    `[100%]    Potentially interesting directories found:
        /admin (Status: 200)
        /images (Status: 200)
        /robots.txt (Status: 200)
        ```
    
    Diese Ausgabe zeigt, dass Gobuster drei Dateien oder Verzeichnisse gefunden hat, die potentiell interessant sind: /admin, /images und /robots.txt. Diese Dateien oder Verzeichnisse sollten weiter untersucht werden, um festzustellen, ob sie Schwachstellen aufweisen.
    
    Gobuster ist ein leistungsstarkes Tool, das zur Schwachstellensuche in Webservern verwendet werden kann. Es ist einfach zu bedienen und kann mit einer Vielzahl von Optionen verwendet werden, um eine Vielzahl von Schwachstellen zu identifizieren.`
    

## Dirb?

## knockpy

**Knockpy** is a portable and modular `python3` tool designed to quickly enumerate subdomains on a target domain through *passive reconnaissance* and *dictionary scan*.

knockpy -d 10.10.11.13  

[https://github.com/guelfoweb/knock](https://github.com/guelfoweb/knock)

## ffuf

ffuf -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -u [http://runner.htb/](http://runner.htb/) -H "Host: FUZZ.runner.htb" -fw 4

ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "HOST: FUZZ.board.htb" -u [http://board.htb/](http://board.htb/) -fs 15949

# Analyse von Datein

## exiftool??

7z @datei

[https://blog.csdn.net/qq_51886509/article/details/137895917](https://blog.csdn.net/qq_51886509/article/details/137895917)

[Wildcards Spare tricks | HackTricks | HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks#id-7z)

## **identify**

todo: auslager

Das `identify`-Tool in Linux ist ein Befehlszeilenprogramm, das verwendet werden kann, um Informationen über ein Bild zu erhalten. Es kann verwendet werden, um die Größe, Auflösung, Farbe und Komprimierungsmethode des Bildes zu erhalten. Es kann auch verwendet werden, um den Dateinamen und den Dateityp des Bildes zu erhalten.

Um `identify` zu verwenden, geben Sie einfach den Namen des Bildes als Argument an. Beispielsweise würde der folgende Befehl die Informationen über das Bild `image.jpg` abrufen:

`identify image.jpg`

Die Ausgabe von `identify` würde wie folgt aussehen:

`Image: image.jpg
Format: JPEG (Joint Photographic Experts Group JFIF format)
Size: 320x240
Resolution: 72x72
Bit depth: 8-bit
Colorspace: RGB
Interlace: JPEG`

Das `identify`-Tool kann auch verwendet werden, um mehrere Bilder gleichzeitig zu identifizieren. Geben Sie einfach die Namen aller Bilder als Argumente an, getrennt durch Leerzeichen. Beispielsweise würde der folgende Befehl die Informationen über die Bilder `image1.jpg`, `image2.jpg` und `image3.jpg` abrufen:

`identify image1.jpg image2.jpg image3.jpg`

Die Ausgabe von `identify` würde wie folgt aussehen:

`Image: image1.jpg
Format: JPEG (Joint Photographic Experts Group JFIF format)
Size: 320x240
Resolution: 72x72
Bit depth: 8-bit
Colorspace: RGB
Interlace: JPEG

Image: image2.jpg
Format: JPEG (Joint Photographic Experts Group JFIF format)
Size: 640x480
Resolution: 96x96
Bit depth: 8-bit
Colorspace: RGB
Interlace: JPEG

Image: image3.jpg
Format: PNG (Portable Network Graphics)
Size: 1280x1024
Resolution: 72x72
Bit depth: 8-bit
Colorspace: RGB
Interlace: None`

Das `identify`-Tool ist ein nützliches Tool, das verwendet werden kann, um Informationen über Bilder zu erhalten. Es kann verwendet werden, um die Größe, Auflösung, Farbe, Komprimierungsmethode, den Dateinamen und den Dateityp eines Bildes abzurufen.

Es gibt viele mögliche Flags, die verwendet werden können, um die Ausgabe von `identify` zu ändern. Einige der häufigsten Flags sind:

- `format`: Gibt das Format der Ausgabe an. Mögliche Werte sind "text", "xml" oder "json".
- `verbose`: Gibt zusätzliche Informationen über das Bild aus.
- `quiet`: Gibt keine Ausgabe aus.
- `list`: Gibt eine Liste der unterstützten Bildformate aus.
- `help`: Gibt die Hilfe zu `identify` aus.

Um mehr über die verschiedenen Flags zu erfahren, können Sie die `identify`-Hilfe aufrufen, indem Sie den Befehl `identify --help` ausführen.

Hier sind einige Beispiele für die Verwendung von Flags mit `identify`:

- Um die Ausgabe in einem XML-Format zu erhalten, führen Sie den folgenden Befehl aus:

`identify -format xml image.jpg`

- Um zusätzliche Informationen über das Bild auszugeben, führen Sie den folgenden Befehl aus:

`identify -verbose image.jpg`

- Um keine Ausgabe auszugeben, führen Sie den folgenden Befehl aus:

`identify -quiet image.jpg`

- Um eine Liste der unterstützten Bildformate zu erhalten, führen Sie den folgenden Befehl aus:

`identify -list`

- Um die Hilfe zu `identify` aufzurufen, führen Sie den folgenden Befehl aus:

`identify --help`

# Analysen

## Wireshark??

nrtzwerk verker anschauen!

## 

## analysen von Pozessen

### Linepace

# Injection

SQL Injection

ImageMagick bug discovered by [https://www.metabaseq.com/imagemagick-zero-days/](https://www.metabaseq.com/imagemagick-zero-days/)
https://github.com/voidz0r/CVE-2022-44268

SQLmap ??

sqlmap -r reset.req -p email --batch --dbms=mysql --level=5 --risk=3
finally finds a valid sqli

sqlmap -r reset.req -p email --batch --dbms=mysql --level=5 --risk=3 -D usage_blog -T admin_users -C username,password - -dump

sudo sqlmap -r reset.req -p email --batch --dbms=mysql --level=5 --risk=3 \nfinally finds a valid sqli

# Sonstiges

alias ll='ls -la'

ipconfig ??

## Protokolle

### SSH??
sudo ssh [henry@10.10.11.189](mailto:henry@10.10.11.189)

-i verbindet über den privet? Key des systems

ssh -i /home/kali/.ssh/user [dash@10.10.11.18](mailto:dash@10.10.11.18) -vvv   

### telnet:

Der Befehl "telnet 10.10.11.249 25565" öffnet eine Verbindung zu einem Server mit der IP-Adresse "10.10.11.249" und dem Port "25565" über das Telnet-Protokoll. Telnet ist ein Netzwerkprotokoll, das eine bidirektionale interaktive Textorientierung über eine Terminalverbindung ermöglicht.

In diesem speziellen Fall wird versucht, eine Verbindung zu einem Server aufzubauen, der wahrscheinlich auf dem Port 25565 läuft. Dieser Port wird oft von Minecraft-Servern verwendet. Wenn die Verbindung erfolgreich hergestellt wird, könnte dies bedeuten, dass der Minecraft-Server auf diesem Host läuft und auf Verbindungen auf diesem Port wartet.

- SMTP/Imap
-DNS
-http
-SSL
-IPSec
-SQL
-Telnet
-NTP

## Hashcat??/h

hashcat -m 3200 --username hash ~/Desktop/KaliShare/rockyou.txt

## John the Ripper

john --format=<hash_type> <hash_file>

**`$2a$07$q.m8WQP8niXODv55lJVovOmxGtg6K/YPHbD48/JQsdGLulmeVo.Em`**: This is likely a hashed password for the user

Impacket??

# Linux Comandos

ls -la
grap          find . | grap Suchbegriff
find.
locate documet
mkdir
chmod

# Kurs Heise

## Passives scannen

Softwardeteils sammel
öffentliche Inforamtionen
sozieale netzwerke
programm sherlock scannt benuzer nahmen nach verwendeung in anderen seiten

Wappalyzer Browser Addon
Wappalyzer is a tool that helps you identify technologies on websites. It can be used for lead generation, market analysis, and competitor research.
sublist3r Pytehon programm zum analyisienen von subdomains

## GEgenmaßnahmen
Informatione reduzieren und kalssiviatioen
BSI Stander IT-GrundschutzMethodik
Selbsttest
[https://haveibeenpwned.com/](https://haveibeenpwned.com/)[builtwith.com](http://builtwith.com/)
wappalyzer check

Aktives scannen
Enummeration
Fuzzing -Codeinjection
Automatisirte scaner -Wpscan

Exploitation
Buffer Overflow -dirty cow
Codeinjection -SOL Injection
Legitime Funktionenmissbrauchen -Developertool

Post-Explonation
Privilege Escalation -Root Rechte
File Transfer

Lateral Movement -Domain Admin

Persisitence Clean-up
CronJob -Dauerhafteverbindun

Cleanup -Verbundugsdatenlöschen

## Grundlagen und Setup

- ISO/OSI- und TCP/IP-Modell
- MAC- und IP-Adressen
- TCP und UDP
- Was passiert in der Anwendungsschicht?
- Installation der Virtualbox und Konfiguration der VM
- Installation von Kali Linux
- Grundlagen Kali Linux
- Linux-Berechtigungen und apt-get
- Die 5 Phasen des Hacking

## Passives Sammeln von Informationen

- Wie sammelt ein Angreifer öffentliche Informationen?
- Burp Suite einrichten
- So sammelt ein Angreifer Zugangsdaten
- Subdomains als Angriffsziel
- Passives Scannen in sozialen Netzwerken
- Wie schützt man sich vor passivem Scannen?
- Sensibilisierung zum Schutz vor Angriffen
- Selbsttests zum Schutz vor passivem Scannen

## Aktives Scannen


- Mit Nmap offene Ports erkennen
- Scannen eines HTTP-Ports
- Schwachstellen in Software durchsuchen
- Über Protokolle SMB und SSH angreifen
- Post-Exploit Scanning
- Zum Schutz unnötige Dienste deaktivieren
- Standardfreigaben in Windows bearbeiten
- Schwachstellenmanagement

## Exploitation

- Pentesting mit Metasploit
- Reverse Shell vs. Bind Shell
- Web Shell mit Basic Pentesting 1
- Web Exploit mit Metasploit
- Sichere Passwörter verwenden
- Präventive Maßnahmen gegen Exploits
- Reaktive Maßnahmen gegen Exploits
- Physische Sicherheit gewährleisten

## Active Directory

- Setup des Active Directory
- Aufbau des Active Diretory
- Authentifizierung in Active-Directory-Netzwerken
- NTLM-Relaying-Angriffe
- Poisoning und Relay-Angriffe verhindern
- mitm6-Angriff vorbereiten
- mitm6-Angriff durchführen
- Vor mitm6-Angriffen schützen
- Bloodhound-Angriff vorbereiten
- Bloodhound-Angriff durchführen
- Kerberoasting, Token und Ticket-Angriffe

## Post-Exploitation

- Angriffe per Datentransfer und Lateral Movement
- Rechteausweitung mit Linux Privilege Escalation
- Privilege Escalation Basic Pentesting 2
- Kritische Schwachstellen in Microsoft Windows finden
- Lateral Movement erkennen und verhindern
- Privilege Escalation erkennen und verhindern
- Persistence: Dauerhaften Zugriff erlangen

## Sicherheitslücken in Anwendungen:

- Buffer Overflow
- Intro
- Übersicht und Tools
- Softwaretests: Fuzzing
- Mit Shellcode Programme manipulieren
- Exploit ausführen
- Buffer Overflow verhindern
- Quiz: Sicherheitslücken in Anwendungen: - Buffer Overflow
- Fazit und Kursabschluss

