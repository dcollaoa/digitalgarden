## Nmap Scan

Empezamos con un escaneo rápido inicial de Nmap contra nuestro objetivo para tener una idea del terreno y ver con qué estamos lidiando. Nos aseguramos de guardar todos los resultados del escaneo en el subdirectorio relevante en nuestro directorio de proyecto.

```r
sudo nmap --open -oA inlanefreight_ept_tcp_1k -iL scope 

Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-20 14:56 EDT
Nmap scan report for 10.129.203.101
Host is up (0.12s latency).
Not shown: 989 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
25/tcp   open  smtp
53/tcp   open  domain
80/tcp   open  http
110/tcp  open  pop3
111/tcp  open  rpcbind
143/tcp  open  imap
993/tcp  open  imaps
995/tcp  open  pop3s
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 2.25 seconds
```

Notamos 11 puertos abiertos en nuestro escaneo rápido de los primeros 1,000 puertos TCP. Parece que estamos tratando con un servidor web que también ejecuta algunos servicios adicionales como FTP, SSH, correo electrónico (SMTP, POP3 e IMAP), DNS y al menos dos puertos relacionados con aplicaciones web.

Mientras tanto, hemos estado ejecutando un escaneo de puertos completo utilizando la flag `-A` ([Aggressive scan options](https://nmap.org/book/man-misc-options.html)) para realizar una enumeración adicional incluyendo detección del sistema operativo, escaneo de versiones y escaneo de scripts. Ten en cuenta que este es un escaneo más intrusivo que simplemente ejecutar con la flag `-sV` para escaneo de versiones, y debemos tener cuidado para asegurarnos de que cualquier script que se ejecute con el escaneo de scripts no cause ningún problema.

```r
sudo nmap --open -p- -A -oA inlanefreight_ept_tcp_all_svc -iL scope

Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-20 15:27 EDT
Nmap scan report for 10.129.203.101
Host is up (0.12s latency).
Not shown: 65524 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0              38 May 30 17:16 flag.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.15
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 71:08:b0:c4:f3:ca:97:57:64:97:70:f9:fe:c5:0c:7b (RSA)
|   256 45:c3:b5:14:63:99:3d:9e:b3:22:51:e5:97:76:e1:50 (ECDSA)
|_  256 2e:c2:41:66:46:ef:b6:81:95:d5:aa:35:23:94:55:38 (ED25519)
25/tcp   open  smtp     Postfix smtpd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-05-30T17:15:40
|_Not valid after:  2032-05-27T17:15:40
|_smtp-commands: ubuntu, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp   open  domain   
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|     bind
| dns-nsid: 
|_  bind.version: 
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Inlanefreight
110/tcp  open  pop3     Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-05-30T17:15:40
|_Not valid after:  2032-05-27T17:15:40
|_pop3-capabilities: SASL TOP PIPELINING STLS RESP-CODES AUTH-RESP-CODE CAPA UIDL
111/tcp  open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
143/tcp  open  imap     Dovecot imapd (Ubuntu)
|_imap-capabilities: LITERAL+ LOGIN-REFERRALS more Pre-login post-login ID capabilities listed have LOGINDISABLEDA0001 OK ENABLE IDLE STARTTLS SASL-IR IMAP4rev1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-05-30T17:15:40
|_Not valid after:  2032-05-27T17:15:40
993/tcp  open  ssl/imap Dovecot imapd (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-05-30T17:15:40
|_Not valid after:  2032-05-27T17:15:40
|_imap-capabilities: LITERAL+ LOGIN-REFERRALS AUTH=PLAINA0001 post-login ID capabilities more have listed OK ENABLE IDLE Pre-login SASL-IR IMAP4rev1
995/tcp  open  ssl/pop3 Dovecot pop3d
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-05-30T17:15:40
|_Not valid after:  2032-05-27T17:15:40
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: SASL(PLAIN) TOP PIPELINING CAPA RESP-CODES AUTH-RESP-CODE USER UIDL
8080/tcp open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-title: Support Center
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.92%I=7%D=6/20%Time=62B0CA68%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,39,"\x007\0\x06\x85\0\0\x01\0\x01\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03\xc0\x0c\0\x10\0\x03\0\0\0\0\0\r\x0c");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=6/20%OT=21%CT=1%CU=36505%PV=Y%DS=2%DC

=T%G=Y%TM=62B0CA8
OS:8%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST1
OS:1NW7%O6=M505ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: Host:  ubuntu; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   116.63 ms 10.10.14.1
2   117.72 ms 10.129.203.101

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 84.91 seconds
```

Lo primero que podemos ver es que este es un host Ubuntu que ejecuta algún tipo de proxy HTTP. Podemos usar esta práctica [cheatsheet](https://github.com/leonjza/awesome-nmap-grep) de Nmap grep para "cortar el ruido" y extraer la información más útil del escaneo. Vamos a extraer los servicios y números de servicio que están ejecutándose, para tenerlos a mano para una investigación adicional.

```r
egrep -v "^#|Status: Up" inlanefreight_ept_tcp_all_svc.gnmap | cut -d ' ' -f4- | tr ',' '\n' | \                                                               
sed -e 's/^[ \t]*//' | awk -F '/' '{print $7}' | grep -v "^$" | sort | uniq -c \
| sort -k 1 -nr

      2 Dovecot pop3d
      2 Dovecot imapd (Ubuntu)
      2 Apache httpd 2.4.41 ((Ubuntu))
      1 vsftpd 3.0.3
      1 Postfix smtpd
      1 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
      1 2-4 (RPC #100000)
```

De estos servicios que escuchan, hay varias cosas que podemos intentar de inmediato, pero como vemos que DNS está presente, intentemos una transferencia de zona DNS (DNS Zone Transfer) para ver si podemos enumerar algún subdominio válido para una mayor exploración y expandir nuestro alcance de pruebas. Sabemos por la hoja de alcance que el dominio principal es `INLANEFREIGHT.LOCAL`, así que veamos qué podemos encontrar.

```r
dig axfr inlanefreight.local @10.129.203.101

; <<>> DiG 9.16.27-Debian <<>> axfr inlanefreight.local @10.129.203.101
;; global options: +cmd
inlanefreight.local.	86400	IN	SOA	ns1.inlanfreight.local. dnsadmin.inlanefreight.local. 21 604800 86400 2419200 86400
inlanefreight.local.	86400	IN	NS	inlanefreight.local.
inlanefreight.local.	86400	IN	A	127.0.0.1
blog.inlanefreight.local. 86400	IN	A	127.0.0.1
careers.inlanefreight.local. 86400 IN	A	127.0.0.1
dev.inlanefreight.local. 86400	IN	A	127.0.0.1
gitlab.inlanefreight.local. 86400 IN	A	127.0.0.1
ir.inlanefreight.local.	86400	IN	A	127.0.0.1
status.inlanefreight.local. 86400 IN	A	127.0.0.1
support.inlanefreight.local. 86400 IN	A	127.0.0.1
tracking.inlanefreight.local. 86400 IN	A	127.0.0.1
vpn.inlanefreight.local. 86400	IN	A	127.0.0.1
inlanefreight.local.	86400	IN	SOA	ns1.inlanfreight.local. dnsadmin.inlanefreight.local. 21 604800 86400 2419200 86400
;; Query time: 116 msec
;; SERVER: 10.129.203.101#53(10.129.203.101)
;; WHEN: Mon Jun 20 16:28:20 EDT 2022
;; XFR size: 14 records (messages 1, bytes 448)
```

La transferencia de zona funciona, y encontramos 9 subdominios adicionales. En un compromiso real, si una transferencia de zona DNS no fuera posible, podríamos enumerar subdominios de muchas maneras. El sitio web [DNSDumpster.com](https://dnsdumpster.com/) es una apuesta rápida. El módulo `Information Gathering - Web Edition` enumera varios métodos para [Passive Subdomain Enumeration](https://academy.hackthebox.com/module/144/section/1252) y [Active Subdomain Enumeration](https://academy.hackthebox.com/module/144/section/1256).

Si DNS no estuviera en juego, también podríamos realizar una enumeración de vhost utilizando una herramienta como `ffuf`. Probemos aquí para ver si encontramos algo más que la transferencia de zona no detectó. Usaremos [esta lista de diccionario](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/namelist.txt) para ayudarnos, que se encuentra en `/opt/useful/SecLists/Discovery/DNS/namelist.txt` en la Pwnbox.

Para fuzzear vhosts, primero debemos averiguar cómo se ve la respuesta para un vhost inexistente. Podemos elegir cualquier cosa aquí; solo queremos provocar una respuesta, así que deberíamos elegir algo que muy probablemente no exista.

```r
curl -s -I http://10.129.203.101 -H "HOST: defnotvalid.inlanefreight.local" | grep "Content-Length:"

Content-Length: 15157
```

Intentar especificar `defnotvalid` en el encabezado del host nos da un tamaño de respuesta de `15157`. Podemos inferir que esto será lo mismo para cualquier vhost inválido, así que trabajemos con `ffuf`, usando la flag `-fs` para filtrar las respuestas con tamaño `15157` ya que sabemos que son inválidas.

```r
ffuf -w namelist.txt:FUZZ -u http://10.129.203.101/ -H 'Host:FUZZ.inlanefreight.local' -fs 15157

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.203.101/
 :: Wordlist         : FUZZ: namelist.txt
 :: Header           : Host: FUZZ.inlanefreight.local
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout

          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 15157
________________________________________________

blog                    [Status: 200, Size: 8708, Words: 1509, Lines: 232, Duration: 143ms]
careers                 [Status: 200, Size: 51810, Words: 22044, Lines: 732, Duration: 153ms]
dev                     [Status: 200, Size: 2048, Words: 643, Lines: 74, Duration: 1262ms]
gitlab                  [Status: 302, Size: 113, Words: 5, Lines: 1, Duration: 226ms]
ir                      [Status: 200, Size: 28545, Words: 2888, Lines: 210, Duration: 1089ms]
<REDACTED>              [Status: 200, Size: 56, Words: 3, Lines: 4, Duration: 120ms]
status                  [Status: 200, Size: 917, Words: 112, Lines: 43, Duration: 126ms]
support                 [Status: 200, Size: 26635, Words: 11730, Lines: 523, Duration: 122ms]
tracking                [Status: 200, Size: 35185, Words: 10409, Lines: 791, Duration: 124ms]
vpn                     [Status: 200, Size: 1578, Words: 414, Lines: 35, Duration: 121ms]
:: Progress: [151265/151265] :: Job [1/1] :: 341 req/sec :: Duration: [0:07:33] :: Errors: 0 ::
```

Comparando los resultados, vemos un vhost que no estaba en los resultados de la transferencia de zona DNS que realizamos.

---

## Resultados de la Enumeración

De nuestra enumeración inicial, notamos varios puertos interesantes abiertos que investigaremos más a fondo en la siguiente sección. También reunimos varios subdominios/vhosts. Agreguemos estos a nuestro archivo `/etc/hosts` para investigar cada uno más a fondo.

```r
sudo tee -a /etc/hosts > /dev/null <<EOT

## inlanefreight hosts 
10.129.203.101 inlanefreight.local blog.inlanefreight.local careers.inlanefreight.local dev.inlanefreight.local gitlab.inlanefreight.local ir.inlanefreight.local status.inlanefreight.local support.inlanefreight.local tracking.inlanefreight.local vpn.inlanefreight.local
EOT
```

En la siguiente sección, profundizaremos en los resultados del escaneo de Nmap y veremos si podemos encontrar algún servicio directamente explotable o mal configurado.