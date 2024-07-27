## Listening Services

Nuestros escaneos Nmap descubrieron algunos servicios interesantes:

- Port 21: FTP
- Port 22: SSH
- Port 25: SMTP
- Port 53: DNS
- Port 80: HTTP
- Ports 110/143/993/995: imap & pop3
- Port 111: rpcbind

Ya realizamos una DNS Zone Transfer durante nuestra recolección inicial de información, lo que arrojó varios subdominios que investigaremos más adelante. Otros ataques DNS no valen la pena intentar en nuestro entorno actual.

---

## FTP

Comencemos con FTP en el puerto 21. El escaneo agresivo de Nmap descubrió que el login anónimo FTP era posible. Confirmémoslo manualmente.

```r
ftp 10.129.203.101

Connected to 10.129.203.101.
220 (vsFTPd 3.0.3)
Name (10.129.203.101:tester): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0              38 May 30 17:16 flag.txt
226 Directory send OK.
ftp>
```

Conectarse con el usuario `anonymous` y una contraseña en blanco funciona. No parece que podamos acceder a ningún archivo interesante aparte de uno, y tampoco podemos cambiar de directorios.

```r
ftp> put test.txt 

local: test.txt remote: test.txt
200 PORT command successful. Consider using PASV.
550 Permission denied.
```

Tampoco podemos subir un archivo.

Otros ataques, como un FTP Bounce Attack, son poco probables, y no tenemos información sobre la red interna aún. Buscar exploits públicos para vsFTPd 3.0.3 solo muestra [este](https://www.exploit-db.com/exploits/49719) PoC para un `Remote Denial of Service`, que está fuera del alcance de nuestras pruebas. La fuerza bruta tampoco nos ayudará aquí ya que no conocemos ningún nombre de usuario.

Parece que esto es un callejón sin salida. Continuemos.

---

## SSH

El siguiente es SSH. Comenzaremos con un banner grab:

```r
nc -nv 10.129.203.101 22

(UNKNOWN) [10.129.203.101] 22 (ssh) open
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
```

Esto nos muestra que el host está ejecutando OpenSSH versión 8.2, que no tiene vulnerabilidades conocidas al momento de escribir esto. Podríamos intentar alguna fuerza bruta de contraseñas, pero no tenemos una lista de nombres de usuario válidos, así que sería un tiro al aire. También es dudoso que podamos forzar la contraseña de root. Podemos intentar algunas combinaciones como `admin:admin`, `root:toor`, `admin:Welcome`, `admin:Pass123` pero sin éxito.

```r
ssh admin@10.129.203.101

The authenticity of host '10.129.203.101 (10.129.203.101)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.203.101' (ECDSA) to the list of known hosts.
admin@10.129.203.101's password: 
Permission denied, please try again.
```

SSH también parece un callejón sin salida. Veamos qué más tenemos.

---

## Email Services

SMTP es interesante. Podemos consultar la sección [Attacking Email Services](https://academy.hackthebox.com/module/116/section/1173) del módulo `Attacking Common Services` para obtener ayuda. En una evaluación del mundo real, podríamos usar un sitio web como [MXToolbox](https://mxtoolbox.com/) o la herramienta `dig` para enumerar MX Records.

Hagamos otro escaneo contra el puerto 25 para buscar configuraciones erróneas.

```r
sudo nmap -sV -sC -p25 10.129.203.101

Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-20 18:55 EDT
Nmap scan report for inlanefreight.local (10.129.203.101)
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
25/tcp open  smtp    Postfix smtpd
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-05-30T17:15:40
|_Not valid after:  2032-05-27T17:15:40
|_smtp-commands: ubuntu, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
|_ssl-date: TLS randomness does not represent time
Service Info: Host:  ubuntu

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 5.37 second
```

A continuación, verificaremos cualquier configuración incorrecta relacionada con la autenticación. Podemos intentar usar el comando `VRFY` para enumerar usuarios del sistema.

```r
telnet 10.129.203.101 25

Trying 10.129.203.101...
Connected to 10.129.203.101.
Escape character is '^]'.
220 ubuntu ESMTP Postfix (Ubuntu)
VRFY root
252 2.0.0 root
VRFY www-data
252 2.0.0 www-data
VRFY randomuser
550 5.1.1 <randomuser>: Recipient address rejected: User unknown in local recipient table
```

Podemos ver que el comando `VRFY` no está deshabilitado y podemos usarlo para enumerar usuarios válidos. Esto podría aprovecharse para reunir una lista de usuarios que podríamos usar para montar un ataque de fuerza bruta de contraseñas contra los servicios FTP y SSH y quizás otros. Aunque esto es relativamente de bajo riesgo, vale la pena anotarlo como un hallazgo `Low` para nuestro informe, ya que nuestros clientes deben reducir su superficie de ataque externa tanto como sea posible. Si no hay una razón válida de negocio para que este comando esté habilitado, entonces deberíamos aconsejarles que lo deshabiliten.

Podríamos intentar enumerar más usuarios con una herramienta como [smtp-user-enum](https://github.com/pentestmonkey/smtp-user-enum) para demostrar el punto y potencialmente encontrar más usuarios. Típicamente no vale la pena pasar mucho tiempo forzando la autenticación para servicios expuestos externamente. Esto podría causar una interrupción del servicio, por lo que incluso si podemos hacer una lista de usuarios, podemos intentar algunas contraseñas débiles y seguir adelante.

Podríamos repetir este proceso con los comandos `EXPN` y `RCPT TO`, pero no produciría nada adicional.

El protocolo `POP3` también puede usarse para enumerar usuarios dependiendo de cómo esté configurado. Podemos intentar enumerar usuarios del sistema con el comando `USER` nuevamente, y si el servidor responde con `+OK`, el usuario existe en el sistema. Esto no funciona para nosotros. Sondear el puerto 995, el puerto SSL/TLS para POP3, tampoco produce nada.

```r
telnet 10.129.203.101 110

Trying 10.129.203.101...
Connected to 10.129.203.101.
Escape character is '^]'.
+OK Dovecot (Ubuntu) ready.
user www-data
-ERR [AUTH] Plaintext authentication disallowed on non-secure (SSL/TLS) connections.
```

El módulo [Footprinting](https://academy.hackthebox.com/module/112/section/1073) contiene más información sobre servicios comunes y principios de enumeración y vale la pena revisarlo nuevamente después de trabajar en esta sección.

En una evaluación del mundo real, querríamos investigar más sobre la implementación del correo electrónico del cliente. Si están usando Office 365 o Exchange on-prem, podríamos montar un ataque de password spraying que podría dar acceso a buzones de correo electrónico o potencialmente a la red interna si podemos usar una contraseña de correo electrónico válida para conectarnos a través de VPN. También podríamos encontrar un Open Relay, que podríamos abusar para Phishing enviando correos electrónicos como usuarios falsos o suplantando una cuenta de correo para hacer que un correo parezca oficial e intentar enga

ñar a los empleados para que ingresen credenciales o ejecuten un payload. El phishing está fuera del alcance de esta evaluación en particular y probablemente lo estará para la mayoría de los tests de penetración externa, por lo que este tipo de vulnerabilidad valdría la pena confirmarla y reportarla si la encontramos, pero no deberíamos ir más allá de una simple validación sin consultar con el cliente primero. Sin embargo, esto podría ser extremadamente útil en una evaluación de red team de alcance completo.

Podemos verificarlo de todos modos, pero no encontramos un relay abierto, lo cual es bueno para nuestro cliente.

```r
nmap -p25 -Pn --script smtp-open-relay  10.129.203.101

Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-20 19:14 EDT
Nmap scan report for inlanefreight.local (10.129.203.101)
Host is up (0.12s latency).

PORT   STATE SERVICE
25/tcp open  smtp
|_smtp-open-relay: Server doesn't seem to be an open relay, all tests failed

Nmap done: 1 IP address (1 host up) scanned in 24.30 seconds
```

---

## Moving On

El puerto 111 es el servicio `rpcbind` que no debería estar expuesto externamente, por lo que podríamos escribir un hallazgo `Low` para `Unnecessary Exposed Services` o similar. Este puerto puede ser sondeado para obtener huellas del sistema operativo o potencialmente recopilar información sobre servicios disponibles. Podemos intentar sondearlo con el comando [rpcinfo](https://linux.die.net/man/8/rpcinfo) o Nmap. Funciona, pero no obtenemos nada útil. Nuevamente, vale la pena anotarlo para que el cliente esté al tanto de lo que está exponiendo, pero no hay nada más que podamos hacer con esto.

```r
rpcinfo 10.129.203.101

   program version netid     address                service    owner
    100000    4    tcp6      ::.0.111               portmapper superuser
    100000    3    tcp6      ::.0.111               portmapper superuser
    100000    4    udp6      ::.0.111               portmapper superuser
    100000    3    udp6      ::.0.111               portmapper superuser
    100000    4    tcp       0.0.0.0.0.111          portmapper superuser
    100000    3    tcp       0.0.0.0.0.111          portmapper superuser
    100000    2    tcp       0.0.0.0.0.111          portmapper superuser
    100000    4    udp       0.0.0.0.0.111          portmapper superuser
    100000    3    udp       0.0.0.0.0.111          portmapper superuser
    100000    2    udp       0.0.0.0.0.111          portmapper superuser
    100000    4    local     /run/rpcbind.sock      portmapper superuser
    100000    3    local     /run/rpcbind.sock      portmapper superuser
```

Vale la pena consultar esta guía de HackTricks sobre [Pentesting rpcbind](https://book.hacktricks.xyz/network-services-pentesting/pentesting-rpcbind) para tener un conocimiento futuro sobre este servicio.

El último puerto es el puerto `80`, que, como sabemos, es el servicio HTTP. Sabemos que probablemente hay múltiples aplicaciones web basadas en la enumeración de subdominios y vhosts que realizamos anteriormente. Así que, pasemos a web. Todavía no tenemos un punto de apoyo o mucho más aparte de un puñado de hallazgos de riesgo medio y bajo. En entornos modernos, rara vez vemos servicios explotables externamente como un servidor FTP vulnerable o similar que conduzca a la ejecución remota de código (RCE). Nunca digas nunca, sin embargo. Hemos visto cosas más locas, por lo que siempre vale la pena explorar cada posibilidad. La mayoría de las organizaciones a las que nos enfrentamos serán más susceptibles a ataques a través de sus aplicaciones web, ya que estas a menudo presentan una vasta superficie de ataque, por lo que generalmente pasaremos la mayor parte de nuestro tiempo durante una prueba de penetración externa enumerando y atacando aplicaciones web.