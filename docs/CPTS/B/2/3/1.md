El [File Transfer Protocol](https://en.wikipedia.org/wiki/File_Transfer_Protocol) (`FTP`) es un protocolo de red estándar utilizado para transferir archivos entre computadoras. También realiza operaciones de directorio y archivos, como cambiar el directorio de trabajo, listar archivos, y renombrar y eliminar directorios o archivos. Por defecto, FTP escucha en el puerto `TCP/21`.

Para atacar un servidor FTP, podemos abusar de configuraciones incorrectas o privilegios excesivos, explotar vulnerabilidades conocidas o descubrir nuevas vulnerabilidades. Por lo tanto, después de obtener acceso al servicio FTP, debemos estar atentos al contenido en el directorio para poder buscar información sensible o crítica, como discutimos anteriormente. El protocolo está diseñado para activar descargas y subidas con comandos. Así, los archivos se pueden transferir entre servidores y clientes. Un sistema de gestión de archivos está disponible para el usuario, conocido por el sistema operativo. Los archivos se pueden almacenar en carpetas, que pueden estar ubicadas en otras carpetas. Esto resulta en una estructura de directorios jerárquica. La mayoría de las empresas usan este servicio para procesos de desarrollo de software o sitios web.

---

## Enumeration

`Nmap` scripts predeterminados `-sC` incluye el script de Nmap [ftp-anon](https://nmap.org/nsedoc/scripts/ftp-anon.html) que verifica si un servidor FTP permite inicios de sesión anónimos. La flag de enumeración de versión `-sV` proporciona información interesante sobre los servicios FTP, como el banner FTP, que a menudo incluye el nombre de la versión. Podemos usar el cliente `ftp` o `nc` para interactuar con el servicio FTP. Por defecto, FTP se ejecuta en el puerto TCP 21.

### Nmap

```r
sudo nmap -sC -sV -p 21 192.168.2.142 

Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-10 22:04 EDT
Nmap scan report for 192.168.2.142
Host is up (0.00054s latency).

PORT   STATE SERVICE
21/tcp open  ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--   1 1170     924            31 Mar 28  2001 .banner
| d--x--x--x   2 root     root         1024 Jan 14  2002 bin
| d--x--x--x   2 root     root         1024 Aug 10  1999 etc
| drwxr-srwt   2 1170     924          2048 Jul 19 18:48 incoming [NSE: writeable]
| d--x--x--x   2 root     root         1024 Jan 14  2002 lib
| drwxr-sr-x   2 1170     924          1024 Aug  5  2004 pub
|_Only 6 shown. Use --script-args ftp-anon.maxlist=-1 to see all.
```

---

## Misconfigurations

Como discutimos, la autenticación anónima se puede configurar para diferentes servicios como FTP. Para acceder con inicio de sesión anónimo, podemos usar el nombre de usuario `anonymous` y sin contraseña. Esto será peligroso para la empresa si los permisos de lectura y escritura no se han configurado correctamente para el servicio FTP. Porque con el inicio de sesión anónimo, la empresa podría haber almacenado información sensible en una carpeta a la que el usuario anónimo del servicio FTP podría tener acceso.

Esto nos permitiría descargar esta información sensible o incluso subir scripts peligrosos. Usando otras vulnerabilidades, como la transversal de directorios en una aplicación web, podríamos descubrir dónde se encuentra este archivo y ejecutarlo como código PHP, por ejemplo.

### Anonymous Authentication

```r
ftp 192.168.2.142    
                     
Connected to 192.168.2.142.
220 (vsFTPd 2.3.4)
Name (192.168.2.142:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0               9 Aug 12 16:51 test.txt
226 Directory send OK.
```

Una vez que obtengamos acceso a un servidor FTP con credenciales anónimas, podemos comenzar a buscar información interesante. Podemos usar los comandos `ls` y `cd` para movernos por los directorios como en Linux. Para descargar un solo archivo, usamos `get`, y para descargar múltiples archivos, podemos usar `mget`. Para operaciones de subida, podemos usar `put` para un archivo simple o `mput` para múltiples archivos. Podemos usar `help` en la sesión del cliente FTP para más información.

En el módulo [Footprinting](https://academy.hackthebox.com/course/preview/footprinting), cubrimos información detallada sobre posibles configuraciones incorrectas de dichos servicios. Por ejemplo, se pueden aplicar muchas configuraciones diferentes a un servidor FTP, y algunas de ellas conducen a diferentes opciones que podrían causar posibles ataques contra ese servicio. Sin embargo, este módulo se centrará en ataques específicos en lugar de encontrar configuraciones incorrectas individuales.

---

## Protocol Specifics Attacks

Muchos ataques y métodos diferentes están basados en protocolos. Sin embargo, es esencial tener en cuenta que no estamos atacando los protocolos individuales en sí mismos, sino los servicios que los utilizan. Dado que hay docenas de servicios para un solo protocolo y procesan la información correspondiente de manera diferente, veremos algunos.

### Brute Forcing

Si no hay autenticación anónima disponible, también podemos forzar el inicio de sesión para los servicios FTP usando una lista de nombres de usuario y contraseñas pre-generados. Hay muchas herramientas diferentes para realizar un ataque de fuerza bruta. Exploremos una de ellas, [Medusa](https://github.com/jmk-foofus/medusa). Con `Medusa`, podemos usar la opción `-u` para especificar un solo usuario a atacar, o podemos usar la opción `-U` para proporcionar un archivo con una lista de nombres de usuario. La opción `-P` es para un archivo que contiene una lista de contraseñas. Podemos usar la opción `-M` y el protocolo que estamos atacando (FTP) y la opción `-h` para el nombre de host o la dirección IP objetivo.

**Nota:** Aunque podemos encontrar servicios vulnerables a la fuerza bruta, la mayoría de las aplicaciones hoy en día previenen este tipo de ataques. Un método más efectivo es Password Spraying.

### Brute Forcing with Medusa

```r
medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp 
                                                             
Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>                                                      
ACCOUNT CHECK: [ftp] Host: 10.129.203.7 (1 of 1, 0 complete) User: fiona (1 of 1, 0 complete) Password: 123456 (1 of 14344392 complete)
ACCOUNT CHECK: [ftp] Host: 10.129.203.7 (1 of 1, 0 complete) User: fiona (1 of 1, 0 complete) Password: 12345 (2 of 14344392 complete)
ACCOUNT CHECK: [ftp] Host: 10.129.203.7 (1 of 1, 0 complete) User: fiona (1 of 1, 0 complete) Password: 123456789 (3 of 14344392 complete)
ACCOUNT FOUND: [ftp] Host: 10.129.203.7 User: fiona Password: family [SUCCESS]
```

### FTP Bounce Attack

Un ataque FTP bounce es un ataque de red que utiliza servidores FTP para entregar tráfico saliente a otro dispositivo en la red. El atacante usa un comando `PORT` para engañar a la conexión FTP y ejecutar comandos y obtener información de un dispositivo diferente al servidor previsto.

Consideremos que estamos apuntando a un servidor FTP `FTP_DMZ` expuesto a Internet. Otro dispositivo dentro de la misma red, `Internal_DMZ`, no está expuesto a Internet. Podemos usar la conexión al servidor `FTP_DMZ` para escanear `Internal_DMZ` usando el ataque FTP Bounce y obtener información sobre los puertos abiertos del servidor. Luego, podemos usar esa información como parte de nuestro ataque contra la infraestructura.

![text](https://academy.hackthebox.com/storage/modules/116/ftp_bounce_attack.png) Source: [https://www.geeksforgeeks.org/what-is-ftp-bounce-attack/](https://www.geeksforgeeks.org/what-is-ftp-bounce-attack/)

La flag `-b` de `Nmap` se puede usar para realizar un ataque FTP bounce:

```r
nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2

Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-27 04:55 EDT
Resolved FTP bounce attack proxy to 10.10.110.213 (10.10.110

.213).
Attempting connection to ftp://anonymous:password@10.10.110.213:21
Connected:220 (vsFTPd 3.0.3)
Login credentials accepted by FTP server!
Initiating Bounce Scan at 04:55
FTP command misalignment detected ... correcting.
Completed Bounce Scan at 04:55, 0.54s elapsed (1 total ports)
Nmap scan report for 172.17.0.2
Host is up.

PORT   STATE  SERVICE
80/tcp open http

<SNIP>
```

Los servidores FTP modernos incluyen protecciones que, por defecto, previenen este tipo de ataque, pero si estas características están mal configuradas en servidores FTP modernos, el servidor puede volverse vulnerable a un ataque FTP Bounce.

Cuando inicies tu objetivo, por favor espera hasta 60 segundos más después de ver la dirección IP para asegurarte de que el servicio correspondiente se haya lanzado correctamente.