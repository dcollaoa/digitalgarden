Como se discutió en la sección anterior, el otro tipo de validación de extensión de archivo es utilizando una `whitelist of allowed file extensions`. Una whitelist es generalmente más segura que una blacklist. El servidor web solo permitiría las extensiones especificadas, y la lista no necesitaría ser exhaustiva en cuanto a cubrir extensiones poco comunes.

Aún así, hay diferentes casos de uso para una blacklist y una whitelist. Una blacklist puede ser útil en casos donde la funcionalidad de carga necesita permitir una amplia variedad de tipos de archivos (por ejemplo, File Manager), mientras que una whitelist generalmente solo se usa con funcionalidades de carga donde solo se permiten unos pocos tipos de archivos. Ambos pueden usarse en conjunto.

---

## Whitelisting Extensions

Comencemos el ejercicio al final de esta sección e intentemos cargar una extensión de PHP poco común, como `.phtml`, y veamos si aún podemos cargarla como lo hicimos en la sección anterior:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_whitelist_message.jpg)

Vemos que recibimos un mensaje que dice `Only images are allowed`, lo cual puede ser más común en aplicaciones web que ver un tipo de extensión bloqueada. Sin embargo, los mensajes de error no siempre reflejan qué forma de validación se está utilizando, así que intentemos fuzzear para encontrar extensiones permitidas como lo hicimos en la sección anterior, usando la misma wordlist que usamos anteriormente:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_whitelist_fuzz.jpg)

Podemos ver que todas las variaciones de las extensiones de PHP están bloqueadas (por ejemplo, `php5`, `php7`, `phtml`). Sin embargo, la wordlist que usamos también contenía otras extensiones 'maliciosas' que no fueron bloqueadas y se cargaron con éxito. Así que, intentemos entender cómo pudimos cargar estas extensiones y en qué casos podríamos utilizarlas para ejecutar código PHP en el servidor back-end.

El siguiente es un ejemplo de una prueba de whitelist de extensiones de archivo:

```r
$fileName = basename($_FILES["uploadFile"]["name"]);

if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

Vemos que el script usa una expresión regular (`regex`) para comprobar si el nombre del archivo contiene alguna de las extensiones de imagen permitidas. El problema aquí reside en la `regex`, ya que solo verifica si el nombre del archivo `contiene` la extensión y no si realmente `termina` con ella. Muchos desarrolladores cometen tales errores debido a una comprensión débil de los patrones regex.

Así que, veamos cómo podemos eludir estas pruebas para cargar scripts PHP.

---

## Double Extensions

El código solo comprueba si el nombre del archivo contiene una extensión de imagen; un método sencillo para pasar la prueba de regex es mediante `Double Extensions`. Por ejemplo, si la extensión `.jpg` está permitida, podemos agregarla en nuestro nombre de archivo cargado y aún así terminar nuestro nombre de archivo con `.php` (por ejemplo, `shell.jpg.php`), en cuyo caso deberíamos poder pasar la prueba de la whitelist, mientras aún cargamos un script PHP que puede ejecutar código PHP.

**Ejercicio:** Intenta fuzzear el formulario de carga con [esta wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt) para encontrar qué extensiones están permitidas por el formulario de carga.

Intercepemos una solicitud de carga normal, y modifiquemos el nombre del archivo a (`shell.jpg.php`), y modifiquemos su contenido para que sea un web shell:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_double_ext_request.jpg)

Ahora, si visitamos el archivo cargado y tratamos de enviar un comando, podemos ver que efectivamente ejecuta comandos del sistema, lo que significa que el archivo que cargamos es un script PHP completamente funcional:

`http://SERVER_IP:PORT/profile_images/shell.jpg.php?cmd=id`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_php_manual_shell.jpg)

Sin embargo, esto no siempre puede funcionar, ya que algunas aplicaciones web pueden usar un patrón regex estricto, como se mencionó anteriormente, como el siguiente:

```r
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) { ...SNIP... }
```

Este patrón solo debería considerar la extensión final del archivo, ya que usa (`^.*\.`) para coincidir con todo hasta el último (`.`), y luego usa (`$`) al final para solo coincidir con extensiones que terminan el nombre del archivo. Entonces, el `ataque anterior no funcionaría`. No obstante, algunas técnicas de explotación pueden permitirnos eludir este patrón, pero la mayoría dependen de configuraciones incorrectas o sistemas desactualizados.

---

## Reverse Double Extension

En algunos casos, la funcionalidad de carga de archivos en sí misma puede no ser vulnerable, pero la configuración del servidor web puede conducir a una vulnerabilidad. Por ejemplo, una organización puede usar una aplicación web de código abierto, que tiene una funcionalidad de carga de archivos. Incluso si la funcionalidad de carga de archivos usa un patrón regex estricto que solo coincide con la extensión final en el nombre del archivo, la organización puede usar configuraciones inseguras para el servidor web.

Por ejemplo, el `/etc/apache2/mods-enabled/php7.4.conf` para el servidor web `Apache2` puede incluir la siguiente configuración:

```r
<FilesMatch ".+\.ph(ar|p|tml)">
    SetHandler application/x-httpd-php
</FilesMatch>
```

La configuración anterior es cómo el servidor web determina qué archivos permitir la ejecución de código PHP. Especifica una whitelist con un patrón regex que coincide con `.phar`, `.php`, y `.phtml`. Sin embargo, este patrón regex puede tener el mismo error que vimos anteriormente si olvidamos terminarlo con (`$`). En tales casos, cualquier archivo que contenga las extensiones anteriores permitirá la ejecución de código PHP, incluso si no termina con la extensión PHP. Por ejemplo, el nombre del archivo (`shell.php.jpg`) debería pasar la prueba de la whitelist anterior ya que termina con (`.jpg`), y podría ejecutar código PHP debido a la configuración incorrecta anterior, ya que contiene (`.php`) en su nombre.

**Ejercicio:** La aplicación web puede aún utilizar una blacklist para negar solicitudes que contengan extensiones de `PHP`. Intenta fuzzear el formulario de carga con la [PHP Wordlist](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) para encontrar qué extensiones están bloqueadas por el formulario de carga.

Intentemos interceptar una solicitud de carga de imagen normal, y usemos el nombre de archivo anterior para pasar la prueba de la whitelist estricta:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_reverse_double_ext_request.jpg)

Ahora, podemos visitar el archivo cargado, e intentar ejecutar un comando:

`http://SERVER_IP:PORT/profile_images/shell.php.jpg?cmd=id`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_php_manual_shell.jpg)

Como podemos ver, pasamos con éxito la prueba de la whitelist estricta y explotamos la configuración incorrecta del servidor web para ejecutar código PHP y tomar control del servidor.

## Character Injection

Finalmente, discutamos otro método para eludir una prueba de validación de whitelist a través de `Character Injection`. Podemos inyectar varios caracteres antes o después de la extensión final para causar que la aplicación web interprete incorrectamente el nombre del archivo y ejecute el archivo cargado como un script PHP.

Los siguientes son algunos de los caracteres que podemos intentar inyectar:

- `%20`
- `%0a`
- `%00`
- `%0d0a`
- `/`
- `.\`
- `.`
- `…`
- `:`

Cada carácter tiene un caso de uso específico que puede engañar a la aplicación web para interpretar incorrectamente la extensión del archivo. Por ejemplo, (`shell.php%00.jpg`) funciona con servidores PHP con versión `5.X` o anterior, ya que hace que el servidor web PHP termine el nombre del archivo después de (`%00`), y lo almacene como (`shell.php`), mientras aún pasa la whitelist. Lo mismo puede usarse con aplicaciones web alojadas en un servidor Windows inyectando un dos puntos (`:`) antes de la extensión permitida (por ejemplo, `shell.aspx:.jpg`), que también debería escribir el archivo como (`shell.aspx`). Del mismo modo, cada uno de los otros caracteres tiene un caso de uso que puede permitirnos cargar un script PHP mientras eludimos la prueba de validación de tipo.

Podemos escribir un pequeño script bash que genere todas las permutaciones del nombre del archivo, donde los caracteres anteriores serían inyectados antes y después de ambas extensiones `PHP` y `JPG`, como sigue:

```r
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$

ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    end
done
```

Con esta wordlist personalizada, podemos ejecutar un escaneo de fuzzing con `Burp Intruder`, similar a los que hicimos anteriormente. Si el back-end o el servidor web está desactualizado o tiene ciertas configuraciones incorrectas, algunos de los nombres de archivo generados pueden eludir la prueba de la whitelist y ejecutar código PHP.

**Ejercicio:** Intenta agregar más extensiones de PHP al script anterior para generar más permutaciones de nombres de archivo, luego haz fuzzing a la funcionalidad de carga con la wordlist generada para ver cuáles de los nombres de archivo generados pueden ser cargados, y cuáles pueden ejecutar código PHP después de ser cargados.