En la sección anterior, vimos un ejemplo de una aplicación web que solo aplicaba controles de validación de tipo en el front-end (es decir, del lado del cliente), lo que hacía que estos controles fueran triviales de eludir. Por eso, siempre se recomienda implementar todos los controles relacionados con la seguridad en el servidor back-end, donde los atacantes no pueden manipularlo directamente.

Aun así, si los controles de validación de tipo en el servidor back-end no están codificados de manera segura, un atacante puede utilizar múltiples técnicas para eludirlos y llegar a la carga de archivos PHP.

El ejercicio que encontramos en esta sección es similar al que vimos en la sección anterior, pero tiene una blacklist de extensiones no permitidas para evitar la carga de scripts web. Veremos por qué usar una blacklist de extensiones comunes puede no ser suficiente para prevenir cargas arbitrarias de archivos y discutiremos varios métodos para eludirla.

---

## Blacklisting Extensions

Comencemos intentando uno de los métodos de elusión del lado del cliente que aprendimos en la sección anterior para cargar un script PHP en el servidor back-end. Interceptaremos una solicitud de carga de imagen con Burp, reemplazaremos el contenido y el nombre del archivo con nuestro script PHP, y reenviamos la solicitud:

   
`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_disallowed_type.jpg)

Como podemos ver, nuestro ataque no tuvo éxito esta vez, ya que obtuvimos `Extension not allowed`. Esto indica que la aplicación web puede tener alguna forma de validación de tipo de archivo en el back-end, además de las validaciones del front-end.

Generalmente, existen dos formas comunes de validar una extensión de archivo en el back-end:

1. Probar contra una `blacklist` de tipos
2. Probar contra una `whitelist` de tipos

Además, la validación también puede verificar el `file type` o el `file content` para coincidir con el tipo. La forma más débil de validación entre estas es `probar la extensión del archivo contra una blacklist de extensiones` para determinar si se debe bloquear la solicitud de carga. Por ejemplo, el siguiente fragmento de código verifica si la extensión del archivo cargado es `PHP` y descarta la solicitud si lo es:


```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$extension = pathinfo($fileName, PATHINFO_EXTENSION);
$blacklist = array('php', 'php7', 'phps');

if (in_array($extension, $blacklist)) {
    echo "File type not allowed";
    die();
}
```

El código toma la extensión del archivo (`$extension`) del nombre del archivo cargado (`$fileName`) y luego la compara con una lista de extensiones en la blacklist (`$blacklist`). Sin embargo, este método de validación tiene un gran defecto. `No es exhaustivo`, ya que muchas otras extensiones no están incluidas en esta lista, las cuales pueden ser usadas para ejecutar código PHP en el servidor back-end si se cargan.

**Tip:** La comparación anterior también es sensible a mayúsculas y solo considera extensiones en minúsculas. En servidores Windows, los nombres de archivo no distinguen entre mayúsculas y minúsculas, por lo que podemos intentar cargar un `php` con una combinación de mayúsculas y minúsculas (por ejemplo, `pHp`), lo que podría eludir la blacklist y aún debería ejecutarse como un script PHP.

Así que, intentemos explotar esta debilidad para eludir la blacklist y cargar un archivo PHP.

---

## Fuzzing Extensions

Como la aplicación web parece estar probando la extensión del archivo, nuestro primer paso es fuzzing la funcionalidad de carga con una lista de extensiones potenciales y ver cuáles de ellas devuelven el mensaje de error anterior. Cualquier solicitud de carga que no devuelva un mensaje de error, devuelva un mensaje diferente o tenga éxito en la carga del archivo, puede indicar una extensión de archivo permitida.

Existen muchas listas de extensiones que podemos utilizar en nuestro escaneo de fuzzing. `PayloadsAllTheThings` proporciona listas de extensiones para [PHP](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) y [.NET](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP) aplicaciones web. También podemos usar la lista de `SecLists` de [Web Extensions](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt) comunes.

Podemos usar cualquiera de las listas anteriores para nuestro escaneo de fuzzing. Como estamos probando una aplicación PHP, descargaremos y usaremos la lista [PHP](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) anterior. Luego, desde `Burp History`, podemos localizar nuestra última solicitud a `/upload.php`, hacer clic derecho sobre ella y seleccionar `Send to Intruder`. Desde la pestaña `Positions`, podemos `Clear` cualquier posición configurada automáticamente, y luego seleccionar la extensión `.php` en `filename="HTB.php"` y hacer clic en el botón `Add` para agregarla como una posición de fuzzing:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_burp_fuzz_extension.jpg)

Mantendremos el contenido del archivo para este ataque, ya que solo nos interesa fuzzing las extensiones de archivo. Finalmente, podemos `Load` la lista de extensiones PHP desde arriba en la pestaña `Payloads` bajo `Payload Options`. También desmarcaremos la opción `URL Encoding` para evitar codificar el (.) antes de la extensión del archivo. Una vez hecho esto, podemos hacer clic en `Start Attack` para comenzar el fuzzing de extensiones de archivo que no están en la blacklist:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_burp_intruder_result.jpg)

Podemos ordenar los resultados por `Length`, y veremos que todas las solicitudes con el Content-Length (`193`) pasaron la validación de la extensión, ya que todas respondieron con `File successfully uploaded`. En contraste, el resto respondió con un mensaje de error diciendo `Extension not allowed`.

---

## Non-Blacklisted Extensions

Ahora, podemos intentar cargar un archivo utilizando cualquiera de las `allowed extensions` anteriores, y algunas de ellas pueden permitirnos ejecutar código PHP. `No todas las extensiones funcionarán con todas las configuraciones del servidor web`, por lo que es posible que necesitemos intentar varias extensiones para obtener una que ejecute código PHP con éxito.

Usemos la extensión `.phtml`, que los servidores web PHP a menudo permiten para derechos de ejecución de código. Podemos hacer clic derecho en su solicitud en los resultados de Intruder y seleccionar `Send to Repeater`. Ahora, todo lo que tenemos que hacer es repetir lo que hemos hecho en las dos secciones anteriores cambiando el nombre del archivo para usar la extensión `.phtml` y cambiando el contenido por el de un web shell PHP:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_php5_web_shell.jpg)

Como podemos ver, nuestro archivo parece haber sido cargado. El paso final es visitar nuestro archivo cargado, que debería estar en el directorio de carga de imágenes (`profile_images`), como vimos en la sección anterior. Luego, podemos probar la ejecución de un comando, lo que debería confirmar que eludimos con éxito la blacklist y cargamos nuestro web shell:

   
`http://SERVER_IP:PORT/profile_images/shell.phtml?cmd=id`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_php_manual_shell.jpg)