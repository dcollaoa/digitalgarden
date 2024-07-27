Ahora que entendemos qué son las vulnerabilidades de inclusión de archivos (File Inclusion) y cómo ocurren, podemos empezar a aprender cómo explotar estas vulnerabilidades en diferentes escenarios para poder leer el contenido de archivos locales en el servidor back-end.

---

## Basic LFI

El ejercicio que tenemos al final de esta sección nos muestra un ejemplo de una aplicación web que permite a los usuarios establecer su idioma en inglés o español:

`http://<SERVER_IP>:<PORT>/`

![](https://academy.hackthebox.com/storage/modules/23/basic_lfi_lang.png)

Si seleccionamos un idioma haciendo clic en él (por ejemplo, `Spanish`), vemos que el texto del contenido cambia a español:

`http://<SERVER_IP>:<PORT>/index.php?language=es.php`

![](https://academy.hackthebox.com/storage/modules/23/basic_lfi_es.png)

También notamos que la URL incluye un parámetro `language` que ahora está configurado en el idioma que seleccionamos (`es.php`). Hay varias formas en que el contenido podría cambiarse para coincidir con el idioma que especificamos. Podría estar obteniendo el contenido de una tabla de base de datos diferente según el parámetro especificado, o podría estar cargando una versión completamente diferente de la aplicación web. Sin embargo, como se discutió anteriormente, cargar parte de la página usando motores de plantillas es el método más fácil y comúnmente utilizado.

Entonces, si la aplicación web realmente está obteniendo un archivo que ahora se está incluyendo en la página, podríamos cambiar el archivo que se está obteniendo para leer el contenido de un archivo local diferente. Dos archivos comunes que están disponibles en la mayoría de los servidores back-end son `/etc/passwd` en Linux y `C:\Windows\boot.ini` en Windows. Así que cambiemos el parámetro de `es` a `/etc/passwd`:

`http://<SERVER_IP>:<PORT>/index.php?language=/etc/passwd`

![](https://academy.hackthebox.com/storage/modules/23/basic_lfi_lang_passwd.png)

Como podemos ver, la página es vulnerable y podemos leer el contenido del archivo `passwd` e identificar qué usuarios existen en el servidor back-end.

---

## Path Traversal

En el ejemplo anterior, leímos un archivo especificando su `absolute path` (por ejemplo, `/etc/passwd`). Esto funcionaría si toda la entrada se usara dentro de la función `include()` sin ninguna adición, como el siguiente ejemplo:

```php
include($_GET['language']);
```

En este caso, si intentamos leer `/etc/passwd`, entonces la función `include()` buscaría ese archivo directamente. Sin embargo, en muchas ocasiones, los desarrolladores web pueden agregar o anteponer una cadena al parámetro `language`. Por ejemplo, el parámetro `language` podría usarse para el nombre del archivo y podría agregarse después de un directorio, como sigue:

```php
include("./languages/" . $_GET['language']);
```

En este caso, si intentamos leer `/etc/passwd`, entonces la ruta pasada a `include()` sería (`./languages//etc/passwd`), y como este archivo no existe, no podremos leer nada:

`http://<SERVER_IP>:<PORT>/index.php?language=/etc/passwd`

![](https://academy.hackthebox.com/storage/modules/23/traversal_passwd_failed.png)

Como se esperaba, el error detallado nos muestra la cadena pasada a la función `include()`, indicando que no hay `/etc/passwd` en el directorio de idiomas.

**Nota:** Solo estamos habilitando errores de PHP en esta aplicación web con fines educativos, para que podamos entender adecuadamente cómo la aplicación web está manejando nuestra entrada. Para aplicaciones web de producción, dichos errores nunca deben mostrarse. Además, todos nuestros ataques deberían ser posibles sin errores, ya que no dependen de ellos.

Podemos eludir fácilmente esta restricción al recorrer directorios usando `relative paths`. Para hacerlo, podemos agregar `../` antes de nuestro nombre de archivo, que se refiere al directorio principal. Por ejemplo, si la ruta completa del directorio de idiomas es `/var/www/html/languages/`, entonces usar `../index.php` se referiría al archivo `index.php` en el directorio principal (es decir, `/var/www/html/index.php`).

Entonces, podemos usar este truco para retroceder varios directorios hasta llegar a la ruta raíz (es decir, `/`), y luego especificar nuestra ruta de archivo absoluta (por ejemplo, `../../../../etc/passwd`), y el archivo debería existir:

`http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/passwd`

![](https://academy.hackthebox.com/storage/modules/23/traversal_passwd.png)

Como podemos ver, esta vez pudimos leer el archivo sin importar el directorio en el que estábamos. Este truco funcionaría incluso si todo el parámetro se usara en la función `include()`, por lo que podemos usar esta técnica de manera predeterminada, y debería funcionar en ambos casos. Además, si estuviéramos en la ruta raíz (`/`) y usáramos `../` entonces seguiríamos permaneciendo en la ruta raíz. Entonces, si no estuviéramos seguros del directorio en el que se encuentra la aplicación web, podemos agregar `../` muchas veces, y no debería romper la ruta (incluso si lo hacemos cien veces).

**Consejo:** Siempre puede ser útil ser eficiente y no agregar `../` innecesariamente muchas veces, especialmente si estamos escribiendo un informe o redactando un exploit. Entonces, siempre trata de encontrar el número mínimo de `../` que funcione y úsalo. También puede ser capaz de calcular cuántos directorios estás lejos de la ruta raíz y usar esa cantidad. Por ejemplo, con `/var/www/html/` estamos a `3` directorios de la ruta raíz, por lo que podemos usar `../` 3 veces (es decir, `../../../`).

---

## Filename Prefix

En nuestro ejemplo anterior, usamos el parámetro `language` después del directorio, por lo que pudimos recorrer la ruta para leer el archivo `passwd`. En algunas ocasiones, nuestra entrada puede ser agregada después de una cadena diferente. Por ejemplo, podría usarse con un prefijo para obtener el nombre completo del archivo, como el siguiente ejemplo:

```php
include("lang_" . $_GET['language']);
```

En este caso, si intentamos recorrer el directorio con `../../../etc/passwd`, la cadena final sería `lang_../../../etc/passwd`, lo cual es inválido:

`http://<SERVER_IP>:<PORT>/index.php?language=../../../etc/passwd`

![](https://academy.hackthebox.com/storage/modules/23/lfi_another_example1.png)

Como se esperaba, el error nos dice que este archivo no existe. entonces, en lugar de usar directamente la exploración de rutas, podemos anteponer un `/` antes de nuestra carga útil, y esto debería considerar el prefijo como un directorio, y luego deberíamos poder recorrer los directorios:

`http://<SERVER_IP>:<PORT>/index.php?language=/../../../etc/passwd`

![](https://academy.hackthebox.com/storage/modules/23/lfi_another_example_passwd1.png)

**Nota:** Esto puede no siempre funcionar, ya que en este ejemplo un directorio llamado `lang_/` puede no existir, por lo que nuestra ruta relativa puede no ser correcta. Además, cualquier prefijo agregado a nuestra entrada puede romper algunas técnicas de inclusión de archivos que discutiremos en secciones posteriores, como el uso de envoltorios y filtros de PHP o RFI.

---

## Appended Extensions

Otro ejemplo muy común es cuando se agrega una extensión al parámetro `language`, como sigue:

```php
include($_GET['language'] . ".php");
```

Esto es bastante común, ya que en este caso, no tendríamos que escribir la extensión cada vez que necesitemos cambiar el idioma. Esto también puede ser más seguro ya que puede restringirnos a solo incluir archivos PHP. En este caso, si intentamos leer `/etc/passwd`, entonces el archivo incluido sería `/etc/passwd.php`, que no existe:

`http://<SERVER_IP>:<PORT>/extension/index.php?language=/etc/passwd`

![](https://academy.hackthebox.com/storage/modules/23/lfi_extension_failed.png)

Hay varias técnicas que podemos usar para eludir esto, y las discutiremos en secciones posteriores.

**Ejercicio:** Intenta leer cualquier archivo php (por ejemplo, index.php) a través de LFI, y verifica si obtienes su código fuente o si el archivo se renderiza como HTML en su lugar.

---

## Second-Order Attacks

Como podemos ver, los ataques LFI pueden presentarse en diferentes formas. Otro ataque LFI común, y un poco más avanzado, es un `Second Order Attack`. Esto ocurre porque muchas funcionalidades de aplicaciones web pueden estar obteniendo archivos de manera insegura desde el servidor back-end basándose en parámetros controlados por el usuario.

Por ejemplo, una aplicación web puede permitirnos descargar nuestro avatar a través de una URL como (`/profile/$username/avatar.png`). Si creamos un nombre de usuario LFI malicioso (por ejemplo, `../../../etc/passwd`), entonces puede ser posible cambiar el archivo que se está obteniendo a otro archivo local en el servidor y obtenerlo en lugar de nuestro avatar.

En este caso, estaríamos envenenando una entrada de base de datos con una carga útil LFI maliciosa en nuestro nombre de usuario. Luego, otra funcionalidad de la aplicación web utilizaría esta entrada envenenada para realizar nuestro ataque (es decir, descargar nuestro avatar basado en el valor del nombre de usuario). Por esto, este

 ataque se llama un ataque de `Second-Order`.

Los desarrolladores a menudo pasan por alto estas vulnerabilidades, ya que pueden protegerse contra la entrada directa del usuario (por ejemplo, desde un parámetro `?page`), pero pueden confiar en los valores obtenidos de su base de datos, como nuestro nombre de usuario en este caso. Si logramos envenenar nuestro nombre de usuario durante nuestro registro, entonces el ataque sería posible.

Explotar vulnerabilidades LFI utilizando ataques de segunda orden es similar a lo que hemos discutido en esta sección. La única variación es que necesitamos identificar una función que obtenga un archivo basado en un valor que controlamos indirectamente y luego tratar de controlar ese valor para explotar la vulnerabilidad.

**Nota:** Todas las técnicas mencionadas en esta sección deberían funcionar con cualquier vulnerabilidad LFI, independientemente del lenguaje de desarrollo o framework del back-end.