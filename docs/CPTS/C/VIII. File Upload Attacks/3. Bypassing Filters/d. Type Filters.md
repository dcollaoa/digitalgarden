Hasta ahora, solo hemos estado tratando con filtros de tipo que solo consideran la extensión del archivo en el nombre del archivo. Sin embargo, como vimos en la sección anterior, aún podemos tomar control del servidor back-end incluso con extensiones de imagen (por ejemplo, `shell.php.jpg`). Además, podemos utilizar algunas extensiones permitidas (por ejemplo, SVG) para realizar otros ataques. Todo esto indica que solo probar la extensión del archivo no es suficiente para prevenir ataques de carga de archivos.

Es por esto que muchos servidores web modernos y aplicaciones web también prueban el contenido del archivo cargado para asegurarse de que coincida con el tipo especificado. Si bien los filtros de extensión pueden aceptar varias extensiones, los filtros de contenido generalmente especifican una sola categoría (por ejemplo, imágenes, videos, documentos), por lo que no suelen usar listas negras o listas blancas. Esto se debe a que los servidores web proporcionan funciones para verificar el tipo de contenido del archivo, y generalmente cae bajo una categoría específica.

Existen dos métodos comunes para validar el contenido del archivo: `Content-Type Header` o `File Content`. Veamos cómo podemos identificar cada filtro y cómo evitarlos.

---

## Content-Type

Comencemos el ejercicio al final de esta sección e intentemos cargar un script PHP:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_content_type_upload.jpg)

Vemos que obtenemos un mensaje que dice `Only images are allowed`. El mensaje de error persiste y nuestro archivo no se carga incluso si intentamos algunos de los trucos que aprendimos en las secciones anteriores. Si cambiamos el nombre del archivo a `shell.jpg.phtml` o `shell.php.jpg`, o incluso si usamos `shell.jpg` con un contenido de web shell, nuestra carga fallará. Dado que la extensión del archivo no afecta el mensaje de error, la aplicación web debe estar probando el contenido del archivo para la validación del tipo. Como se mencionó anteriormente, esto puede ser en el `Content-Type Header` o el `File Content`.

El siguiente es un ejemplo de cómo una aplicación web PHP prueba el encabezado Content-Type para validar el tipo de archivo:

```php
$type = $_FILES['uploadFile']['type'];

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```

El código establece la variable (`$type`) del encabezado `Content-Type` del archivo cargado. Nuestros navegadores configuran automáticamente el encabezado `Content-Type` al seleccionar un archivo a través del cuadro de diálogo de selección de archivos, generalmente derivado de la extensión del archivo. Sin embargo, dado que nuestros navegadores configuran esto, esta operación es del lado del cliente y podemos manipularla para cambiar el tipo de archivo percibido y potencialmente eludir el filtro de tipo.

Podemos comenzar fuzzing el encabezado `Content-Type` con la lista de palabras de SecLists `Content-Type Wordlist` a través de Burp Intruder, para ver qué tipos están permitidos. Sin embargo, el mensaje nos dice que solo se permiten imágenes, por lo que podemos limitar nuestra exploración a tipos de imagen, lo que reduce la lista de palabras a solo `45` tipos (en comparación con alrededor de 700 originalmente). Podemos hacerlo de la siguiente manera:

**Type Filters**

```sh
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Miscellaneous/web/content-type.txt
cat content-type.txt | grep 'image/' > image-content-types.txt
```

**Ejercicio:** Intenta ejecutar el escaneo anterior para encontrar qué tipos de Content-Type están permitidos.

Para simplificar, solo elijamos un tipo de imagen (por ejemplo, `image/jpg`), luego interceptemos nuestra solicitud de carga y cambiemos el encabezado `Content-Type` a este:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_bypass_content_type_request.jpg)

Esta vez obtenemos `File successfully uploaded`, y si visitamos nuestro archivo, vemos que se cargó correctamente:

`http://SERVER_IP:PORT/profile_images/shell.php?cmd=id`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_php_manual_shell.jpg)

**Nota:** Una solicitud HTTP de carga de archivos tiene dos encabezados `Content-Type`, uno para el archivo adjunto (en la parte inferior) y otro para la solicitud completa (en la parte superior). Generalmente necesitamos modificar el encabezado `Content-Type` del archivo, pero en algunos casos, la solicitud solo contendrá el encabezado `Content-Type` principal (por ejemplo, si el contenido cargado se envió como `POST` data), en cuyo caso necesitaremos modificar el encabezado `Content-Type` principal.

---

## MIME-Type

El segundo y más común tipo de validación de contenido de archivo es probar el `MIME-Type` del archivo cargado. `Multipurpose Internet Mail Extensions (MIME)` es un estándar de internet que determina el tipo de un archivo a través de su formato general y estructura de bytes.

Esto generalmente se hace inspeccionando los primeros bytes del contenido del archivo, que contienen la `File Signature` o `Magic Bytes`. Por ejemplo, si un archivo comienza con (`GIF87a` o `GIF89a`), esto indica que es una imagen `GIF`, mientras que un archivo que comienza con texto plano generalmente se considera un archivo `Text`. Si cambiamos los primeros bytes de cualquier archivo a los bytes mágicos de GIF, su tipo MIME se cambiaría a una imagen GIF, independientemente de su contenido o extensión restante.

**Tip:** Muchos otros tipos de imágenes tienen bytes no imprimibles para sus firmas de archivo, mientras que una imagen `GIF` comienza con bytes imprimibles en ASCII (como se muestra arriba), por lo que es la más fácil de imitar. Además, dado que la cadena `GIF8` es común entre ambas firmas de GIF, generalmente es suficiente imitar una imagen GIF.

Tomemos un ejemplo básico para demostrar esto. El comando `file` en sistemas Unix encuentra el tipo de archivo a través del tipo MIME. Si creamos un archivo básico con texto, se consideraría como un archivo de texto, de la siguiente manera:

**Type Filters**

```sh
echo "this is a text file" > text.jpg 
file text.jpg 
text.jpg: ASCII text
```

Como vemos, el tipo MIME del archivo es `ASCII text`, aunque su extensión sea `.jpg`. Sin embargo, si escribimos `GIF8` al principio del archivo, se considerará como una imagen `GIF` en su lugar, aunque su extensión siga siendo `.jpg`:

**Type Filters**

```sh
echo "GIF8" > text.jpg 
file text.jpg
text.jpg: GIF image data
```

Los servidores web también pueden utilizar este estándar para determinar tipos de archivo, lo cual es generalmente más preciso que probar la extensión del archivo. El siguiente ejemplo muestra cómo una aplicación web PHP puede probar el tipo MIME de un archivo cargado:

```php
$type = mime_content_type($_FILES['uploadFile']['tmp_name']);

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```

Como podemos ver, los tipos MIME son similares a los encontrados en los encabezados `Content-Type`, pero su fuente es diferente, ya que PHP usa la función `mime_content_type()` para obtener el tipo MIME de un archivo. Intentemos repetir nuestro último ataque, pero ahora con un ejercicio que pruebe tanto el encabezado `Content-Type` como el tipo MIME:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_bypass_content_type_request.jpg)

Una vez que reenviamos nuestra solicitud, notamos que obtenemos el mensaje de error `Only images are allowed`. Ahora, intentemos agregar `GIF8` antes de nuestro código PHP para intentar imitar una imagen GIF mientras mantenemos la extensión de nuestro archivo como `.php`, para que ejecute código PHP independientemente:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_bypass_mime_type_request.jpg)

Esta vez obtenemos `File successfully uploaded`, y nuestro archivo se carga correctamente en el servidor:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_bypass_mime_type.jpg)

Ahora podemos visitar nuestro archivo cargado, y veremos que podemos ejecutar comandos del sistema con éxito:

`http://SERVER_IP:PORT/profile_images/shell.php?cmd=id`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_php_manual_shell_gif.jpg)

**Nota:** Vemos que la salida del comando comienza con `GIF8`, ya que esta fue la primera línea en nuestro script PHP para imitar los bytes mágicos de GIF, y ahora se muestra como texto plano antes de que se ejecute nuestro código PHP.

Podemos usar una combinación de los dos métodos discutidos en esta sección, lo que puede ayudarnos a eludir algunos filtros de contenido más robustos. Por ejemplo, podemos intentar usar un `MIME type permitido con un Content-Type no permitido`, un `MIME/Content-Type permitido con una extensión no permitida`, o un `MIME/Content-Type no permitido con una extensión permitida`, y así sucesivamente. Del mismo modo, podemos intentar otras combinaciones y permutaciones para intentar confundir al servidor web, y dependiendo del nivel de seguridad del código, podemos ser capaces de eludir varios filtros.