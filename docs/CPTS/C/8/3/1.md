Muchas aplicaciones web solo confían en el código JavaScript del front-end para validar el formato del archivo seleccionado antes de subirlo y no lo suben si el archivo no está en el formato requerido (por ejemplo, no es una imagen).

Sin embargo, como la validación del formato del archivo se realiza en el cliente, podemos omitirla fácilmente interactuando directamente con el servidor, saltándonos las validaciones del front-end por completo. También podemos modificar el código del front-end a través de las herramientas de desarrollo de nuestro navegador para deshabilitar cualquier validación en su lugar.

---

## Client-Side Validation

El ejercicio al final de esta sección muestra una funcionalidad básica de `Profile Image`, frecuentemente vista en aplicaciones web que utilizan características de perfiles de usuario, como aplicaciones web de redes sociales:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_profile_image_upload.jpg)

Sin embargo, esta vez, cuando obtenemos el cuadro de diálogo de selección de archivos, no podemos ver nuestros scripts `PHP` (o pueden estar deshabilitados), ya que el cuadro de diálogo parece estar limitado solo a formatos de imagen:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_select_file_types.jpg)

Aún podemos seleccionar la opción `All Files` para seleccionar nuestro script `PHP` de todos modos, pero cuando lo hacemos, recibimos un mensaje de error que dice (`Only images are allowed!`), y el botón `Upload` se desactiva:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_select_denied.jpg)

Esto indica algún tipo de validación de tipo de archivo, por lo que no podemos simplemente subir una web shell a través del formulario de carga como hicimos en la sección anterior. Afortunadamente, toda la validación parece estar ocurriendo en el front-end, ya que la página nunca se actualiza ni envía solicitudes HTTP después de seleccionar nuestro archivo. Por lo tanto, deberíamos poder tener control total sobre estas validaciones del lado del cliente.

Cualquier código que se ejecute en el lado del cliente está bajo nuestro control. Mientras que el servidor web es responsable de enviar el código del front-end, la representación y ejecución del código del front-end ocurre dentro de nuestro navegador. Si la aplicación web no aplica ninguna de estas validaciones en el back-end, deberíamos poder subir cualquier tipo de archivo.

Como se mencionó anteriormente, para omitir estas protecciones, podemos `modificar la solicitud de carga al servidor back-end`, o podemos `manipular el código del front-end para deshabilitar estas validaciones de tipo`.

---

## Back-end Request Modification

Comencemos examinando una solicitud normal a través de `Burp`. Cuando seleccionamos una imagen, vemos que se refleja como nuestra imagen de perfil, y cuando hacemos clic en `Upload`, nuestra imagen de perfil se actualiza y persiste a través de actualizaciones. Esto indica que nuestra imagen fue subida al servidor, que ahora la muestra de vuelta a nosotros:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_normal_request.jpg)

Si capturamos la solicitud de carga con `Burp`, vemos la siguiente solicitud enviada por la aplicación web:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_image_upload_request.jpg)

La aplicación web parece estar enviando una solicitud estándar de carga HTTP a `/upload.php`. De esta manera, ahora podemos modificar esta solicitud para cumplir con nuestras necesidades sin tener las restricciones de validación de tipo del front-end. Si el servidor back-end no valida el tipo de archivo subido, entonces teóricamente deberíamos poder enviar cualquier tipo de archivo/contenido, y sería subido al servidor.

Las dos partes importantes en la solicitud son `filename="HTB.png"` y el contenido del archivo al final de la solicitud. Si modificamos el `filename` a `shell.php` y modificamos el contenido al web shell que usamos en la sección anterior, estaríamos subiendo una web shell `PHP` en lugar de una imagen.

Así que, capturemos otra solicitud de carga de imagen y luego modifiquémosla en consecuencia:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_modified_upload_request.jpg)

**Nota:** También podemos modificar el `Content-Type` del archivo subido, aunque esto no debería jugar un papel importante en esta etapa, así que lo dejaremos sin modificar.

Como podemos ver, nuestra solicitud de carga se realizó y obtuvimos `File successfully uploaded` en la respuesta. Así que, ahora podemos visitar nuestro archivo subido e interactuar con él para obtener ejecución remota de código.

---

## Disabling Front-end Validation

Otro método para omitir las validaciones del lado del cliente es a través de la manipulación del código del front-end. Dado que estas funciones se procesan completamente dentro de nuestro navegador web, tenemos control total sobre ellas. Por lo tanto, podemos modificar estos scripts o deshabilitarlos por completo. Luego, podemos usar la funcionalidad de carga para subir cualquier tipo de archivo sin necesidad de utilizar `Burp` para capturar y modificar nuestras solicitudes.

Para comenzar, podemos hacer clic en [`CTRL+SHIFT+C`] para activar el `Page Inspector` del navegador, y luego hacer clic en la imagen de perfil, que es donde activamos el selector de archivos para el formulario de carga:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_element_inspector.jpg)

Esto resaltará la siguiente entrada de archivo HTML en la línea `18`:

```r
<input type="file" name="uploadFile" id="uploadFile" onchange="checkFile(this)" accept=".jpg,.jpeg,.png">
```

Aquí, vemos que la entrada del archivo especifica (`.jpg,.jpeg,.png`) como los tipos de archivo permitidos dentro del cuadro de diálogo de selección de archivos. Sin embargo, podemos modificar esto fácilmente y seleccionar `All Files` como hicimos antes, por lo que no es necesario cambiar esta parte de la página.

La parte más interesante es `onchange="checkFile(this)"`, que parece ejecutar un código JavaScript cada vez que seleccionamos un archivo, que parece estar realizando la validación del tipo de archivo. Para obtener los detalles de esta función, podemos ir a la `Console` del navegador haciendo clic en [`CTRL+SHIFT+K`], y luego podemos escribir el nombre de la función (`checkFile`) para obtener sus detalles:

```r
function checkFile(File) {
...SNIP...
    if (extension !== 'jpg' && extension !== 'jpeg' && extension !== 'png') {
        $('#error_message').text("Only images are allowed!");
        File.form.reset();
        $("#submit").attr("disabled", true);
    ...SNIP...
    }
}
```

Lo clave que obtenemos de esta función es donde verifica si la extensión del archivo es una imagen, y si no lo es, imprime el mensaje de error que vimos anteriormente (`Only images are allowed!`) y desactiva el botón `Upload`. Podemos agregar `PHP` como una de las extensiones permitidas o modificar la función para eliminar la verificación de la extensión.

Afortunadamente, no necesitamos entrar en escribir y modificar código JavaScript. Podemos eliminar esta función del código HTML, ya que su uso principal parece ser la validación del tipo de archivo, y eliminarla no debería romper nada.

Para hacerlo, podemos volver a nuestro inspector, hacer clic en la imagen de perfil nuevamente, hacer doble clic en el nombre de la función (`checkFile`) en la línea `18`, y eliminarla:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_removed_js_function.jpg)

**Tip:** También puedes hacer lo mismo para eliminar `accept=".jpg,.jpeg,.png"`, lo que debería hacer más fácil seleccionar la shell `PHP` en el cuadro de diálogo de selección de archivos, aunque esto no es obligatorio, como se mencionó anteriormente.

Con la función `checkFile` eliminada de la entrada del archivo, deberíamos poder seleccionar nuestra web shell `PHP` a través del cuadro de diálogo de selección de archivos y subirla normalmente sin validaciones, similar a lo que hicimos en la sección anterior.

**Nota:** La modificación que hicimos al código fuente es temporal y no persistirá a través de actualizaciones de página, ya que solo estamos cambiándola en el lado del cliente. Sin embargo, nuestra única necesidad es omitir la validación del lado del cliente, por lo que debería ser suficiente para este propósito.

Una vez que subimos nuestra web shell usando cualquiera de los métodos anteriores y luego actualizamos la página, podemos usar el `Page Inspector` una vez más con [`CTRL+SHIFT+C`], hacer clic en la imagen de perfil, y deberíamos ver la URL de nuestra web shell subida:

```r
<img src="/profile_images/shell.php" class="profile-image" id="profile-image">
```

Si podemos hacer clic en el enlace anterior, llegaremos a nuestra web shell subida, con la cual podemos interactuar para ejecutar comandos en el servidor back-end:

`http://SERVER_IP:PORT/profile_images/shell.php?cmd=id`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_php_manual_shell.jpg)

**Nota:** Los pasos mostrados se aplican a Firefox, ya que otros navegadores pueden tener métodos ligeramente diferentes para aplicar cambios locales al código fuente, como el uso de `overrides` en Chrome.