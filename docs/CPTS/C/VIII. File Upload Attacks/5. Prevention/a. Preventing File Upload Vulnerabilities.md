A lo largo de este módulo, hemos discutido varios métodos para explotar diferentes vulnerabilidades de carga de archivos. En cualquier prueba de penetración o ejercicio de bug bounty en el que participemos, debemos poder informar sobre los puntos de acción que se deben tomar para rectificar las vulnerabilidades identificadas.

Esta sección discutirá lo que podemos hacer para asegurar que nuestras funciones de carga de archivos estén codificadas de manera segura y sean seguras contra la explotación, y qué puntos de acción podemos recomendar para cada tipo de vulnerabilidad de carga de archivos.

---

## Extension Validation

El primer y más común tipo de vulnerabilidad de carga que discutimos en este módulo fue la validación de extensión de archivo. Las extensiones de archivo juegan un papel importante en cómo se ejecutan los archivos y scripts, ya que la mayoría de los servidores web y aplicaciones web tienden a usar extensiones de archivo para configurar sus propiedades de ejecución. Por eso, debemos asegurarnos de que nuestras funciones de carga de archivos puedan manejar de manera segura la validación de extensiones.

Aunque la lista blanca de extensiones es siempre más segura, como vimos anteriormente, se recomienda usar ambas, listando en blanco las extensiones permitidas y en negro las extensiones peligrosas. De esta manera, la lista negra evitará la carga de scripts maliciosos si la lista blanca se omite (por ejemplo, `shell.php.jpg`). El siguiente ejemplo muestra cómo se puede hacer esto con una aplicación web PHP, pero el mismo concepto se puede aplicar a otros frameworks:

```php
$fileName = basename($_FILES["uploadFile"]["name"]);

// blacklist test
if (preg_match('/^.+\.ph(p|ps|ar|tml)/', $fileName)) {
    echo "Only images are allowed";
    die();
}

// whitelist test
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

Vemos que con la extensión en la lista negra, la aplicación web verifica `si la extensión existe en cualquier parte del nombre del archivo`, mientras que con la lista blanca, la aplicación web verifica `si el nombre del archivo termina con la extensión`. Además, también debemos aplicar la validación de archivos tanto en el back-end como en el front-end. Incluso si la validación del front-end puede ser fácilmente omitida, reduce las posibilidades de que los usuarios carguen archivos no deseados, lo que podría desencadenar un mecanismo de defensa y enviarnos una falsa alerta.

---

## Content Validation

Como también aprendimos en este módulo, la validación de extensiones no es suficiente, ya que también debemos validar el contenido del archivo. No podemos validar uno sin el otro y siempre debemos validar tanto la extensión del archivo como su contenido. Además, siempre debemos asegurarnos de que la extensión del archivo coincida con el contenido del archivo.

El siguiente ejemplo nos muestra cómo podemos validar la extensión del archivo mediante una lista blanca, y validar tanto la firma del archivo como el encabezado HTTP Content-Type, asegurando que ambos coincidan con nuestro tipo de archivo esperado:

```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

// whitelist test
if (!preg_match('/^.*\.png$/', $fileName)) {
    echo "Only PNG images are allowed";
    die();
}

// content test
foreach (array($contentType, $MIMEtype) as $type) {
    if (!in_array($type, array('image/png'))) {
        echo "Only PNG images are allowed";
        die();
    }
}
```

---

## Upload Disclosure

Otra cosa que debemos evitar hacer es divulgar el directorio de cargas o proporcionar acceso directo al archivo cargado. Siempre se recomienda ocultar el directorio de cargas a los usuarios finales y solo permitirles descargar los archivos cargados a través de una página de descarga.

Podemos escribir un script `download.php` para recuperar el archivo solicitado del directorio de cargas y luego descargar el archivo para el usuario final. De esta manera, la aplicación web oculta el directorio de cargas y evita que el usuario acceda directamente al archivo cargado. Esto puede reducir significativamente las posibilidades de acceder a un script malicioso cargado para ejecutar código.

Si utilizamos una página de descarga, debemos asegurarnos de que el script `download.php` solo otorgue acceso a los archivos propiedad de los usuarios (es decir, evitar vulnerabilidades `IDOR/LFI`) y que los usuarios no tengan acceso directo al directorio de cargas (es decir, `403 error`). Esto se puede lograr utilizando los encabezados `Content-Disposition` y `nosniff` y utilizando un encabezado `Content-Type` preciso.

Además de restringir el directorio de cargas, también debemos aleatorizar los nombres de los archivos cargados en el almacenamiento y almacenar sus nombres originales "sanitizados" en una base de datos. Cuando el script `download.php` necesita descargar un archivo, recupera su nombre original de la base de datos y lo proporciona en el momento de la descarga para el usuario. De esta manera, los usuarios no conocerán el directorio de cargas ni el nombre del archivo cargado. También podemos evitar vulnerabilidades causadas por inyecciones en los nombres de archivos, como vimos en la sección anterior.

Otra cosa que podemos hacer es almacenar los archivos cargados en un servidor o contenedor separado. Si un atacante puede obtener la ejecución de código remoto, solo comprometería el servidor de cargas, no todo el servidor de back-end. Además, los servidores web se pueden configurar para evitar que las aplicaciones web accedan a archivos fuera de sus directorios restringidos mediante configuraciones como (`open_basedir`) en PHP.

---

## Further Security

Los consejos anteriores deberían reducir significativamente las posibilidades de cargar y acceder a un archivo malicioso. Podemos tomar algunas otras medidas para asegurarnos de que el servidor de back-end no se vea comprometido si alguna de las medidas anteriores es omitida.

Una configuración crítica que podemos agregar es deshabilitar funciones específicas que pueden usarse para ejecutar comandos del sistema a través de la aplicación web. Por ejemplo, para hacerlo en PHP, podemos usar la configuración `disable_functions` en `php.ini` y agregar funciones peligrosas como `exec`, `shell_exec`, `system`, `passthru`, y algunas otras.

Otra cosa que debemos hacer es deshabilitar la visualización de cualquier error del sistema o del servidor, para evitar la divulgación de información sensible. Siempre debemos manejar los errores a nivel de la aplicación web e imprimir errores simples que expliquen el error sin divulgar detalles sensibles o específicos, como el nombre del archivo, el directorio de cargas o los errores sin procesar.

Finalmente, los siguientes son algunos otros consejos que debemos considerar para nuestras aplicaciones web:

- Limitar el tamaño del archivo
- Actualizar cualquier biblioteca utilizada
- Escanear archivos cargados en busca de malware o cadenas maliciosas
- Utilizar un Web Application Firewall (WAF) como una capa de protección secundaria

Una vez que implementemos todas las medidas de seguridad discutidas en esta sección, la aplicación web debería ser relativamente segura y no vulnerable a las amenazas comunes de carga de archivos. Cuando realicemos una prueba de penetración web, podemos usar estos puntos como una lista de verificación y proporcionar cualquier punto faltante a los desarrolladores para cubrir cualquier brecha restante.