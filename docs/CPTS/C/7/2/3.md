Muchas aplicaciones web populares están desarrolladas en PHP, junto con varias aplicaciones web personalizadas construidas con diferentes frameworks PHP, como Laravel o Symfony. Si identificamos una vulnerabilidad LFI en aplicaciones web PHP, entonces podemos utilizar diferentes [PHP Wrappers](https://www.php.net/manual/en/wrappers.php.php) para poder extender nuestra explotación LFI, e incluso potencialmente alcanzar la ejecución remota de código.

Los PHP Wrappers nos permiten acceder a diferentes flujos de E/S a nivel de aplicación, como entrada/salida estándar, descriptores de archivos y flujos de memoria. Esto tiene muchos usos para los desarrolladores PHP. Sin embargo, como penetration testers web, podemos utilizar estos wrappers para extender nuestros ataques de explotación y poder leer archivos de código fuente PHP o incluso ejecutar comandos del sistema. Esto no solo es beneficioso con ataques LFI, sino también con otros ataques web como XXE, como se cubre en el módulo [Web Attacks](https://academy.hackthebox.com/module/details/134).

En esta sección, veremos cómo se utilizan los filtros básicos de PHP para leer el código fuente PHP, y en la siguiente sección, veremos cómo diferentes PHP wrappers pueden ayudarnos a obtener la ejecución remota de código a través de vulnerabilidades LFI.

---

## Input Filters

[PHP Filters](https://www.php.net/manual/en/filters.php) son un tipo de PHP wrappers, donde podemos pasar diferentes tipos de entrada y hacer que se filtren mediante el filtro que especifiquemos. Para usar los flujos de PHP wrapper, podemos usar el esquema `php://` en nuestra cadena, y podemos acceder al PHP filter wrapper con `php://filter/`.

El wrapper `filter` tiene varios parámetros, pero los principales que necesitamos para nuestro ataque son `resource` y `read`. El parámetro `resource` es requerido para los wrappers de filtro, y con él podemos especificar el flujo al que nos gustaría aplicar el filtro (por ejemplo, un archivo local), mientras que el parámetro `read` puede aplicar diferentes filtros en el recurso de entrada, por lo que podemos usarlo para especificar qué filtro queremos aplicar en nuestro recurso.

Hay cuatro tipos diferentes de filtros disponibles para su uso, que son [String Filters](https://www.php.net/manual/en/filters.string.php), [Conversion Filters](https://www.php.net/manual/en/filters.convert.php), [Compression Filters](https://www.php.net/manual/en/filters.compression.php), y [Encryption Filters](https://www.php.net/manual/en/filters.encryption.php). Puedes leer más sobre cada filtro en su enlace respectivo, pero el filtro que es útil para ataques LFI es el filtro `convert.base64-encode`, bajo Conversion Filters.

---

## Fuzzing for PHP Files

El primer paso sería fuzzear para diferentes páginas PHP disponibles con una herramienta como `ffuf` o `gobuster`, como se cubre en el módulo [Attacking Web Applications with Ffuf](https://academy.hackthebox.com/module/details/54):

```r
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php

...SNIP...

index                   [Status: 200, Size: 2652, Words: 690, Lines: 64]
config                  [Status: 302, Size: 0, Words: 1, Lines: 1]
```

**Tip:** A diferencia del uso normal de aplicaciones web, no estamos restringidos a páginas con código de respuesta HTTP 200, ya que tenemos acceso a la inclusión de archivos locales, por lo que deberíamos estar escaneando para todos los códigos, incluyendo `301`, `302` y `403` páginas, y deberíamos poder leer su código fuente también.

Incluso después de leer las fuentes de cualquier archivo identificado, podemos escanearlos para otros archivos PHP referenciados y luego leer esos también, hasta que podamos capturar la mayor parte del código fuente de la aplicación web o tener una imagen precisa de lo que hace. También es posible comenzar leyendo `index.php` y escanearlo para más referencias, pero fuzzear para archivos PHP puede revelar algunos archivos que de otro modo no se encontrarían de esa manera.

---

## Standard PHP Inclusion

En secciones anteriores, si intentaste incluir cualquier archivo PHP a través de LFI, habrías notado que el archivo PHP incluido se ejecuta y finalmente se renderiza como una página HTML normal. Por ejemplo, intentemos incluir la página `config.php` (extensión `.php` añadida por la aplicación web):

![](https://academy.hackthebox.com/storage/modules/23/lfi_config_failed.png)

Como podemos ver, obtenemos un resultado vacío en lugar de nuestra cadena LFI, ya que `config.php` probablemente solo configura la aplicación web y no renderiza ningún output HTML.

Esto puede ser útil en ciertos casos, como acceder a páginas PHP locales a las que no tenemos acceso (es decir, SSRF), pero en la mayoría de los casos, estaríamos más interesados en leer el código fuente PHP a través de LFI, ya que los códigos fuente tienden a revelar información importante sobre la aplicación web. Aquí es donde el filtro `base64` de PHP es útil, ya que podemos usarlo para codificar en base64 el archivo PHP, y luego obtendríamos el código fuente codificado en lugar de que se ejecute y se renderice. Esto es especialmente útil para casos donde estamos lidiando con LFI con extensiones PHP añadidas, porque podemos estar restringidos a incluir solo archivos PHP, como se discutió en la sección anterior.

**Note:** Lo mismo se aplica a los lenguajes de aplicaciones web que no sean PHP, siempre que la función vulnerable pueda ejecutar archivos. De lo contrario, obtendríamos directamente el código fuente y no necesitaríamos usar filtros/funciones adicionales para leer el código fuente. Consulta la tabla de funciones en la sección 1 para ver qué funciones tienen qué privilegios.

---

## Source Code Disclosure

Una vez que tengamos una lista de archivos PHP potenciales que queremos leer, podemos comenzar a revelar sus fuentes con el filtro `base64` de PHP. Intentemos leer el código fuente de `config.php` usando el filtro base64, especificando `convert.base64-encode` para el parámetro `read` y `config` para el parámetro `resource`, como sigue:

```r
php://filter/read=convert.base64-encode/resource=config
```

![](https://academy.hackthebox.com/storage/modules/23/lfi_config_wrapper.png)

**Note:** Dejamos intencionalmente el archivo de recurso al final de nuestra cadena, ya que la extensión `.php` se añade automáticamente al final de nuestra cadena de entrada, lo que haría que el recurso que especificamos sea `config.php`.

Como podemos ver, a diferencia de nuestro intento con LFI regular, usar el filtro base64 devolvió una cadena codificada en lugar del resultado vacío que vimos anteriormente. Ahora podemos decodificar esta cadena para obtener el contenido del código fuente de `config.php`, como sigue:

```r
echo 'PD9waHAK...SNIP...KICB9Ciov' | base64 -d

...SNIP...

if ($_SERVER['REQUEST_METHOD'] == 'GET' && realpath(__FILE__) == realpath($_SERVER['SCRIPT_FILENAME'])) {
  header('HTTP/1.0 403 Forbidden', TRUE, 403);
  die(header('location: /index.php'));
}

...SNIP...
```

**Tip:** Al copiar la cadena codificada en base64, asegúrate de copiar la cadena completa o no se decodificará por completo. Puedes ver el código fuente de la página para asegurarte de copiar la cadena completa.

Ahora podemos investigar este archivo en busca de información sensible como credenciales o claves de bases de datos y comenzar a identificar referencias adicionales y luego revelar sus fuentes.