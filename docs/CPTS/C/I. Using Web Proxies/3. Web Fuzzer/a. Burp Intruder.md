Tanto Burp como ZAP proporcionan características adicionales aparte del proxy web predeterminado, esenciales para el penetration testing de aplicaciones web. Dos de las características extra más importantes son los `web fuzzers` y los `web scanners`. Los web fuzzers incorporados son herramientas poderosas que actúan como herramientas de fuzzing, enumeración y fuerza bruta web. Esto también puede funcionar como una alternativa para muchos de los fuzzers basados en CLI que utilizamos, como `ffuf`, `dirbuster`, `gobuster`, `wfuzz`, entre otros.

El web fuzzer de Burp se llama `Burp Intruder` y puede usarse para fuzzear páginas, directorios, subdominios, parámetros, valores de parámetros y muchas otras cosas. Aunque es mucho más avanzado que la mayoría de las herramientas de fuzzing web basadas en CLI, la versión gratuita `Burp Community` está limitada a una velocidad de 1 solicitud por segundo, lo que la hace extremadamente lenta en comparación con las herramientas de fuzzing web basadas en CLI, que generalmente pueden manejar hasta 10k solicitudes por segundo. Es por eso que solo usaríamos la versión gratuita de Burp Intruder para consultas cortas. La versión `Pro` tiene velocidad ilimitada, lo que puede competir con las herramientas de fuzzing web comunes, además de las características muy útiles de Burp Intruder. Esto lo convierte en una de las mejores herramientas de fuzzing y fuerza bruta web.

En esta sección, demostraremos los diversos usos de Burp Intruder para el fuzzing y la enumeración web.

---

## Target

Como de costumbre, iniciaremos Burp y su navegador preconfigurado y luego visitaremos la aplicación web del ejercicio al final de esta sección. Una vez que lo hagamos, podemos ir a Proxy History, localizar nuestra solicitud, hacer clic derecho sobre la solicitud y seleccionar `Send to Intruder`, o usar el atajo [`CTRL+I`] para enviarlo a `Intruder`.

Luego podemos ir a `Intruder` haciendo clic en su pestaña o con el atajo [`CTRL+SHIFT+I`], lo que nos lleva directamente a `Burp Intruder`:

![intruder_target](https://academy.hackthebox.com/storage/modules/110/burp_intruder_target.jpg)

En la primera pestaña, `Target`, vemos los detalles del objetivo que vamos a fuzzear, que se alimentan de la solicitud que enviamos a `Intruder`.

---

## Positions

La segunda pestaña, `Positions`, es donde colocamos el puntero de posición del payload, que es el punto donde las palabras de nuestra lista de palabras se colocarán y se iterarán. Demostraremos cómo fuzzear directorios web, similar a lo que hacen herramientas como `ffuf` o `gobuster`.

Para verificar si existe un directorio web, nuestro fuzzing debe estar en `GET /DIRECTORY/`, de modo que las páginas existentes devuelvan `200 OK`, de lo contrario obtendremos `404 NOT FOUND`. Por lo tanto, necesitaremos seleccionar `DIRECTORY` como la posición del payload, envolviéndolo con `§` o seleccionando la palabra `DIRECTORY` y haciendo clic en el botón `Add §`:

![intruder_position](https://academy.hackthebox.com/storage/modules/110/burp_intruder_position.jpg)

Consejo: `DIRECTORY` en este caso es el nombre del puntero, que puede ser cualquier cosa, y puede usarse para referirse a cada puntero en caso de que usemos más de una posición con diferentes listas de palabras para cada una.

Lo último que se debe seleccionar en la pestaña target es el `Attack Type`. El tipo de ataque define cuántos punteros de payload se usan y determina qué payload se asigna a qué posición. Para simplificar, nos quedaremos con el primer tipo, `Sniper`, que utiliza solo una posición. Intenta hacer clic en el `?` en la parte superior de la ventana para leer más sobre los tipos de ataque, o consulta este [enlace](https://portswigger.net/burp/documentation/desktop/tools/intruder/positions#attack-type).

Nota: Asegúrate de dejar las dos líneas adicionales al final de la solicitud, de lo contrario podríamos obtener una respuesta de error del servidor.

---

## Payloads

En la tercera pestaña, `Payloads`, podemos elegir y personalizar nuestros payloads/listas de palabras. Este payload/lista de palabras es lo que se iterará y cada elemento/línea de la misma se colocará y probará uno por uno en la Posición de Payload que elegimos anteriormente. Hay cuatro cosas principales que necesitamos configurar:

- Payload Sets
- Payload Options
- Payload Processing
- Payload Encoding

### Payload Sets

Lo primero que debemos configurar es el `Payload Set`. El conjunto de payloads identifica el número de Payload, dependiendo del tipo de ataque y el número de Payloads que utilizamos en los Punteros de Posición de Payload:

![Payload Sets](https://academy.hackthebox.com/storage/modules/110/burp_intruder_payload_set.jpg)

En este caso, solo tenemos un conjunto de Payloads, ya que elegimos el tipo de ataque `Sniper` con solo una posición de payload. Si hubiéramos elegido el tipo de ataque `Cluster Bomb`, por ejemplo, y agregado varias posiciones de payload, obtendríamos más conjuntos de payloads para elegir y seleccionar diferentes opciones para cada uno. En nuestro caso, seleccionaremos `1` para el conjunto de payloads.

A continuación, debemos seleccionar el `Payload Type`, que es el tipo de payloads/listas de palabras que usaremos. Burp proporciona una variedad de tipos de Payloads, cada uno de los cuales actúa de cierta manera. Por ejemplo:

- `Simple List`: El tipo básico y más fundamental. Proporcionamos una lista de palabras y Intruder itera sobre cada línea de la misma.
    
- `Runtime file`: Similar a `Simple List`, pero se carga línea por línea mientras se ejecuta el escaneo para evitar el uso excesivo de memoria por parte de Burp.
    
- `Character Substitution`: Nos permite especificar una lista de caracteres y sus reemplazos, y Burp Intruder prueba todas las permutaciones posibles.
    

Hay muchos otros tipos de Payloads, cada uno con sus propias opciones, y muchos de los cuales pueden construir listas de palabras personalizadas para cada ataque. Intenta hacer clic en el `?` junto a `Payload Sets`, y luego haz clic en `Payload Type` para aprender más sobre cada tipo de Payload. En nuestro caso, usaremos un `Simple List` básico.

### Payload Options

A continuación, debemos especificar las Opciones de Payload, que son diferentes para cada tipo de Payload que seleccionamos en `Payload Sets`. Para un `Simple List`, tenemos que crear o cargar una lista de palabras. Para hacerlo, podemos ingresar cada elemento manualmente haciendo clic en `Add`, lo que construiría nuestra lista de palabras sobre la marcha. La otra opción más común es hacer clic en `Load` y luego seleccionar un archivo para cargar en Burp Intruder.

Seleccionaremos `/opt/useful/SecLists/Discovery/Web-Content/common.txt` como nuestra lista de palabras. Podemos ver que Burp Intruder carga todas las líneas de nuestra lista de palabras en la tabla de Opciones de Payload:

![Payload Options](https://academy.hackthebox.com/storage/modules/110/burp_intruder_payload_wordlist.jpg)

Podemos agregar otra lista de palabras o agregar manualmente algunos elementos, y se agregarían a la misma lista de elementos. Podemos usar esto para combinar múltiples listas de palabras o crear listas de palabras personalizadas. En Burp Pro, también podemos seleccionar de una lista de listas de palabras existentes contenidas dentro de Burp eligiendo la opción del menú `Add from list`.

Consejo: En caso de que desees usar una lista de palabras muy grande, es mejor usar `Runtime file` como el tipo de Payload en lugar de `Simple List`, para que Burp Intruder no tenga que cargar toda la lista de palabras por adelantado, lo que puede limitar el uso de memoria.

### Payload Processing

Otra opción que podemos aplicar es `Payload Processing`, que nos permite determinar reglas de fuzzing sobre la lista de palabras cargada. Por ejemplo, si deseamos agregar una extensión después de nuestro elemento de payload, o si queremos filtrar la lista de palabras según criterios específicos, podemos hacerlo con el procesamiento de payload.

Intentemos agregar una regla que omita cualquier línea que comience con un `.` (como se muestra en la captura de pantalla de la lista de palabras anterior). Podemos hacerlo haciendo clic en el botón `Add` y luego seleccionando `Skip if matches regex`, lo que nos permite proporcionar un patrón de regex para los elementos que queremos omitir. Luego, podemos proporcionar un patrón de regex que coincida con las líneas que comienzan con `.` que es: `^\..*$`:

![payload processing](https://academy.hackthebox.com/storage/modules/110/burp_intruder_payload_processing_1.jpg)

Podemos ver que nuestra regla se agrega y habilita: ![payload processing](https://academy.hackthebox.com/storage/modules/110/burp_intruder_payload_processing_2.jpg)

### Payload Encoding

La cuarta y última opción que podemos aplicar es `Payload Encoding`, que nos permite habilitar o deshabilitar la codificación URL del Payload.

![payload encoding](https://academy.hackthebox.com/storage/modules/110/burp_intruder_payload_encoding.jpg)

Lo dejaremos habilitado.

---

## Options

Finalmente, podemos personalizar nuestras opciones de ataque desde la pestaña `Options`. Hay muchas opciones que podemos personalizar (o dejar en su valor predeterminado) para nuestro ataque. Por ejemplo, podemos establecer el número de `retried on failure

` y `pause before retry` en 0.

Otra opción útil es el `Grep - Match`, que nos permite marcar solicitudes específicas según sus respuestas. Como estamos haciendo fuzzing de directorios web, solo nos interesan las respuestas con el código HTTP `200 OK`. Por lo tanto, primero lo habilitaremos y luego haremos clic en `Clear` para borrar la lista actual. Después de eso, podemos escribir `200 OK` para que coincida con cualquier solicitud con esta cadena y hacer clic en `Add` para agregar la nueva regla. Finalmente, también deshabilitaremos `Exclude HTTP Headers`, ya que lo que estamos buscando está en el encabezado HTTP:

![options match](https://academy.hackthebox.com/storage/modules/110/burp_intruder_options_match.jpg)

También podemos utilizar la opción `Grep - Extract`, que es útil si las respuestas HTTP son largas y solo nos interesa una parte específica de la respuesta. Como solo estamos buscando respuestas con el código HTTP `200 OK`, independientemente de su contenido, no optaremos por esta opción.

Prueba otras opciones de `Intruder` y usa la ayuda de Burp haciendo clic en `?` junto a cada una para aprender más sobre cada opción.

Nota: También podemos usar la pestaña `Resource Pool` para especificar cuántos recursos de red utilizará Intruder, lo cual puede ser útil para ataques muy grandes. En nuestro ejemplo, lo dejaremos en sus valores predeterminados.

---

## Attack

Ahora que todo está configurado correctamente, podemos hacer clic en el botón `Start Attack` y esperar a que termine nuestro ataque. Una vez más, en la versión gratuita `Community Version`, estos ataques serían muy lentos y tomarían un tiempo considerable para listas de palabras más largas.

Lo primero que notaremos es que todas las líneas que comienzan con `.` fueron omitidas, y comenzamos directamente con las líneas posteriores:

![intruder_attack_exclude](https://academy.hackthebox.com/storage/modules/110/burp_intruder_attack_exclude.jpg)

También podemos ver la columna `200 OK`, que muestra las solicitudes que coinciden con el valor `200 OK` que especificamos en la pestaña Opciones. Podemos hacer clic en ella para ordenar por ella, de modo que tengamos los resultados coincidentes en la parte superior. De lo contrario, podemos ordenar por `status` o por `Length`. Una vez que nuestro escaneo haya terminado, vemos que obtenemos un hit `\admin`:

![intruder_attack](https://academy.hackthebox.com/storage/modules/110/burp_intruder_attack.jpg)

Ahora podemos visitar manualmente la página `<http://SERVER_IP:PORT/admin/>`, para asegurarnos de que realmente existe.

De manera similar, podemos usar `Burp Intruder` para realizar cualquier tipo de fuzzing y fuerza bruta web, incluyendo la fuerza bruta para contraseñas, o fuzzing para ciertos parámetros PHP, y así sucesivamente. Incluso podemos usar `Intruder` para realizar password spraying contra aplicaciones que usan autenticación de Active Directory (AD) como Outlook Web Access (OWA), portales SSL VPN, Remote Desktop Services (RDS), Citrix, aplicaciones web personalizadas que usan autenticación AD y más. Sin embargo, como la versión gratuita de `Intruder` está extremadamente limitada, en la próxima sección, veremos el fuzzer de ZAP y sus diversas opciones, que no tienen un nivel de pago.