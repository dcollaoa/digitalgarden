El Fuzzer de ZAP se llama `ZAP Fuzzer`. Puede ser muy potente para fuzzing de varios endpoints web, aunque carece de algunas de las características proporcionadas por Burp Intruder. Sin embargo, `ZAP Fuzzer` no limita la velocidad de fuzzing, lo que lo hace mucho más útil que el Intruder gratuito de Burp.

En esta sección, intentaremos replicar lo que hicimos en la sección anterior utilizando `ZAP Fuzzer` para tener una comparación "manzanas con manzanas" y decidir cuál nos gusta más.

---

## Fuzz

Para comenzar nuestro fuzzing, visitaremos la URL del ejercicio al final de esta sección para capturar una solicitud de muestra. Como vamos a fuzzear directorios, visitemos `<http://SERVER_IP:PORT/test/>` para colocar nuestra ubicación de fuzzing en `test` más adelante. Una vez que ubiquemos nuestra solicitud en el historial del proxy, haremos clic derecho sobre ella y seleccionaremos `Attack>Fuzz`, lo que abrirá la ventana de `Fuzzer`:

![payload processing](https://academy.hackthebox.com/storage/modules/110/zap_fuzzer.jpg)

Las principales opciones que necesitamos configurar para nuestro ataque Fuzzer son:

- Fuzz Location
- Payloads
- Processors
- Options

Intentemos configurarlas para nuestro ataque de fuzzing de directorios web.

---

## Locations

El `Fuzz Location` es muy similar a `Intruder Payload Position`, donde se colocarán nuestros payloads. Para colocar nuestra ubicación en una determinada palabra, podemos seleccionarla y hacer clic en el botón `Add` en el panel derecho. Así que seleccionemos `test` y hagamos clic en `Add`:

![payload processing](https://academy.hackthebox.com/storage/modules/110/zap_fuzzer_add.jpg)

Como podemos ver, esto colocó un marcador `verde` en nuestra ubicación seleccionada y abrió la ventana de `Payloads` para que configuremos nuestros payloads de ataque.

---

## Payloads

Los payloads de ataque en el Fuzzer de ZAP son similares en concepto a los Payloads de Intruder, aunque no son tan avanzados como los de Intruder. Podemos hacer clic en el botón `Add` para agregar nuestros payloads y seleccionar entre 8 tipos de payloads diferentes. Algunos de ellos son:

- `File`: Esto nos permite seleccionar una lista de palabras de un archivo.
- `File Fuzzers`: Esto nos permite seleccionar listas de palabras de bases de datos integradas de listas de palabras.
- `Numberzz`: Genera secuencias de números con incrementos personalizados.

Una de las ventajas del Fuzzer de ZAP es tener listas de palabras integradas que podemos elegir, por lo que no tenemos que proporcionar nuestra propia lista de palabras. Se pueden instalar más bases de datos desde el ZAP Marketplace, como veremos en una sección posterior. Así que podemos seleccionar `File Fuzzers` como el `Type`, y luego seleccionaremos la primera lista de palabras de `dirbuster`:

![payload processing](https://academy.hackthebox.com/storage/modules/110/zap_fuzzer_add_payload.jpg)

Una vez que hagamos clic en el botón `Add`, nuestra lista de palabras de payload se agregará y podremos examinarla con el botón `Modify`.

---

## Processors

También podemos querer realizar algún procesamiento en cada palabra de nuestra lista de palabras de payload. Algunos de los procesadores de payload que podemos usar son:

- Base64 Decode/Encode
- MD5 Hash
- Postfix String
- Prefix String
- SHA-1/256/512 Hash
- URL Decode/Encode
- Script

Como podemos ver, tenemos una variedad de codificadores y algoritmos de hash para seleccionar. También podemos agregar una cadena personalizada antes del payload con `Prefix String` o una cadena personalizada con `Postfix String`. Finalmente, el tipo `Script` nos permite seleccionar un script personalizado que construimos y ejecutarlo en cada payload antes de usarlo en el ataque.

Seleccionaremos el procesador `URL Encode` para nuestro ejercicio para asegurarnos de que nuestro payload se codifique correctamente y evitar errores del servidor si nuestro payload contiene caracteres especiales. Podemos hacer clic en el botón `Generate Preview` para obtener una vista previa de cómo se verá nuestro payload final en la solicitud:

![payload processing](https://academy.hackthebox.com/storage/modules/110/zap_fuzzer_add_processor.jpg)

Una vez hecho esto, podemos hacer clic en `Add` para agregar el procesador y hacer clic en `Ok` en las ventanas de procesadores y payloads para cerrarlas.

---

## Options

Finalmente, podemos establecer algunas opciones para nuestros fuzzers, similar a lo que hicimos con Burp Intruder. Por ejemplo, podemos establecer los `Concurrent threads per scan` en `20`, para que nuestro escaneo se ejecute muy rápidamente:

![payload processing](https://academy.hackthebox.com/storage/modules/110/zap_fuzzer_options.jpg)

El número de hilos que configuramos puede estar limitado por la cantidad de potencia de procesamiento de la computadora que queremos usar o la cantidad de conexiones que el servidor nos permite establecer.

También podemos optar por ejecutar los payloads `Depth first`, lo que intentaría todas las palabras de la lista de palabras en una sola posición de payload antes de pasar a la siguiente (por ejemplo, probar todas las contraseñas para un solo usuario antes de hacer fuerza bruta en el siguiente usuario). También podríamos usar `Breadth first`, lo que ejecutaría cada palabra de la lista de palabras en todas las posiciones de payload antes de pasar a la siguiente palabra (por ejemplo, intentar cada contraseña para todos los usuarios antes de pasar a la siguiente contraseña).

---

## Start

Con todas nuestras opciones configuradas, finalmente podemos hacer clic en el botón `Start Fuzzer` para comenzar nuestro ataque. Una vez que nuestro ataque ha comenzado, podemos ordenar los resultados por el código `Response`, ya que solo nos interesan las respuestas con código `200`:

![payload processing](https://academy.hackthebox.com/storage/modules/110/zap_fuzzer_attack.jpg)

Como podemos ver, obtuvimos un acierto con el código `200` con el payload `skills`, lo que significa que el directorio `/skills/` existe en el servidor y es accesible. Podemos hacer clic en la solicitud en la ventana de resultados para ver sus detalles: ![payload processing](https://academy.hackthebox.com/storage/modules/110/zap_fuzzer_dir.jpg)

Podemos ver por la respuesta que esta página es accesible para nosotros. Hay otros campos que pueden indicar un acierto exitoso dependiendo del escenario del ataque, como `Size Resp. Body` que puede indicar que obtuvimos una página diferente si su tamaño es diferente al de otras respuestas, o `RTT` para ataques como `time-based SQL injections`, que se detectan por un retraso en el tiempo de respuesta del servidor.