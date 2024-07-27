A medida que modificamos y enviamos solicitudes HTTP personalizadas, es posible que tengamos que realizar varios tipos de codificación y decodificación para interactuar correctamente con el servidor web. Ambas herramientas tienen codificadores integrados que pueden ayudarnos a codificar y decodificar rápidamente varios tipos de texto.

---

## URL Encoding

Es esencial asegurarse de que los datos de nuestra solicitud estén codificados en URL y que los encabezados de nuestra solicitud estén correctamente configurados. De lo contrario, podríamos obtener un error del servidor en la respuesta. Por eso, la codificación y decodificación de datos se vuelve esencial a medida que modificamos y repetimos las solicitudes web. Algunos de los caracteres clave que necesitamos codificar son:

- `Spaces`: Pueden indicar el final de los datos de la solicitud si no están codificados
- `&`: De otro modo, se interpreta como un delimitador de parámetros
- `#`: De otro modo, se interpreta como un identificador de fragmentos

Para codificar en URL el texto en Burp Repeater, podemos seleccionar ese texto y hacer clic derecho sobre él, luego seleccionar (`Convert Selection>URL>URL encode key characters`), o seleccionando el texto y presionando [`CTRL+U`]. Burp también admite la codificación en URL mientras escribimos si hacemos clic derecho y habilitamos esa opción, lo que codificará todo nuestro texto mientras lo escribimos. Por otro lado, ZAP debería codificar automáticamente en URL todos los datos de nuestra solicitud en segundo plano antes de enviar la solicitud, aunque es posible que no lo veamos explícitamente.

Existen otros tipos de codificación en URL, como `Full URL-Encoding` o `Unicode URL` encoding, que también pueden ser útiles para solicitudes con muchos caracteres especiales.

---

## Decoding

Si bien la codificación en URL es clave para las solicitudes HTTP, no es el único tipo de codificación que encontraremos. Es muy común que las aplicaciones web codifiquen sus datos, por lo que debemos ser capaces de decodificar rápidamente esos datos para examinar el texto original. Por otro lado, los servidores back-end pueden esperar que los datos estén codificados en un formato particular o con un codificador específico, por lo que necesitamos poder codificar rápidamente nuestros datos antes de enviarlos.

A continuación, se muestran algunos de los otros tipos de codificadores compatibles con ambas herramientas:

- HTML
- Unicode
- Base64
- ASCII hex

Para acceder al codificador completo en Burp, podemos ir a la pestaña `Decoder`. En ZAP, podemos usar el `Encoder/Decoder/Hash` presionando [`CTRL+E`]. Con estos codificadores, podemos ingresar cualquier texto y hacer que se codifique o decodifique rápidamente. Por ejemplo, quizás nos encontramos con la siguiente cookie que está codificada en base64 y necesitamos decodificarla: `eyJ1c2VybmFtZSI6Imd1ZXN0IiwgImlzX2FkbWluIjpmYWxzZX0=`

Podemos ingresar la cadena anterior en Burp Decoder y seleccionar `Decode as > Base64`, y obtendremos el valor decodificado:

![Burp B64 Decode](https://academy.hackthebox.com/storage/modules/110/burp_b64_decode.jpg)

En las versiones recientes de Burp, también podemos usar la herramienta `Burp Inspector` para realizar codificación y decodificación (entre otras cosas), que se puede encontrar en varios lugares como `Burp Proxy` o `Burp Repeater`:

![Burp Inspector](https://academy.hackthebox.com/storage/modules/110/burp_inspector.jpg)

En ZAP, podemos usar la herramienta `Encoder/Decoder/Hash`, que decodificará automáticamente las cadenas utilizando varios decodificadores en la pestaña `Decode`: ![ZAP B64 Decode](https://academy.hackthebox.com/storage/modules/110/zap_b64_decode.jpg)

Consejo: Podemos crear pestañas personalizadas en el `Encoder/Decoder/Hash` de ZAP con el botón "Add New Tab", y luego podemos agregar cualquier tipo de codificador/decodificador que queramos que se muestre en el texto. Intenta crear tu propia pestaña con algunos codificadores/decodificadores.

---

## Encoding

Como podemos ver, el texto contiene el valor `{"username":"guest", "is_admin":false}`. Entonces, si estuviéramos realizando una prueba de penetración en una aplicación web y encontramos que la cookie contiene este valor, podríamos querer probar modificarlo para ver si cambia nuestros privilegios de usuario. Entonces, podemos copiar el valor anterior, cambiar `guest` a `admin` y `false` a `true`, y tratar de codificarlo nuevamente usando su método de codificación original (`base64`):

![Burp B64 Encode](https://academy.hackthebox.com/storage/modules/110/burp_b64_encode.jpg)

![ZAP B64 Encode](https://academy.hackthebox.com/storage/modules/110/zap_b64_encode.jpg)

Consejo: La salida del `Burp Decoder` se puede codificar/decodificar directamente con un codificador diferente. Selecciona el nuevo método de codificación en el panel de salida en la parte inferior, y se codificará/decodificará nuevamente. En ZAP, podemos copiar el texto de salida y pegarlo en el campo de entrada superior.

Luego podemos copiar la cadena codificada en base64 y usarla con nuestra solicitud en `Burp Repeater` o `ZAP Request Editor`. El mismo concepto se puede utilizar para codificar y decodificar varios tipos de texto codificado para realizar pruebas de penetración web efectivas sin utilizar otras herramientas para hacer la codificación.