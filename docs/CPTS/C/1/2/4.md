Podemos querer aplicar ciertas modificaciones a todas las solicitudes HTTP salientes o a todas las respuestas HTTP entrantes en ciertas situaciones. En estos casos, podemos utilizar modificaciones automáticas basadas en reglas que establezcamos, de modo que las herramientas de proxy web las apliquen automáticamente.

---

## Automatic Request Modification

Comencemos con un ejemplo de modificación automática de solicitudes. Podemos elegir coincidir cualquier texto dentro de nuestras solicitudes, ya sea en el encabezado o en el cuerpo de la solicitud, y luego reemplazarlos con un texto diferente. Para el propósito de esta demostración, reemplacemos nuestro `User-Agent` con `HackTheBox Agent 1.0`, lo cual puede ser útil en casos donde estamos lidiando con filtros que bloquean ciertos User-Agents.

### Burp Match and Replace

Podemos ir a (`Proxy>Options>Match and Replace`) y hacer clic en `Add` en Burp. Como muestra la captura de pantalla a continuación, configuraremos las siguientes opciones:

![Burp Match Replace](https://academy.hackthebox.com/storage/modules/110/burp_match_replace_user_agent_1.jpg)

| `Type`: `Request header`                      | Dado que el cambio que queremos hacer será en el encabezado de la solicitud y no en su cuerpo.                      |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `Match`: `^User-Agent.*$`                     | El patrón regex que coincide con toda la línea que contiene `User-Agent`.                                            |
| `Replace`: `User-Agent: HackTheBox Agent 1.0` | Este es el valor que reemplazará la línea que coincidió con el patrón anterior.                                      |
| `Regex match`: True                           | No sabemos la cadena exacta del User-Agent que queremos reemplazar, así que utilizaremos regex para coincidir con cualquier valor que coincida con el patrón especificado anteriormente. |

Una vez que ingresamos las opciones anteriores y hacemos clic en `Ok`, nuestra nueva opción de Match and Replace se agregará y habilitará automáticamente, comenzando a reemplazar el encabezado `User-Agent` en nuestras solicitudes con nuestro nuevo User-Agent. Podemos verificarlo visitando cualquier sitio web usando el navegador preconfigurado de Burp y revisando la solicitud interceptada. Veremos que nuestro User-Agent ha sido reemplazado automáticamente:

![Burp Match Replace](https://academy.hackthebox.com/storage/modules/110/burp_match_replace_user_agent_2.jpg)

### ZAP Replacer

ZAP tiene una función similar llamada `Replacer`, a la que podemos acceder presionando [`CTRL+R`] o haciendo clic en `Replacer` en el menú de opciones de ZAP. Es bastante similar a lo que hicimos anteriormente, por lo que podemos hacer clic en `Add` y agregar las mismas opciones que usamos antes:

![ZAP Match Replace](https://academy.hackthebox.com/storage/modules/110/zap_match_replace_user_agent_1.jpg)

- `Description`: `HTB User-Agent`.
- `Match Type`: `Request Header (will add if not present)`.
- `Match String`: `User-Agent`. Podemos seleccionar el encabezado que queremos del menú desplegable, y ZAP reemplazará su valor.
- `Replacement String`: `HackTheBox Agent 1.0`.
- `Enable`: True.

ZAP también tiene la opción `Request Header String` que podemos usar con un patrón Regex. `Prueba usar esta opción con los mismos valores que usamos para Burp para ver cómo funciona`.

ZAP también proporciona la opción de configurar los `Initiators`, a los que podemos acceder haciendo clic en la otra pestaña en la ventana que se muestra arriba. Los Initiators nos permiten seleccionar dónde se aplicará nuestra opción de `Replacer`. Mantendremos la opción predeterminada de `Apply to all HTTP(S) messages` para aplicarlo en todas partes.

Ahora podemos habilitar la intercepción de solicitudes presionando [`CTRL+B`], y luego visitar cualquier página en el navegador preconfigurado de ZAP:

![ZAP Match Replace](https://academy.hackthebox.com/storage/modules/110/zap_match_replace_user_agent_2.jpg)

---

## Automatic Response Modification

El mismo concepto puede usarse con las respuestas HTTP también. En la sección anterior, puede haber notado que cuando interceptamos la respuesta, las modificaciones que hicimos al campo `IP` eran temporales y no se aplicaban cuando actualizábamos la página a menos que interceptáramos la respuesta y las agregáramos nuevamente. Para resolver esto, podemos automatizar la modificación de respuestas de manera similar a lo que hicimos antes para habilitar automáticamente cualquier carácter en el campo `IP` para una inyección de comandos más fácil.

Volvamos a (`Proxy>Options>Match and Replace`) en Burp para agregar otra regla. Esta vez usaremos el tipo de `Response body`, ya que el cambio que queremos hacer existe en el cuerpo de la respuesta y no en sus encabezados. En este caso, no necesitamos usar regex ya que conocemos la cadena exacta que queremos reemplazar, aunque es posible usar regex para hacer lo mismo si preferimos.

![Burp Match Replace](https://academy.hackthebox.com/storage/modules/110/burp_match_replace_response_1.jpg)

- `Type`: `Response body`.
- `Match`: `type="number"`.
- `Replace`: `type="text"`.
- `Regex match`: False.

Intenta agregar otra regla para cambiar `maxlength="3"` a `maxlength="100"`.

Ahora, una vez que actualicemos la página con [`CTRL+SHIFT+R`], veremos que podemos agregar cualquier entrada al campo de entrada, y esto debería persistir entre actualizaciones de página también:

![Burp Match Replace](https://academy.hackthebox.com/storage/modules/110/burp_match_replace_response_2.jpg)

Ahora podemos hacer clic en `Ping`, y nuestra inyección de comandos debería funcionar sin interceptar y modificar la solicitud.

Ejercicio 1: Intenta aplicar las mismas reglas con ZAP Replacer. Puedes hacer clic en la pestaña de abajo para mostrar las opciones correctas.

Cambiar el tipo de entrada a texto:
- `Match Type`: `Response Body String`.
- `Match Regex`: `False`.
- `Match String`: `type="number"`.
- `Replacement String`: `type="text"`.
- `Enable`: `True`.

Cambiar la longitud máxima a 100:
- `Match Type`: `Response Body String`.
- `Match Regex`: `False`.
- `Match String`: `maxlength="3"`.
- `Replacement String`: `maxlength="100"`.
- `Enable`: `True`.

Ejercicio 2: Intenta agregar una regla que agregue automáticamente `;ls;` cuando hagamos clic en `Ping`, coincidiendo y reemplazando el cuerpo de la solicitud del `Ping`.