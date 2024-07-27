El tercer y último tipo de XSS es otro tipo `Non-Persistent` llamado `DOM-based XSS`. Mientras que `reflected XSS` envía los datos de entrada al servidor back-end a través de solicitudes HTTP, el DOM XSS se procesa completamente en el lado del cliente a través de JavaScript. El DOM XSS ocurre cuando se utiliza JavaScript para cambiar el origen de la página a través del `Document Object Model (DOM)`.

Podemos ejecutar el servidor a continuación para ver un ejemplo de una aplicación web vulnerable a DOM XSS. Podemos intentar agregar un ítem `test`, y vemos que la aplicación web es similar a las aplicaciones web `To-Do List` que usamos anteriormente:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/103/xss_dom_1.jpg)

Sin embargo, si abrimos la pestaña `Network` en las herramientas de desarrollador de Firefox, y volvemos a agregar el ítem `test`, notaríamos que no se están realizando solicitudes HTTP:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/103/xss_dom_network.jpg)

Vemos que el parámetro de entrada en la URL está utilizando un hashtag `#` para el ítem que agregamos, lo que significa que este es un parámetro del lado del cliente que se procesa completamente en el navegador. Esto indica que la entrada se está procesando en el lado del cliente a través de JavaScript y nunca llega al back-end; por lo tanto, es un `DOM-based XSS`.

Además, si miramos el origen de la página presionando [`CTRL+U`], notaremos que nuestra cadena `test` no se encuentra por ninguna parte. Esto se debe a que el código JavaScript está actualizando la página cuando hacemos clic en el botón `Add`, que es después de que el navegador recupera el origen de la página, por lo tanto, el origen base de la página no mostrará nuestra entrada, y si actualizamos la página, no se conservará (es decir, `Non-Persistent`). Aún podemos ver el origen de la página renderizada con la herramienta de Inspector Web haciendo clic en [`CTRL+SHIFT+C`]:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/103/xss_dom_inspector.jpg)

---

## Source & Sink

Para entender mejor la naturaleza de la vulnerabilidad DOM-based XSS, debemos entender el concepto de `Source` y `Sink` del objeto mostrado en la página. El `Source` es el objeto JavaScript que toma la entrada del usuario, y puede ser cualquier parámetro de entrada como un parámetro de URL o un campo de entrada, como vimos anteriormente.

Por otro lado, el `Sink` es la función que escribe la entrada del usuario en un objeto DOM en la página. Si la función `Sink` no desinfecta adecuadamente la entrada del usuario, sería vulnerable a un ataque XSS. Algunas de las funciones JavaScript comúnmente utilizadas para escribir en objetos DOM son:

- `document.write()`
- `DOM.innerHTML`
- `DOM.outerHTML`

Además, algunas de las funciones de la biblioteca `jQuery` que escriben en objetos DOM son:

- `add()`
- `after()`
- `append()`

Si una función `Sink` escribe la entrada exacta sin ninguna desinfección (como las funciones anteriores), y no se utilizaron otros medios de desinfección, entonces sabemos que la página debería ser vulnerable a XSS.

Podemos mirar el código fuente de la aplicación web `To-Do`, y verificar `script.js`, y veremos que el `Source` se está tomando del parámetro `task=`:


```javascript
var pos = document.URL.indexOf("task=");
var task = document.URL.substring(pos + 5, document.URL.length);
```

Justo debajo de estas líneas, vemos que la página usa la función `innerHTML` para escribir la variable `task` en el DOM `todo`:


```javascript
document.getElementById("todo").innerHTML = "<b>Next Task:</b> " + decodeURIComponent(task);
```

Entonces, podemos ver que podemos controlar la entrada, y la salida no se está desinfectando, por lo que esta página debería ser vulnerable a DOM XSS.

---

## DOM Attacks

Si probamos el payload XSS que hemos estado usando anteriormente, veremos que no se ejecutará. Esto se debe a que la función `innerHTML` no permite el uso de etiquetas `<script>` dentro de ella como una característica de seguridad. Sin embargo, hay muchos otros payloads XSS que podemos usar que no contienen etiquetas `<script>`, como el siguiente payload XSS:


```html
<img src="" onerror=alert(window.origin)>
```

La línea anterior crea un nuevo objeto de imagen HTML, que tiene un atributo `onerror` que puede ejecutar código JavaScript cuando no se encuentra la imagen. Entonces, como proporcionamos un enlace de imagen vacío (`""`), nuestro código debería ejecutarse siempre sin tener que usar etiquetas `<script>`:

`http://SERVER_IP:PORT/#task=<img src=`

![](https://academy.hackthebox.com/storage/modules/103/xss_dom_alert.jpg)

Para apuntar a un usuario con esta vulnerabilidad DOM XSS, podemos copiar nuevamente la URL del navegador y compartirla con ellos, y una vez que la visiten, el código JavaScript debería ejecutarse. Ambos payloads son de los más básicos de XSS. Hay muchas instancias en las que podemos necesitar usar varios payloads dependiendo de la seguridad de la aplicación web y del navegador, que discutiremos en la siguiente sección.