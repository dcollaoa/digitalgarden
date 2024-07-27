There are two types of `Non-Persistent XSS` vulnerabilities: `Reflected XSS`, which gets processed by the back-end server, and `DOM-based XSS`, which is completely processed on the client-side and never reaches the back-end server. Unlike Persistent XSS, `Non-Persistent XSS` vulnerabilities are temporary and are not persistent through page refreshes. Hence, our attacks only affect the targeted user and will not affect other users who visit the page.

`Reflected XSS` vulnerabilities occur when our input reaches the back-end server and gets returned to us without being filtered or sanitized. There are many cases in which our entire input might get returned to us, like error messages or confirmation messages. In these cases, we may attempt using XSS payloads to see whether they execute. However, as these are usually temporary messages, once we move from the page, they would not execute again, and hence they are `Non-Persistent`.

We can start the server below to practice on a web page vulnerable to a Reflected XSS vulnerability. It is a similar `To-Do List` app to the one we practiced with in the previous section. We can try adding any `test` string to see how it's handled:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/103/xss_reflected_1.jpg)

As we can see, we get `Task 'test' could not be added.`, which includes our input `test` as part of the error message. If our input was not filtered or sanitized, the page might be vulnerable to XSS. We can try the same XSS payload we used in the previous section and click `Add`:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/103/xss_reflected_2.jpg)

Once we click `Add`, we get the alert pop-up:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/103/xss_stored_xss_alert.jpg)

In this case, we see that the error message now says `Task '' could not be added.`. Since our payload is wrapped with a `<script>` tag, it does not get rendered by the browser, so we get empty single quotes `''` instead. We can once again view the page source to confirm that the error message includes our XSS payload:


```r
<div></div><ul class="list-unstyled" id="todo"><div style="padding-left:25px">Task '<script>alert(window.origin)</script>' could not be added.</div></ul>
```

As we can see, the single quotes indeed contain our XSS payload `'<script>alert(window.origin)</script>'`.

If we visit the `Reflected` page again, the error message no longer appears, and our XSS payload is not executed, which means that this XSS vulnerability is indeed `Non-Persistent`.

`But if the XSS vulnerability is Non-Persistent, how would we target victims with it?`

This depends on which HTTP request is used to send our input to the server. We can check this through the Firefox `Developer Tools` by clicking [`CTRL+I`] and selecting the `Network` tab. Then, we can put our `test` payload again and click `Add` to send it:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/103/xss_reflected_network.jpg)

As we can see, the first row shows that our request was a `GET` request. `GET` request sends their parameters and data as part of the URL. So, `to target a user, we can send them a URL containing our payload`. To get the URL, we can copy the URL from the URL bar in Firefox after sending our XSS payload, or we can right-click on the `GET` request in the `Network` tab and select `Copy>Copy URL`. Once the victim visits this URL, the XSS payload would execute:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/103/xss_stored_xss_alert.jpg)Existen dos tipos de vulnerabilidades `Non-Persistent XSS`: `Reflected XSS`, que es procesado por el servidor back-end, y `DOM-based XSS`, que es completamente procesado en el cliente y nunca llega al servidor back-end. A diferencia del Persistent XSS, las vulnerabilidades `Non-Persistent XSS` son temporales y no persisten a través de las actualizaciones de la página. Por lo tanto, nuestros ataques solo afectan al usuario objetivo y no afectan a otros usuarios que visiten la página.

Las vulnerabilidades `Reflected XSS` ocurren cuando nuestra entrada llega al servidor back-end y se nos devuelve sin ser filtrada o saneada. Hay muchos casos en los que nuestra entrada completa podría devolverse, como mensajes de error o mensajes de confirmación. En estos casos, podemos intentar usar payloads de XSS para ver si se ejecutan. Sin embargo, como estos suelen ser mensajes temporales, una vez que nos movemos de la página, no se ejecutarían de nuevo, por lo que son `Non-Persistent`.

Podemos iniciar el servidor a continuación para practicar en una página web vulnerable a una vulnerabilidad Reflected XSS. Es una app similar a `To-Do List` con la que practicamos en la sección anterior. Podemos intentar agregar cualquier string `test` para ver cómo se maneja:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/103/xss_reflected_1.jpg)

Como podemos ver, obtenemos `Task 'test' could not be added.`, que incluye nuestra entrada `test` como parte del mensaje de error. Si nuestra entrada no fue filtrada o saneada, la página podría ser vulnerable a XSS. Podemos intentar el mismo payload XSS que usamos en la sección anterior y hacer clic en `Add`:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/103/xss_reflected_2.jpg)

Una vez que hacemos clic en `Add`, obtenemos el pop-up de alerta:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/103/xss_stored_xss_alert.jpg)

En este caso, vemos que el mensaje de error ahora dice `Task '' could not be added.`. Dado que nuestro payload está envuelto con una etiqueta `<script>`, no es renderizado por el navegador, por lo que obtenemos comillas simples vacías `''`. Podemos ver nuevamente el código fuente de la página para confirmar que el mensaje de error incluye nuestro payload XSS:


```r
<div></div><ul class="list-unstyled" id="todo"><div style="padding-left:25px">Task '<script>alert(window.origin)</script>' could not be added.</div></ul>
```

Como podemos ver, las comillas simples contienen nuestro payload XSS `'<script>alert(window.origin)</script>'`.

Si visitamos nuevamente la página `Reflected`, el mensaje de error ya no aparece y nuestro payload XSS no se ejecuta, lo que significa que esta vulnerabilidad XSS es realmente `Non-Persistent`.

`Pero si la vulnerabilidad XSS es Non-Persistent, ¿cómo podríamos apuntar a las víctimas con ella?`

Esto depende de qué solicitud HTTP se utiliza para enviar nuestra entrada al servidor. Podemos verificar esto a través de las `Developer Tools` de Firefox haciendo clic en [`CTRL+I`] y seleccionando la pestaña `Network`. Luego, podemos poner nuestro payload `test` nuevamente y hacer clic en `Add` para enviarlo:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/103/xss_reflected_network.jpg)

Como podemos ver, la primera fila muestra que nuestra solicitud fue una solicitud `GET`. Las solicitudes `GET` envían sus parámetros y datos como parte de la URL. Entonces, `para apuntar a un usuario, podemos enviarles una URL que contenga nuestro payload`. Para obtener la URL, podemos copiar la URL de la barra de URL en Firefox después de enviar nuestro payload XSS, o podemos hacer clic derecho en la solicitud `GET` en la pestaña `Network` y seleccionar `Copy>Copy URL`. Una vez que la víctima visite esta URL, el payload XSS se ejecutará:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/103/xss_stored_xss_alert.jpg)