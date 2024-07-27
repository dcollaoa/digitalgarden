Antes de aprender cómo descubrir vulnerabilidades XSS y utilizarlas para diversos ataques, primero debemos entender los diferentes tipos de vulnerabilidades XSS y sus diferencias para saber cuál usar en cada tipo de ataque.

El primer y más crítico tipo de vulnerabilidad XSS es `Stored XSS` o `Persistent XSS`. Si nuestro payload XSS inyectado se almacena en la base de datos del back-end y se recupera al visitar la página, esto significa que nuestro ataque XSS es persistente y puede afectar a cualquier usuario que visite la página.

Esto hace que este tipo de XSS sea el más crítico, ya que afecta a una audiencia mucho más amplia, ya que cualquier usuario que visite la página sería víctima de este ataque. Además, `Stored XSS` puede no ser fácilmente eliminable, y el payload puede necesitar ser eliminado de la base de datos del back-end.

Podemos iniciar el servidor a continuación para ver y practicar un ejemplo de `Stored XSS`. Como podemos ver, la página web es una aplicación simple de `To-Do List` a la que podemos agregar elementos. Podemos intentar escribir `test` y presionar enter/return para agregar un nuevo elemento y ver cómo la página lo maneja:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/103/xss_stored_xss.jpg)

Como podemos ver, nuestra entrada se mostró en la página. Si no se aplicó ninguna sanitización o filtrado a nuestra entrada, la página podría ser vulnerable a XSS.

---

## XSS Testing Payloads

Podemos probar si la página es vulnerable a XSS con el siguiente payload básico de XSS:

```html
<script>alert(window.origin)</script>
```

Usamos este payload ya que es un método muy fácil de detectar para saber cuándo nuestro payload XSS se ha ejecutado con éxito. Supongamos que la página permite cualquier entrada y no realiza ninguna sanitización en ella. En ese caso, la alerta debería aparecer con la URL de la página en la que se está ejecutando, directamente después de que ingresemos nuestro payload o cuando actualicemos la página:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/103/xss_stored_xss_alert.jpg)

Como podemos ver, efectivamente obtuvimos la alerta, lo que significa que la página es vulnerable a XSS, ya que nuestro payload se ejecutó con éxito. Podemos confirmar esto aún más mirando el código fuente de la página haciendo clic en [`CTRL+U`] o haciendo clic derecho y seleccionando `View Page Source`, y deberíamos ver nuestro payload en el código fuente de la página:

```html
<div></div><ul class="list-unstyled" id="todo"><ul><script>alert(window.origin)</script>
</ul></ul>
```

**Tip:** Muchas aplicaciones web modernas utilizan IFrames de cross-domain para manejar la entrada del usuario, de modo que incluso si el formulario web es vulnerable a XSS, no sería una vulnerabilidad en la aplicación web principal. Por eso mostramos el valor de `window.origin` en la caja de alerta, en lugar de un valor estático como `1`. En este caso, la caja de alerta revelaría la URL en la que se está ejecutando y confirmará qué formulario es el vulnerable, en caso de que se esté utilizando un IFrame.

Dado que algunos navegadores modernos pueden bloquear la función JavaScript `alert()` en ubicaciones específicas, puede ser útil conocer algunos otros payloads básicos de XSS para verificar la existencia de XSS. Uno de esos payloads de XSS es `<plaintext>`, que detendrá la renderización del código HTML que viene después y lo mostrará como texto plano. Otro payload fácil de detectar es `<script>print()</script>` que abrirá el diálogo de impresión del navegador, lo cual es poco probable que sea bloqueado por los navegadores. Prueba usar estos payloads para ver cómo funciona cada uno. Puedes usar el botón de reinicio para eliminar cualquier payload actual.

Para ver si el payload es persistente y está almacenado en el back-end, podemos actualizar la página y ver si obtenemos la alerta nuevamente. Si lo hacemos, veríamos que seguimos obteniendo la alerta incluso a lo largo de las actualizaciones de la página, confirmando que esto es de hecho una vulnerabilidad de `Stored/Persistent XSS`. Esto no es único para nosotros, ya que cualquier usuario que visite la página activará el payload XSS y obtendrá la misma alerta.