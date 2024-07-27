En las secciones anteriores, logramos evadir la validación de entrada para usar una entrada no numérica y llegar a la inyección de comandos en el servidor remoto. Si queremos repetir el mismo proceso con un comando diferente, tendríamos que interceptar la solicitud nuevamente, proporcionar un payload diferente, reenviarla y finalmente revisar nuestro navegador para obtener el resultado final.

Como puedes imaginar, si hiciéramos esto para cada comando, nos tomaría una eternidad enumerar un sistema, ya que cada comando requeriría de 5 a 6 pasos para ejecutarse. Sin embargo, para tareas tan repetitivas, podemos utilizar la repetición de solicitudes para hacer este proceso significativamente más fácil.

La repetición de solicitudes nos permite reenviar cualquier solicitud web que haya pasado previamente por el proxy web. Esto nos permite realizar cambios rápidos en cualquier solicitud antes de enviarla y luego obtener la respuesta dentro de nuestras herramientas sin interceptar y modificar cada solicitud.

---

## Proxy History

Para comenzar, podemos ver el historial de solicitudes HTTP en `Burp` en (`Proxy>HTTP History`):

![Burp history tab](https://academy.hackthebox.com/storage/modules/110/burp_history_tab.jpg)

En `ZAP` HUD, podemos encontrarlo en el panel de historial inferior o en la interfaz principal de ZAP en la pestaña inferior `History` también:

![ZAP history tab](https://academy.hackthebox.com/storage/modules/110/zap_history_tab.jpg)

Ambas herramientas también proporcionan opciones de filtrado y ordenación para el historial de solicitudes, lo cual puede ser útil si lidiamos con una gran cantidad de solicitudes y queremos localizar una solicitud específica. `Prueba ver cómo funcionan los filtros en ambas herramientas.`

Nota: Ambas herramientas también mantienen un historial de WebSockets, que muestra todas las conexiones iniciadas por la aplicación web incluso después de cargarse, como actualizaciones asíncronas y obtención de datos. Los WebSockets pueden ser útiles al realizar pruebas avanzadas de penetración web y están fuera del alcance de este módulo.

Si hacemos clic en cualquier solicitud en el historial de cualquiera de las herramientas, se mostrarán sus detalles:

`Burp`: ![Burp request details](https://academy.hackthebox.com/storage/modules/110/burp_history_details.jpg)

`ZAP`: ![ZAP request details](https://academy.hackthebox.com/storage/modules/110/zap_history_details.jpg)

Consejo: Mientras que ZAP solo muestra la solicitud final/modificada que fue enviada, Burp proporciona la capacidad de examinar tanto la solicitud original como la modificada. Si una solicitud fue editada, el encabezado del panel dirá `Original Request`, y podemos hacer clic en él y seleccionar `Edited Request` para examinar la solicitud final que fue enviada.

---

## Repeating Requests

### Burp

Una vez que localicemos la solicitud que queremos repetir, podemos hacer clic en [`CTRL+R`] en Burp para enviarla a la pestaña `Repeater`, y luego podemos navegar a la pestaña `Repeater` o hacer clic en [`CTRL+SHIFT+R`] para ir directamente a ella. Una vez en `Repeater`, podemos hacer clic en `Send` para enviar la solicitud:

![Burp repeat request](https://academy.hackthebox.com/storage/modules/110/burp_repeater_request.jpg)

Consejo: También podemos hacer clic derecho en la solicitud y seleccionar `Change Request Method` para cambiar el método HTTP entre POST/GET sin tener que reescribir toda la solicitud.

### ZAP

En ZAP, una vez que localicemos nuestra solicitud, podemos hacer clic derecho en ella y seleccionar `Open/Resend with Request Editor`, lo que abrirá la ventana del editor de solicitudes y nos permitirá reenviar la solicitud con el botón `Send` para enviar nuestra solicitud: ![ZAP resend request](https://academy.hackthebox.com/storage/modules/110/zap_repeater_request.jpg)

También podemos ver el menú desplegable `Method`, que nos permite cambiar rápidamente el método de solicitud a cualquier otro método HTTP.

Consejo: Por defecto, la ventana del Editor de Solicitudes en ZAP tiene la Solicitud/Respuesta en diferentes pestañas. Puedes hacer clic en los botones de visualización para cambiar cómo están organizadas. Para coincidir con la apariencia anterior, elige las mismas opciones de visualización que se muestran en la captura de pantalla.

Podemos lograr el mismo resultado dentro del navegador preconfigurado con `ZAP HUD`. Podemos localizar la solicitud en el panel de historial inferior, y una vez que hagamos clic en ella, la ventana del `Request Editor` se mostrará, permitiéndonos reenviarla. Podemos seleccionar `Replay in Console` para obtener la respuesta en la misma ventana `HUD` o seleccionar `Replay in Browser` para ver la respuesta renderizada en el navegador:

![ZAP HUD resend](https://academy.hackthebox.com/storage/modules/110/zap_hud_resend.jpg)

Entonces, intentemos modificar nuestra solicitud y enviarla. En las tres opciones (`Burp Repeater`, `ZAP Request Editor`, y `ZAP HUD`), vemos que las solicitudes son modificables, y podemos seleccionar el texto que queremos cambiar y reemplazarlo con lo que queramos, y luego hacer clic en el botón `Send` para enviarlo nuevamente:

![Burp modify repeat](https://academy.hackthebox.com/storage/modules/110/burp_repeat_modify.jpg)

Como podemos ver, pudimos modificar fácilmente el comando y obtener instantáneamente su salida utilizando `Burp Repeater`. Intenta hacer lo mismo en `ZAP Request Editor` y `ZAP HUD` para ver cómo funcionan.

Finalmente, podemos ver en nuestra solicitud POST anterior que los datos están codificados en URL. Esta es una parte esencial del envío de solicitudes HTTP personalizadas, que discutiremos en la siguiente sección.