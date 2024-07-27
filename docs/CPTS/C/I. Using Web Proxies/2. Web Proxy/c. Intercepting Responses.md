En algunas instancias, puede que necesitemos interceptar las respuestas HTTP del servidor antes de que lleguen al navegador. Esto puede ser útil cuando queremos cambiar cómo se ve una página web específica, como habilitar ciertos campos deshabilitados o mostrar ciertos campos ocultos, lo cual puede ayudarnos en nuestras actividades de penetration testing.

Así que, veamos cómo podemos lograr eso con el ejercicio que probamos en la sección anterior.

En nuestro ejercicio anterior, el campo `IP` solo nos permitía ingresar valores numéricos. Si interceptamos la respuesta antes de que llegue a nuestro navegador, podemos editarla para aceptar cualquier valor, lo que nos permitiría ingresar el payload que usamos la última vez directamente.

---

## Burp

En Burp, podemos habilitar la interceptación de respuestas yendo a (`Proxy>Options`) y habilitando `Intercept Response` bajo `Intercept Server Responses`:

![Burp Enable Response Int](https://academy.hackthebox.com/storage/modules/110/response_interception_enable.jpg)

Después de eso, podemos habilitar la interceptación de solicitudes una vez más y actualizar la página con [`CTRL+SHIFT+R`] en nuestro navegador (para forzar una actualización completa). Cuando volvamos a Burp, deberíamos ver la solicitud interceptada, y podemos hacer clic en `forward`. Una vez que reenviemos la solicitud, veremos nuestra respuesta interceptada:

![Burp Intercept Response](https://academy.hackthebox.com/storage/modules/110/response_intercept_response_1_1.jpg)

Intentemos cambiar el `type="number"` en la línea 27 a `type="text"`, lo que debería permitirnos escribir cualquier valor que queramos. También cambiaremos el `maxlength="3"` a `maxlength="100"` para poder ingresar entradas más largas:

```html
<input type="text" id="ip" name="ip" min="1" max="255" maxlength="100"
    oninput="javascript: if (this.value.length > this.maxLength) this.value = this.value.slice(0, this.maxLength);"
    required>
```

Ahora, una vez que hagamos clic en `forward` nuevamente, podemos volver a Firefox para examinar la respuesta editada:

![Burp Intercept Response](https://academy.hackthebox.com/storage/modules/110/response_intercept_response_2.jpg)

Como podemos ver, pudimos cambiar la forma en que la página se renderiza en el navegador y ahora podemos ingresar cualquier valor que queramos. Podemos usar la misma técnica para habilitar de manera persistente cualquier botón HTML deshabilitado modificando su código HTML.

Ejercicio: Intenta usar el payload que usamos la última vez directamente en el navegador, para probar cómo la interceptación de respuestas puede facilitar el penetration testing de aplicaciones web.

---

## ZAP

Intentemos ver cómo podemos hacer lo mismo con ZAP. Como vimos en la sección anterior, cuando nuestras solicitudes son interceptadas por ZAP, podemos hacer clic en `Step`, y enviará la solicitud e interceptará automáticamente la respuesta:

![ZAP Intercept Response](https://academy.hackthebox.com/storage/modules/110/zap_response_intercept_response.jpg)

Una vez que realicemos los mismos cambios que hicimos anteriormente y hagamos clic en `Continue`, veremos que también podemos usar cualquier valor de entrada:

![ZAP Edit Response](https://academy.hackthebox.com/storage/modules/110/ZAP_edit_response.jpg)

Sin embargo, ZAP HUD también tiene otra característica poderosa que puede ayudarnos en casos como este. Aunque en muchas instancias podemos necesitar interceptar la respuesta para hacer cambios personalizados, si todo lo que queríamos era habilitar campos de entrada deshabilitados o mostrar campos de entrada ocultos, entonces podemos hacer clic en el tercer botón a la izquierda (el ícono de la bombilla), y habilitará/mostrará estos campos sin que tengamos que interceptar la respuesta o actualizar la página.

Por ejemplo, la siguiente aplicación web tenía el campo de entrada `IP` deshabilitado:

![ZAP Disabled Field](https://academy.hackthebox.com/storage/modules/110/ZAP_disabled_field.jpg)

En estos casos, podemos hacer clic en el botón `Show/Enable`, y habilitará el botón para nosotros, y podemos interactuar con él para agregar nuestra entrada:

![ZAP Enable Field](https://academy.hackthebox.com/storage/modules/110/ZAP_enable_field.jpg)

Podemos usar esta característica de manera similar para mostrar todos los campos o botones ocultos. Burp también tiene una característica similar, que podemos habilitar bajo `Proxy>Options>Response Modification`, y luego seleccionar una de las opciones, como `Unhide hidden form fields`.

Otra característica similar es el botón `Comments`, que indicará las posiciones donde hay comentarios HTML que usualmente solo son visibles en el código fuente. Podemos hacer clic en el botón `+` en el panel izquierdo y seleccionar `Comments` para agregar el botón `Comments`, y una vez que hagamos clic en él, los indicadores de `Comments` deberían mostrarse. Por ejemplo, la captura de pantalla a continuación muestra un indicador para una posición que tiene un comentario, y al pasar el cursor sobre él muestra el contenido del comentario:

![ZAP Show Comments](https://academy.hackthebox.com/storage/modules/110/ZAP_show_comments.jpg)

Poder modificar cómo se ve la página web facilita mucho el penetration testing de aplicaciones web en ciertos escenarios, en lugar de tener que enviar nuestra entrada a través de una solicitud interceptada. A continuación, veremos cómo podemos automatizar este proceso para modificar nuestros cambios en la respuesta automáticamente y no tener que seguir interceptando y cambiando las respuestas manualmente.