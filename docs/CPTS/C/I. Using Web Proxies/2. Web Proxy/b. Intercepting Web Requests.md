Ahora que hemos configurado nuestro proxy, podemos usarlo para interceptar y manipular varias solicitudes HTTP enviadas por la aplicación web que estamos probando. Comenzaremos aprendiendo cómo interceptar solicitudes web, cambiarlas y luego enviarlas a su destino previsto.

---

## Intercepting Requests

### Burp

En Burp, podemos navegar a la pestaña `Proxy`, y la interceptación de solicitudes debería estar activada por defecto. Si queremos activar o desactivar la interceptación de solicitudes, podemos ir a la subpestaña `Intercept` y hacer clic en el botón `Intercept is on/off` para hacerlo:

![Burp Intercept On](https://academy.hackthebox.com/storage/modules/110/burp_intercept_htb_on.jpg)

Una vez que activamos la interceptación de solicitudes, podemos iniciar el navegador preconfigurado y luego visitar nuestro sitio web objetivo después de iniciarlo desde el ejercicio al final de esta sección. Luego, cuando volvamos a Burp, veremos la solicitud interceptada esperando nuestra acción, y podemos hacer clic en `forward` para reenviar la solicitud:

![Burp Intercept Page](https://academy.hackthebox.com/storage/modules/110/burp_intercept_page.jpg)

Nota: como todo el tráfico de Firefox será interceptado en este caso, es posible que veamos otra solicitud interceptada antes de esta. Si esto sucede, haz clic en 'Forward' hasta que lleguemos a la solicitud a nuestra IP objetivo, como se muestra arriba.

### ZAP

En ZAP, la interceptación está desactivada por defecto, como lo indica el botón verde en la barra superior (verde indica que las solicitudes pueden pasar y no ser interceptadas). Podemos hacer clic en este botón para activar o desactivar la interceptación de solicitudes, o podemos usar el atajo [`CTRL+B`] para alternarla:

![ZAP Intercept On](https://academy.hackthebox.com/storage/modules/110/zap_intercept_htb_on.jpg)

Luego, podemos iniciar el navegador preconfigurado y volver a visitar la página web del ejercicio. Veremos la solicitud interceptada en el panel superior derecho, y podemos hacer clic en el paso (a la derecha del botón rojo `break`) para reenviar la solicitud:

![ZAP Intercept Page](https://academy.hackthebox.com/storage/modules/110/zap_intercept_page.jpg)

ZAP también tiene una característica poderosa llamada `Heads Up Display (HUD)`, que nos permite controlar la mayoría de las funciones principales de ZAP directamente desde el navegador preconfigurado. Podemos habilitar el `HUD` haciendo clic en su botón al final de la barra de menú superior:

![ZAP HUD On](https://academy.hackthebox.com/storage/modules/110/zap_enable_HUD.jpg)

El HUD tiene muchas funciones que cubriremos a medida que avancemos en el módulo. Para interceptar solicitudes, podemos hacer clic en el segundo botón desde la parte superior en el panel izquierdo para activar la interceptación de solicitudes:

![](https://academy.hackthebox.com/storage/modules/110/zap_hud_break.jpg)

Ahora, una vez que actualicemos la página o enviemos otra solicitud, el HUD interceptará la solicitud y nos la presentará para su acción:

![](https://academy.hackthebox.com/storage/modules/110/zap_hud_break_request.jpg)

Podemos elegir `step` para enviar la solicitud y examinar su respuesta y romper cualquier solicitud adicional, o podemos elegir `continue` y dejar que la página envíe las solicitudes restantes. El botón `step` es útil cuando queremos examinar cada paso de la funcionalidad de la página, mientras que `continue` es útil cuando solo estamos interesados en una solicitud y podemos reenviar las solicitudes restantes una vez que lleguemos a nuestra solicitud objetivo.

**Tip:** La primera vez que uses el navegador preconfigurado de ZAP, se te presentará el tutorial del HUD. Puedes considerar tomar este tutorial después de esta sección, ya que te enseñará lo básico del HUD. Incluso si no entiendes todo, las secciones siguientes deberían cubrir lo que te hayas perdido. Si no obtienes el tutorial, puedes hacer clic en el botón de configuración en la parte inferior derecha y elegir "Take the HUD tutorial".

---

## Manipulating Intercepted Requests

Una vez que interceptamos la solicitud, esta permanecerá en espera hasta que la reenviemos, como hicimos anteriormente. Podemos examinar la solicitud, manipularla para hacer cualquier cambio que queramos y luego enviarla a su destino. Esto nos ayuda a comprender mejor qué información está enviando una aplicación web en sus solicitudes y cómo puede responder a los cambios que hacemos en esa solicitud.

Hay numerosas aplicaciones para esto en Web Penetration Testing, como probar para:

1. SQL injections
2. Command injections
3. Upload bypass
4. Authentication bypass
5. XSS
6. XXE
7. Error handling
8. Deserialization

Y muchas otras posibles vulnerabilidades web, como veremos en otros módulos web en HTB Academy. Entonces, demostremos esto con un ejemplo básico para demostrar la interceptación y manipulación de solicitudes web.

Activemos nuevamente la interceptación de solicitudes en la herramienta de nuestra elección, configuremos el valor de `IP` en la página, luego hagamos clic en el botón `Ping`. Una vez que se intercepte nuestra solicitud, deberíamos obtener una solicitud HTTP similar a la siguiente:

```r
POST /ping HTTP/1.1
Host: 46.101.23.188:30820
Content-Length: 4
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://46.101.23.188:30820
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://46.101.23.188:30820/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

ip=1
```

Normalmente, solo podemos especificar números en el campo `IP` usando el navegador, ya que la página web nos impide enviar cualquier carácter no numérico usando JavaScript en el front-end. Sin embargo, con el poder de interceptar y manipular solicitudes HTTP, podemos intentar usar otros caracteres para "romper" la aplicación (romper el flujo de solicitud/respuesta manipulando el parámetro objetivo, no dañando la aplicación web objetivo). Si la aplicación web no verifica y valida las solicitudes HTTP en el back-end, es posible que podamos manipularla y explotarla.

Entonces, cambiemos el valor del parámetro `ip` de `1` a `;ls;` y veamos cómo la aplicación web maneja nuestra entrada:

![](https://academy.hackthebox.com/storage/modules/110/ping_manipulate_request.jpg)

Una vez que hagamos clic en continuar/reenviar, veremos que la respuesta cambió de la salida predeterminada de ping a la salida `ls`, lo que significa que manipulamos exitosamente la solicitud para inyectar nuestro comando:

![](https://academy.hackthebox.com/storage/modules/110/ping_inject.jpg)

Esto demuestra un ejemplo básico de cómo la interceptación y manipulación de solicitudes puede ayudar a probar aplicaciones web en busca de varias vulnerabilidades, lo cual se considera una herramienta esencial para poder probar diferentes aplicaciones web de manera efectiva.

**Nota**: Como se mencionó anteriormente, no cubriremos ataques web específicos en este módulo, sino cómo los Web Proxies pueden facilitar varios tipos de ataques. Otros módulos web en HTB Academy cubren estos tipos de ataques en profundidad.