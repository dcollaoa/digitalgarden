ZAP también viene con un Web Scanner similar a Burp Scanner. ZAP Scanner es capaz de construir mapas del sitio utilizando ZAP Spider y realizar tanto escaneos pasivos como activos para buscar varios tipos de vulnerabilidades.

---

## Spider

Comencemos con `ZAP Spider`, que es similar a la función Crawler en Burp. Para iniciar un escaneo de Spider en cualquier sitio web, podemos ubicar una solicitud en nuestra pestaña History y seleccionar (`Attack>Spider`) desde el menú del botón derecho. Otra opción es usar el HUD en el navegador preconfigurado. Una vez que visitemos la página o sitio web donde queremos iniciar nuestro escaneo de Spider, podemos hacer clic en el segundo botón en el panel derecho (`Spider Start`), lo que nos pedirá iniciar el escaneo:

![ZAP Spider](https://academy.hackthebox.com/storage/modules/110/zap_spider.jpg)

Nota: Cuando hacemos clic en el botón Spider, ZAP puede indicarnos que el sitio web actual no está en nuestro alcance, y nos pedirá agregarlo automáticamente al alcance antes de iniciar el escaneo, a lo que podemos responder 'Yes'. El Scope es el conjunto de URLs que ZAP probará si iniciamos un escaneo genérico, y puede ser personalizado por nosotros para escanear múltiples sitios web y URLs. Intenta agregar múltiples objetivos al alcance para ver cómo se ejecuta el escaneo de manera diferente.

Una vez que hagamos clic en `Start` en la ventana emergente, nuestro escaneo de Spider debería comenzar a spidering el sitio web buscando enlaces y validándolos, de manera muy similar a cómo funciona Burp Crawler. Podemos ver el progreso del escaneo de Spider tanto en el HUD en el botón `Spider` como en la interfaz principal de ZAP, que debería cambiar automáticamente a la pestaña Spider actual para mostrar el progreso y las solicitudes enviadas. Cuando nuestro escaneo esté completo, podemos verificar la pestaña Sites en la interfaz principal de ZAP, o podemos hacer clic en el primer botón en el panel derecho (`Sites Tree`), que debería mostrarnos una vista en forma de árbol expandible de todos los sitios web identificados y sus subdirectorios:

![ZAP Spider](https://academy.hackthebox.com/storage/modules/110/zap_sites.jpg)

Consejo: ZAP también tiene un tipo diferente de Spider llamado `Ajax Spider`, que se puede iniciar desde el tercer botón en el panel derecho. La diferencia entre este y el escáner normal es que Ajax Spider también intenta identificar enlaces solicitados a través de solicitudes AJAX de JavaScript, que pueden estar ejecutándose en la página incluso después de que se carga. Intenta ejecutarlo después de que el Spider normal termine su escaneo, ya que esto puede dar un mejor resultado y agregar algunos enlaces que el Spider normal puede haber omitido, aunque puede tardar un poco más en completarse.

---

## Passive Scanner

A medida que ZAP Spider se ejecuta y realiza solicitudes a varios endpoints, está ejecutando automáticamente su escáner pasivo en cada respuesta para ver si puede identificar problemas potenciales desde el código fuente, como encabezados de seguridad faltantes o vulnerabilidades de XSS basadas en DOM. Es por eso que, incluso antes de ejecutar el Active Scanner, podemos ver que el botón de alertas comienza a poblarse con algunos problemas identificados. Las alertas en el panel izquierdo nos muestran problemas identificados en la página actual que estamos visitando, mientras que el panel derecho nos muestra las alertas generales en esta aplicación web, que incluyen alertas encontradas en otras páginas:

![ZAP Spider](https://academy.hackthebox.com/storage/modules/110/zap_alerts.jpg)

También podemos verificar la pestaña `Alerts` en la interfaz principal de ZAP para ver todos los problemas identificados. Si hacemos clic en cualquier alerta, ZAP nos mostrará sus detalles y las páginas en las que se encontró:

![ZAP Spider](https://academy.hackthebox.com/storage/modules/110/zap_site_alerts.jpg)

---

## Active Scanner

Una vez que el árbol del sitio esté poblado, podemos hacer clic en el botón `Active Scan` en el panel derecho para iniciar un escaneo activo en todas las páginas identificadas. Si aún no hemos ejecutado un Spider Scan en la aplicación web, ZAP lo ejecutará automáticamente para construir un árbol del sitio como objetivo de escaneo. Una vez que el Active Scan comience, podemos ver su progreso de manera similar a como lo hicimos con el Spider Scan:

![ZAP Spider](https://academy.hackthebox.com/storage/modules/110/zap_active_scan.jpg)

El Active Scanner intentará varios tipos de ataques contra todas las páginas y parámetros HTTP identificados para identificar tantas vulnerabilidades como pueda. Es por eso que el Active Scanner tomará más tiempo en completarse. A medida que el Active Scan se ejecuta, veremos que el botón de alertas comienza a poblarse con más alertas a medida que ZAP descubre más problemas. Además, podemos verificar la interfaz principal de ZAP para obtener más detalles sobre el escaneo en curso y ver las diversas solicitudes enviadas por ZAP:

![ZAP Spider](https://academy.hackthebox.com/storage/modules/110/zap_active_scan_progress.jpg)

Una vez que el Active Scan termine, podemos ver las alertas para ver cuáles debemos seguir. Aunque todas las alertas deben ser reportadas y tomadas en consideración, las alertas `High` son las que generalmente llevan a comprometer directamente la aplicación web o el servidor backend. Si hacemos clic en el botón `High Alerts`, nos mostrará la Alerta Alta identificada:

![ZAP Spider](https://academy.hackthebox.com/storage/modules/110/zap_high_alert.jpg)

También podemos hacer clic en ella para ver más detalles y ver cómo podemos replicar y corregir esta vulnerabilidad:

![ZAP Spider](https://academy.hackthebox.com/storage/modules/110/zap_alert_details.jpg)

En la ventana de detalles de la alerta, también podemos hacer clic en la URL para ver los detalles de la solicitud y respuesta que ZAP utilizó para identificar esta vulnerabilidad, y también podemos repetir la solicitud a través de ZAP HUD o ZAP Request Editor:

![ZAP Spider](https://academy.hackthebox.com/storage/modules/110/zap_alert_evidence.jpg)

---

## Reporting

Finalmente, podemos generar un informe con todos los hallazgos identificados por ZAP a través de sus diversos escaneos. Para hacerlo, podemos seleccionar (`Report>Generate HTML Report`) desde la barra superior, lo que nos pedirá la ubicación para guardar el informe. También podemos exportar el informe en otros formatos como `XML` o `Markdown`. Una vez que generamos nuestro informe, podemos abrirlo en cualquier navegador para verlo:

![ZAP Spider](https://academy.hackthebox.com/storage/modules/110/zap_report.jpg)

Como podemos ver, el informe muestra todos los detalles identificados de manera organizada, lo que puede ser útil para mantener como un registro para varias aplicaciones web en las que ejecutamos nuestros escaneos durante un penetration test.