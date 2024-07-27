Una característica esencial de las herramientas de proxy web son sus web scanners. Burp Suite viene con `Burp Scanner`, un potente escáner para varios tipos de vulnerabilidades web, que utiliza un `Crawler` para construir la estructura del sitio web y un `Scanner` para escaneos pasivos y activos.

Burp Scanner es una característica exclusiva de la versión Pro y no está disponible en la versión gratuita Community de Burp Suite. Sin embargo, dado el amplio alcance que cubre Burp Scanner y las características avanzadas que incluye, lo convierte en una herramienta a nivel empresarial, y como tal, se espera que sea una función de pago.

---

## Target Scope

Para iniciar un escaneo en Burp Suite, tenemos las siguientes opciones:

1. Iniciar un escaneo en una solicitud específica desde Proxy History
2. Iniciar un nuevo escaneo en un conjunto de objetivos
3. Iniciar un escaneo en elementos dentro del alcance

Para iniciar un escaneo en una solicitud específica desde Proxy History, podemos hacer clic derecho sobre ella una vez que la ubiquemos en el historial y luego seleccionar `Scan` para poder configurar el escaneo antes de ejecutarlo, o seleccionar `Passive/Active Scan` para iniciar rápidamente un escaneo con las configuraciones predeterminadas:

![Scan Request](https://academy.hackthebox.com/storage/modules/110/burp_scan_request.jpg)

También podemos hacer clic en el botón `New Scan` en la pestaña `Dashboard`, lo que abrirá la ventana de configuración `New Scan` para configurar un escaneo en un conjunto de objetivos personalizados. En lugar de crear un escaneo personalizado desde cero, veamos cómo podemos utilizar el alcance para definir correctamente lo que se incluye/excluye de nuestros escaneos utilizando el `Target Scope`. El `Target Scope` puede ser utilizado con todas las características de Burp para definir un conjunto personalizado de objetivos que serán procesados. Burp también nos permite limitar Burp a elementos dentro del alcance para ahorrar recursos al ignorar cualquier URL fuera del alcance.

Nota: Escanearemos la aplicación web del ejercicio que se encuentra al final de la próxima sección. Si obtienes una licencia para usar Burp Pro, puedes iniciar el objetivo al final de la próxima sección y seguir aquí.

Si vamos a (`Target>Site map`), mostrará una lista de todos los directorios y archivos que Burp ha detectado en varias solicitudes que pasaron por su proxy:

![Site Map](https://academy.hackthebox.com/storage/modules/110/burp_site_map_before.jpg)

Para agregar un elemento a nuestro alcance, podemos hacer clic derecho sobre él y seleccionar `Add to scope`:

![Add to Scope](https://academy.hackthebox.com/storage/modules/110/burp_add_to_scope.jpg)

Nota: Cuando agregues el primer elemento a tu alcance, Burp te dará la opción de restringir sus características solo a elementos dentro del alcance e ignorar cualquier elemento fuera del alcance.

También puede ser necesario excluir algunos elementos del alcance si escanearlos puede ser peligroso o puede finalizar nuestra sesión, como una función de cierre de sesión. Para excluir un elemento de nuestro alcance, podemos hacer clic derecho sobre cualquier elemento dentro del alcance y seleccionar `Remove from scope`. Finalmente, podemos ir a (`Target>Scope`) para ver los detalles de nuestro alcance. Aquí, también podemos agregar/eliminar otros elementos y utilizar el control avanzado del alcance para especificar patrones regex que se incluirán/excluirán.

![Target Scope](https://academy.hackthebox.com/storage/modules/110/burp_target_scope.jpg)

---

## Crawler

Una vez que tengamos nuestro alcance listo, podemos ir a la pestaña `Dashboard` y hacer clic en `New Scan` para configurar nuestro escaneo, que se rellenará automáticamente con nuestros elementos dentro del alcance:

![New Scan](https://academy.hackthebox.com/storage/modules/110/burp_new_scan.jpg)

Vemos que Burp nos da dos opciones de escaneo: `Crawl and Audit` y `Crawl`. Un Web Crawler navega por un sitio web accediendo a cualquier enlace que encuentre en sus páginas, accediendo a cualquier formulario y examinando cualquier solicitud que haga para construir un mapa completo del sitio web. Al final, Burp Scanner nos presenta un mapa del objetivo, mostrando todos los datos accesibles públicamente en un solo lugar. Si seleccionamos `Crawl and Audit`, Burp ejecutará su escáner después de su Crawler (como veremos más adelante).

Nota: Un escaneo de Crawl solo sigue y mapea enlaces encontrados en la página que especificamos y cualquier página encontrada en ella. No realiza un escaneo de fuzzing para identificar páginas que nunca son referenciadas, como lo harían dirbuster o ffuf. Esto se puede hacer con Burp Intruder o Content Discovery, y luego agregarse al alcance, si es necesario.

Seleccionemos `Crawl` como inicio y vayamos a la pestaña `Scan configuration` para configurar nuestro escaneo. Desde aquí, podemos elegir hacer clic en `New` para construir una configuración personalizada, lo que nos permitiría establecer configuraciones como la velocidad de crawling o el límite, si Burp intentará iniciar sesión en cualquier formulario de inicio de sesión, y algunas otras configuraciones. Para simplificar, haremos clic en el botón `Select from library`, que nos da algunas configuraciones preestablecidas para elegir (o configuraciones personalizadas que definimos anteriormente):

![Crawl Config](https://academy.hackthebox.com/storage/modules/110/burp_crawl_config.jpg)

Seleccionaremos la opción `Crawl strategy - fastest` y continuaremos a la pestaña `Application login`. En esta pestaña, podemos agregar un conjunto de credenciales para que Burp intente en cualquier formulario/campo de inicio de sesión que encuentre. También podemos grabar un conjunto de pasos realizando un inicio de sesión manual en el navegador preconfigurado, de modo que Burp sepa qué pasos seguir para obtener una sesión de inicio de sesión. Esto puede ser esencial si ejecutamos nuestro escaneo utilizando un usuario autenticado, lo que nos permitiría cubrir partes de la aplicación web a las que Burp de otro modo no tendría acceso. Como no tenemos credenciales, lo dejaremos vacío.

Con eso, podemos hacer clic en el botón `Ok` para iniciar nuestro escaneo de Crawl. Una vez que nuestro escaneo comience, podemos ver su progreso en la pestaña `Dashboard` bajo `Tasks`:

![Crawl Config](https://academy.hackthebox.com/storage/modules/110/burp_crawl_progress.jpg)

También podemos hacer clic en el botón `View details` en las tareas para ver más detalles sobre el escaneo en curso o hacer clic en el icono de engranaje para personalizar aún más nuestras configuraciones de escaneo. Finalmente, una vez que nuestro escaneo esté completo, veremos `Crawl Finished` en la información de la tarea, y luego podemos volver a (`Target>Site map`) para ver el mapa del sitio actualizado:

![Site Map](https://academy.hackthebox.com/storage/modules/110/burp_site_map_after.jpg)

---

## Passive Scanner

Ahora que el mapa del sitio está completamente construido, podemos optar por escanear este objetivo en busca de posibles vulnerabilidades. Cuando elegimos la opción `Crawl and Audit` en el diálogo `New Scan`, Burp realizará dos tipos de escaneos: un `Passive Vulnerability Scan` y un `Active Vulnerability Scan`.

A diferencia de un escaneo activo, un escaneo pasivo no envía nuevas solicitudes, sino que analiza la fuente de las páginas ya visitadas en el objetivo/alcance y luego intenta identificar `potenciales` vulnerabilidades. Esto es muy útil para un análisis rápido de un objetivo específico, como etiquetas HTML faltantes o posibles vulnerabilidades de XSS basadas en DOM. Sin embargo, sin enviar solicitudes para probar y verificar estas vulnerabilidades, un escaneo pasivo solo puede sugerir una lista de vulnerabilidades potenciales. Aún así, el Burp Passive Scanner proporciona un nivel de `Confidence` para cada vulnerabilidad identificada, lo que también es útil para priorizar posibles vulnerabilidades.

Comencemos intentando realizar solo un escaneo pasivo. Para hacerlo, podemos nuevamente seleccionar el objetivo en (`Target>Site map`) o una solicitud en Burp Proxy History, luego hacer clic derecho sobre él y seleccionar `Do passive scan` o `Passively scan this target`. El escaneo pasivo comenzará a ejecutarse, y su tarea se puede ver en la pestaña `Dashboard` también. Una vez que el escaneo termine, podemos hacer clic en `View Details` para revisar las vulnerabilidades identificadas y luego seleccionar la pestaña `Issue activity`:

![Passive Scan](https://academy.hackthebox.com/storage/modules/110/burp_passive_scan.jpg)

Alternativamente, podemos ver todos los problemas identificados en el panel `Issue activity` en la pestaña `Dashboard`. Como podemos ver, muestra la lista de vulnerabilidades potenciales, su severidad y su confianza. Por lo general, buscamos vulnerabilidades con severidad `High` y confianza `Certain`. Sin embargo, deberíamos incluir todos los niveles de severidad y confianza para aplicaciones web muy sensibles, con un enfoque especial en severidad `High` y confianza `Confident/Firm`.

---

## Active Scanner

Finalmente, llegamos a la parte más poderosa de Burp Scanner, que es su Active Vulnerability Scanner. Un escaneo activo ejecuta un escaneo más completo que un escaneo pasivo, de la siguiente manera:

1. Comienza ejecutando un Crawl y un web fuzzer (como dirbuster/ffuf) para identificar todas las páginas posibles
    
2. Ejecuta un escaneo pasivo en todas las páginas identificadas
    
3. Verifica cada una de las vulnerabilidades identificadas en el escaneo pasivo y envía solicitudes para verificarlas
    
4.

 Realiza un análisis de JavaScript para identificar más posibles vulnerabilidades
    
5. Realiza fuzzing en varios puntos de inserción y parámetros identificados para buscar vulnerabilidades comunes como XSS, Command Injection, SQL Injection y otras vulnerabilidades web comunes
    

El Burp Active Scanner es considerado una de las mejores herramientas en ese campo y se actualiza frecuentemente para escanear nuevas vulnerabilidades web identificadas por el equipo de investigación de Burp.

Podemos iniciar un escaneo activo de manera similar a cómo comenzamos un escaneo pasivo seleccionando la opción `Do active scan` desde el menú del botón derecho en una solicitud en Burp Proxy History. Alternativamente, podemos ejecutar un escaneo en nuestro alcance con el botón `New Scan` en la pestaña `Dashboard`, lo que nos permitirá configurar nuestro escaneo activo. Esta vez, seleccionaremos la opción `Crawl and Audit`, que realizaría todos los puntos mencionados anteriormente y todo lo que hemos discutido hasta ahora.

También podemos establecer las configuraciones de Crawl (como discutimos anteriormente) y las configuraciones de Audit. Las configuraciones de Audit nos permiten seleccionar qué tipo de vulnerabilidades queremos escanear (por defecto todas), dónde el escáner intentará insertar sus payloads, además de muchas otras configuraciones útiles. Una vez más, podemos seleccionar una configuración preestablecida con el botón `Select from library`. Para nuestra prueba, como estamos interesados en vulnerabilidades `High` que pueden permitirnos ganar control sobre el servidor backend, seleccionaremos la opción `Audit checks - critical issues only`. Finalmente, podemos agregar detalles de inicio de sesión, como vimos anteriormente con las configuraciones de Crawl.

Una vez que seleccionemos nuestras configuraciones, podemos hacer clic en el botón `Ok` para iniciar el escaneo, y la tarea del escaneo activo debería agregarse en el panel `Tasks` en la pestaña `Dashboard`:

![Active Scan](https://academy.hackthebox.com/storage/modules/110/burp_active_scan.jpg)

El escaneo ejecutará todos los pasos mencionados anteriormente, por lo que tomará significativamente más tiempo en completarse que nuestros escaneos anteriores, dependiendo de las configuraciones que seleccionamos. Mientras el escaneo se ejecuta, podemos ver las diversas solicitudes que está haciendo haciendo clic en el botón `View details` y seleccionando la pestaña `Logger`, o yendo a la pestaña `Logger` en Burp, que muestra todas las solicitudes que pasaron por o fueron hechas por Burp:

![Logger](https://academy.hackthebox.com/storage/modules/110/burp_logger.jpg)

Una vez que el escaneo termine, podemos mirar el panel `Issue activity` en la pestaña `Dashboard` para ver y filtrar todos los problemas identificados hasta ahora. Desde el filtro sobre los resultados, seleccionemos `High` y `Certain` y veamos nuestros resultados filtrados:

![High Vulnerabilities](https://academy.hackthebox.com/storage/modules/110/burp_high_vulnerabilities.jpg)

Vemos que Burp identificó una vulnerabilidad de `OS command injection`, que está clasificada con una severidad `High` y confianza `Firm`. Como Burp está firmemente seguro de que esta severa vulnerabilidad existe, podemos leer sobre ella haciendo clic en ella y leyendo el aviso mostrado y ver la solicitud enviada y la respuesta recibida, para poder saber si la vulnerabilidad puede ser explotada o cómo representa una amenaza para el servidor web:

![Vulnerability Details](https://academy.hackthebox.com/storage/modules/110/burp_vuln_details.jpg)

---

## Reporting

Finalmente, una vez que todos nuestros escaneos estén completos y todos los problemas potenciales hayan sido identificados, podemos ir a (`Target>Site map`), hacer clic derecho en nuestro objetivo y seleccionar (`Issue>Report issues for this host`). Se nos pedirá que seleccionemos el tipo de exportación para el informe y qué información nos gustaría incluir en el informe. Una vez que exportamos el informe, podemos abrirlo en cualquier navegador web para ver sus detalles:

![Scan Report](https://academy.hackthebox.com/storage/modules/110/burp_scan_report.jpg)

Como podemos ver, el informe de Burp está muy organizado y puede personalizarse para incluir solo los problemas seleccionados por severidad/confianza. También muestra detalles de prueba de concepto sobre cómo explotar la vulnerabilidad e información sobre cómo remediarla. Estos informes pueden utilizarse como datos complementarios para los informes detallados que preparamos para nuestros clientes o los desarrolladores de la aplicación web al realizar un penetration test web, o pueden almacenarse para nuestra referencia futura. Nunca deberíamos simplemente exportar un informe de cualquier herramienta de penetración y presentarlo a un cliente como el entregable final. En cambio, los informes y datos generados por las herramientas pueden ser útiles como datos de referencia para los clientes que puedan necesitar los datos de escaneo en bruto para los esfuerzos de remediación o para importar a un panel de seguimiento.