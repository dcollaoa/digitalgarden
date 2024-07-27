Ahora que hemos instalado y comenzado ambas herramientas, aprenderemos a usar la función más comúnmente utilizada; `Web Proxy`.

Podemos configurar estas herramientas como un proxy para cualquier aplicación, de modo que todas las solicitudes web se enruten a través de ellas para que podamos examinar manualmente qué solicitudes web está enviando y recibiendo una aplicación. Esto nos permitirá comprender mejor lo que la aplicación está haciendo en segundo plano y nos permitirá interceptar y cambiar estas solicitudes o reutilizarlas con varios cambios para ver cómo responde la aplicación.

---

## Pre-Configured Browser

Para usar las herramientas como proxies web, debemos configurar la configuración del proxy del navegador para usarlas como el proxy o usar el navegador preconfigurado. Ambas herramientas tienen un navegador preconfigurado que viene con configuraciones de proxy preconfiguradas y los certificados CA preinstalados, lo que hace que comenzar una prueba de penetración web sea muy rápido y fácil.

En Burp's (`Proxy>Intercept`), podemos hacer clic en `Open Browser`, lo que abrirá el navegador preconfigurado de Burp y automáticamente enrutará todo el tráfico web a través de Burp: ![Burp Preconfigured Browser](https://academy.hackthebox.com/storage/modules/110/burp_preconfigured_browser.jpg)

En ZAP, podemos hacer clic en el ícono del navegador Firefox al final de la barra superior y abrirá el navegador preconfigurado:

![ZAP Preconfigured Browser](https://academy.hackthebox.com/storage/modules/110/zap_preconfigured_browser.jpg)

Para nuestros usos en este módulo, usar el navegador preconfigurado debería ser suficiente.

---

## Proxy Setup

En muchos casos, es posible que deseemos usar un navegador real para pentesting, como Firefox. Para usar Firefox con nuestras herramientas de web proxy, primero debemos configurarlo para que las use como proxy. Podemos ir manualmente a las preferencias de Firefox y configurar el proxy para usar el puerto de escucha del web proxy. Tanto Burp como ZAP usan el puerto `8080` por defecto, pero podemos usar cualquier puerto disponible. Si elegimos un puerto que está en uso, el proxy no se iniciará y recibiremos un mensaje de error.

**Nota:** En caso de que queramos servir el web proxy en un puerto diferente, podemos hacerlo en Burp en (`Proxy>Options`), o en ZAP en (`Tools>Options>Local Proxies`). En ambos casos, debemos asegurarnos de que el proxy configurado en Firefox use el mismo puerto.

En lugar de cambiar manualmente el proxy, podemos utilizar la extensión de Firefox [Foxy Proxy](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/) para cambiar fácilmente y rápidamente el proxy de Firefox. Esta extensión está preinstalada en tu instancia de PwnBox y se puede instalar en tu propio navegador Firefox visitando la [Firefox Extensions Page](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/) y haciendo clic en `Add to Firefox` para instalarla.

Una vez que tenemos la extensión añadida, podemos configurar el web proxy en ella haciendo clic en su ícono en la barra superior de Firefox y luego eligiendo `options`:

![Foxyproxy Options](https://academy.hackthebox.com/storage/modules/110/foxyproxy_options.jpg)

Una vez que estamos en la página de `options`, podemos hacer clic en `add` en el panel izquierdo y luego usar `127.0.0.1` como la IP y `8080` como el puerto, y nombrarlo `Burp` o `ZAP`:

![Foxyproxy Add](https://academy.hackthebox.com/storage/modules/110/foxyproxy_add.jpg)

Nota: Esta configuración ya está añadida a Foxy Proxy en PwnBox, por lo que no tienes que hacer este paso si estás usando PwnBox.

Finalmente, podemos hacer clic en el ícono de `Foxy Proxy` y seleccionar `Burp`/`ZAP`. ![Foxyproxy Use](https://academy.hackthebox.com/storage/modules/110/foxyproxy_use.jpg)

---

## Installing CA Certificate

Otro paso importante al usar Burp Proxy/ZAP con nuestro navegador es instalar los certificados CA del web proxy. Si no hacemos este paso, es posible que algunos tráficos HTTPS no se enruten correctamente, o es posible que tengamos que hacer clic en `accept` cada vez que Firefox necesite enviar una solicitud HTTPS.

Podemos instalar el certificado de Burp una vez que seleccionamos Burp como nuestro proxy en `Foxy Proxy`, navegando a `http://burp` y descargando el certificado desde allí haciendo clic en `CA Certificate`:

![Burp cert](https://academy.hackthebox.com/storage/modules/110/burp_cert.jpg)

Para obtener el certificado de ZAP, podemos ir a (`Tools>Options>Dynamic SSL Certificate`), luego hacer clic en `Save`:

![ZAP cert](https://academy.hackthebox.com/storage/modules/110/zap_cert.jpg)

También podemos cambiar nuestro certificado generando uno nuevo con el botón `Generate`.

Una vez que tenemos nuestros certificados, podemos instalarlos en Firefox navegando a [about:preferences#privacy](about:preferences#privacy), desplazándonos hasta la parte inferior y haciendo clic en `View Certificates`:

![Cert Firefox](https://academy.hackthebox.com/storage/modules/110/firefox_cert.jpg)

Después de eso, podemos seleccionar la pestaña `Authorities` y luego hacer clic en `import` y seleccionar el certificado CA descargado:

![Import Firefox Cert](https://academy.hackthebox.com/storage/modules/110/firefox_import_cert.jpg)

Finalmente, debemos seleccionar `Trust this CA to identify websites` y `Trust this CA to identify email users`, y luego hacer clic en OK: ![Trust Firefox Cert](https://academy.hackthebox.com/storage/modules/110/firefox_trust_cert.jpg)

Una vez que instalemos el certificado y configuremos el proxy de Firefox, todo el tráfico web de Firefox comenzará a enrutarse a través de nuestro web proxy.