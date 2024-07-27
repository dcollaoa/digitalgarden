Hoy en día, la mayoría de las aplicaciones web y móviles modernas funcionan conectándose continuamente a servidores back-end para enviar y recibir datos, y luego procesar estos datos en el dispositivo del usuario, como sus navegadores web o teléfonos móviles. Con la mayoría de las aplicaciones dependiendo en gran medida de los servidores back-end para procesar datos, probar y asegurar estos servidores back-end se está volviendo rápidamente más importante.

Probar solicitudes web a servidores back-end constituye la mayor parte del Web Application Penetration Testing, que incluye conceptos que se aplican tanto a aplicaciones web como móviles. Para capturar las solicitudes y el tráfico que pasa entre las aplicaciones y los servidores back-end y manipular estos tipos de solicitudes con fines de prueba, necesitamos usar `Web Proxies`.

---

## **What Are Web Proxies?**

Web proxies son herramientas especializadas que se pueden configurar entre un navegador/aplicación móvil y un servidor back-end para capturar y ver todas las solicitudes web que se envían entre ambos extremos, actuando esencialmente como herramientas man-in-the-middle (MITM). Mientras que otras aplicaciones de `Network Sniffing`, como Wireshark, operan analizando todo el tráfico local para ver qué está pasando por una red, Web Proxies trabajan principalmente con puertos web como, pero no limitados a, `HTTP/80` y `HTTPS/443`.

Web proxies se consideran entre las herramientas más esenciales para cualquier web pentester. Simplifican significativamente el proceso de captura y reproducción de solicitudes web en comparación con herramientas anteriores basadas en CLI. Una vez que un web proxy está configurado, podemos ver todas las solicitudes HTTP realizadas por una aplicación y todas las respuestas enviadas por el servidor back-end. Además, podemos interceptar una solicitud específica para modificar sus datos y ver cómo el servidor back-end las maneja, lo cual es una parte esencial de cualquier web penetration test.

---

## **Uses of Web Proxies**

Si bien el uso principal de los web proxies es capturar y reproducir solicitudes HTTP, tienen muchas otras características que permiten diferentes usos para los web proxies. La siguiente lista muestra algunas de las otras tareas para las que podemos usar web proxies:

- Web application vulnerability scanning
- Web fuzzing
- Web crawling
- Web application mapping
- Web request analysis
- Web configuration testing
- Code reviews

En este módulo, no discutiremos ningún ataque web específico, ya que otros módulos de HTB Academy cubren varios ataques web. Sin embargo, cubriremos a fondo cómo usar los web proxies y sus diversas características y mencionaremos qué tipo de ataques web requieren qué característica. Cubriremos las dos herramientas de web proxy más comunes: `Burp Suite` y `ZAP`.

---

## **Burp Suite**

[Burp Suite (Burp)](https://portswigger.net/burp) -pronunciado Burp Sweet- es el web proxy más común para web penetration testing. Tiene una excelente interfaz de usuario para sus diversas características e incluso proporciona un navegador Chromium integrado para probar aplicaciones web. Ciertas características de Burp solo están disponibles en la versión comercial `Burp Pro/Enterprise`, pero incluso la versión gratuita es una herramienta de prueba extremadamente poderosa para mantener en nuestro arsenal.

Algunas de las características `paid-only` son:

- Active web app scanner
- Fast Burp Intruder
- La capacidad de cargar ciertas Burp Extensions

La versión comunitaria `free` de Burp Suite debería ser suficiente para la mayoría de los penetration testers. Una vez que comencemos con pruebas de penetración de aplicaciones web más avanzadas, las características `pro` pueden volverse útiles. La mayoría de las características que cubriremos en este módulo están disponibles en la versión comunitaria `free` de Burp Suite, pero también mencionaremos algunas de las características `pro`, como el Active Web App Scanner.

**Tip:** Si tienes una dirección de correo electrónico educativa o empresarial, puedes solicitar una prueba gratuita de Burp Pro en este [link](https://portswigger.net/burp/pro/trial) para poder seguir algunas de las características exclusivas de Burp Pro que se muestran más adelante en este módulo.

---

## **OWASP Zed Attack Proxy (ZAP)**

[OWASP Zed Attack Proxy (ZAP)](https://www.zaproxy.org/) es otra herramienta común de web proxy para web penetration testing. ZAP es un proyecto gratuito y de código abierto iniciado por el [Open Web Application Security Project (OWASP)](https://owasp.org/) y mantenido por la comunidad, por lo que no tiene características exclusivas de pago como Burp. Ha crecido significativamente en los últimos años y está ganando rápidamente reconocimiento en el mercado como la herramienta de web proxy de código abierto líder.

Al igual que Burp, ZAP proporciona varias características básicas y avanzadas que se pueden utilizar para web pentesting. ZAP también tiene ciertas ventajas sobre Burp, que cubriremos a lo largo de este módulo. La principal ventaja de ZAP sobre Burp es ser un proyecto gratuito y de código abierto, lo que significa que no enfrentaremos ningún tipo de limitación o restricción en nuestras exploraciones que solo se levantan con una suscripción de pago. Además, con una comunidad creciente de colaboradores, ZAP está ganando muchas de las características exclusivas de pago de Burp de forma gratuita.

Al final, aprender ambas herramientas puede ser bastante similar y nos proporcionará opciones para cada situación a lo largo de un web pentest, y podemos optar por usar la que consideremos más adecuada para nuestras necesidades. En algunas instancias, puede que no veamos suficiente valor para justificar una suscripción de pago de Burp, y podemos cambiar a ZAP para tener una experiencia completamente abierta y gratuita. En otras situaciones, donde queremos una solución más madura para pentests avanzados o pentesting corporativo, puede que encontremos que el valor proporcionado por Burp Pro está justificado y cambiemos a Burp para estas características.