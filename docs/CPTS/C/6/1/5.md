Hasta ahora, deberíamos tener una buena comprensión de lo que es una vulnerabilidad XSS, los tres tipos de XSS y cómo cada tipo difiere de los otros. También deberíamos entender cómo funciona el XSS mediante la inyección de código JavaScript en el código fuente de la página del lado del cliente, ejecutando así código adicional que luego aprenderemos a utilizar a nuestro favor.

En esta sección, revisaremos varias formas de detectar vulnerabilidades XSS dentro de una aplicación web. En las vulnerabilidades de aplicaciones web (y todas las vulnerabilidades en general), detectarlas puede ser tan difícil como explotarlas. Sin embargo, dado que las vulnerabilidades XSS están muy extendidas, hay muchas herramientas que pueden ayudarnos a detectarlas e identificarlas.

---

## Automated Discovery

Casi todos los Web Application Vulnerability Scanners (como [Nessus](https://www.tenable.com/products/nessus), [Burp Pro](https://portswigger.net/burp/pro) o [ZAP](https://www.zaproxy.org/)) tienen diversas capacidades para detectar los tres tipos de vulnerabilidades XSS. Estos escáneres suelen realizar dos tipos de escaneo: un Passive Scan, que revisa el código del lado del cliente en busca de posibles vulnerabilidades basadas en DOM, y un Active Scan, que envía varios tipos de payloads para intentar desencadenar un XSS mediante la inyección de payloads en el código fuente de la página.

Aunque las herramientas pagas generalmente tienen un nivel de precisión más alto en la detección de vulnerabilidades XSS (especialmente cuando se requieren bypasses de seguridad), aún podemos encontrar herramientas de código abierto que pueden ayudarnos a identificar posibles vulnerabilidades XSS. Estas herramientas generalmente funcionan identificando campos de entrada en las páginas web, enviando varios tipos de payloads XSS y luego comparando el código fuente renderizado para ver si el mismo payload se puede encontrar en él, lo que puede indicar una inyección XSS exitosa. Aun así, esto no siempre será preciso, ya que a veces, incluso si el mismo payload fue inyectado, podría no conducir a una ejecución exitosa por diversas razones, por lo que siempre debemos verificar manualmente la inyección XSS.

Algunas de las herramientas de código abierto comunes que pueden ayudarnos en el descubrimiento de XSS son [XSS Strike](https://github.com/s0md3v/XSStrike), [Brute XSS](https://github.com/rajeshmajumdar/BruteXSS) y [XSSer](https://github.com/epsylon/xsser). Podemos probar `XSS Strike` clonándolo en nuestra VM con `git clone`:

```bash
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip install -r requirements.txt
python xsstrike.py

XSStrike v3.1.4
...SNIP...
```

Luego, podemos ejecutar el script y proporcionarle una URL con un parámetro usando `-u`. Probemos usarlo con nuestro ejemplo de `Reflected XSS` de la sección anterior:

```bash
python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test" 

        XSStrike v3.1.4

[~] Checking for DOM vulnerabilities 
[+] WAF Status: Offline 
[!] Testing parameter: task 
[!] Reflections found: 1 
[~] Analysing reflections 
[~] Generating payloads 
[!] Payloads generated: 3072 
------------------------------------------------------------
[+] Payload: <HtMl%09onPoIntERENTER+=+confirm()> 
[!] Efficiency: 100 
[!] Confidence: 10 
[?] Would you like to continue scanning? [y/N]
```

Como podemos ver, la herramienta identificó el parámetro como vulnerable a XSS desde el primer payload. `Intenta verificar el payload anterior probándolo en uno de los ejercicios previos. También puedes probar las otras herramientas y ejecutarlas en los mismos ejercicios para ver qué tan capaces son de detectar vulnerabilidades XSS.`

---

## Manual Discovery

Cuando se trata del descubrimiento manual de XSS, la dificultad de encontrar la vulnerabilidad XSS depende del nivel de seguridad de la aplicación web. Las vulnerabilidades básicas de XSS generalmente se pueden encontrar probando varios payloads XSS, pero identificar vulnerabilidades avanzadas de XSS requiere habilidades avanzadas de revisión de código.

---

### XSS Payloads

El método más básico para buscar vulnerabilidades XSS es probar manualmente varios payloads XSS contra un campo de entrada en una página web determinada. Podemos encontrar grandes listas de payloads XSS en línea, como la de [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md) o la de [PayloadBox](https://github.com/payloadbox/xss-payload-list). Luego podemos comenzar a probar estos payloads uno por uno copiando cada uno y agregándolo en nuestro formulario, y viendo si aparece un cuadro de alerta.

Nota: XSS puede inyectarse en cualquier entrada en la página HTML, lo cual no es exclusivo de los campos de entrada de HTML, sino que también puede estar en los encabezados HTTP como Cookie o User-Agent (es decir, cuando sus valores se muestran en la página).

Notarás que la mayoría de los payloads anteriores no funcionan con nuestras aplicaciones web de ejemplo, aunque estamos tratando con el tipo más básico de vulnerabilidades XSS. Esto se debe a que estos payloads están escritos para una amplia variedad de puntos de inyección (como la inyección después de una comilla simple) o están diseñados para evadir ciertas medidas de seguridad (como los filtros de sanitización). Además, tales payloads utilizan una variedad de vectores de inyección para ejecutar código JavaScript, como etiquetas básicas `<script>`, otros `HTML Attributes` como `<img>`, o incluso `CSS Style` attributes. Por eso, podemos esperar que muchos de estos payloads no funcionen en todos los casos de prueba, ya que están diseñados para funcionar con ciertos tipos de inyecciones.

Por eso, no es muy eficiente recurrir a copiar/pegar manualmente payloads XSS, ya que incluso si una aplicación web es vulnerable, puede tomarnos un tiempo identificar la vulnerabilidad, especialmente si tenemos muchos campos de entrada para probar. Por eso, puede ser más eficiente escribir nuestro propio script en Python para automatizar el envío de estos payloads y luego comparar el código fuente de la página para ver cómo se renderizaron nuestros payloads. Esto puede ayudarnos en casos avanzados donde las herramientas XSS no pueden enviar y comparar fácilmente los payloads. De esta manera, tendríamos la ventaja de personalizar nuestra herramienta para nuestra aplicación web objetivo. Sin embargo, este es un enfoque avanzado para el descubrimiento de XSS, y no forma parte del alcance de este módulo.

---

## Code Review

El método más confiable para detectar vulnerabilidades XSS es la revisión manual de código, que debe cubrir tanto el código del back-end como del front-end. Si entendemos exactamente cómo se maneja nuestra entrada hasta que llega al navegador web, podemos escribir un payload personalizado que debería funcionar con alta confianza.

En la sección anterior, vimos un ejemplo básico de revisión de código HTML al discutir la `Source` y `Sink` para vulnerabilidades XSS basadas en DOM. Esto nos dio una visión rápida de cómo funciona la revisión de código del front-end para identificar vulnerabilidades XSS, aunque en un ejemplo muy básico de front-end.

Es poco probable que encontremos vulnerabilidades XSS a través de listas de payloads o herramientas XSS para las aplicaciones web más comunes. Esto se debe a que los desarrolladores de tales aplicaciones web probablemente ejecutan su aplicación a través de herramientas de evaluación de vulnerabilidades y luego parchean cualquier vulnerabilidad identificada antes del lanzamiento. Para tales casos, la revisión manual de código puede revelar vulnerabilidades XSS no detectadas, que pueden sobrevivir a los lanzamientos públicos de aplicaciones web comunes. Estas también son técnicas avanzadas que están fuera del alcance de este módulo. Aun así, si estás interesado en aprenderlas, los módulos [Secure Coding 101: JavaScript](https://academy.hackthebox.com/course/preview/secure-coding-101-javascript) y [Whitebox Pentesting 101: Command Injection](https://academy.hackthebox.com/course/preview/whitebox-pentesting-101-command-injection) cubren a fondo este tema.