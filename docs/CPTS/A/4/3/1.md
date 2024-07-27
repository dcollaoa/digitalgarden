Como se discutió anteriormente, el escaneo de vulnerabilidades se realiza para identificar posibles vulnerabilidades en dispositivos de red como routers, firewalls, switches, así como servidores, estaciones de trabajo y aplicaciones. El escaneo es automatizado y se enfoca en encontrar vulnerabilidades potenciales o conocidas a nivel de red o aplicación. Los `vulnerability scanners generalmente no explotan vulnerabilidades (con algunas excepciones), pero necesitan que un humano valide manualmente los problemas del escaneo` para determinar si un escaneo particular devolvió problemas reales que necesitan ser solucionados o falsos positivos que pueden ser ignorados y excluidos de futuros escaneos contra el mismo objetivo.

El escaneo de vulnerabilidades a menudo es parte de una prueba de penetración estándar, pero no son lo mismo. Un escaneo de vulnerabilidades puede ayudar a obtener una cobertura adicional durante una prueba de penetración o acelerar las pruebas del proyecto bajo limitaciones de tiempo. Una prueba de penetración real incluye mucho más que solo un escaneo.

El tipo de escaneos que se ejecutan varía de una herramienta a otra, pero la mayoría de las herramientas `ejecutan una combinación de pruebas dinámicas y estáticas`, dependiendo del objetivo y la vulnerabilidad. Una `prueba estática` determinaría una vulnerabilidad si la versión identificada de un activo en particular tiene un CVE público. Sin embargo, esto no siempre es preciso ya que se puede haber aplicado un parche o el objetivo no es específicamente vulnerable a ese CVE. Por otro lado, una `prueba dinámica` prueba payloads específicas (generalmente benignas) como credenciales débiles, inyección SQL o inyección de comandos en el objetivo (es decir, una aplicación web). Si alguna carga útil devuelve un acierto, entonces hay una buena probabilidad de que sea vulnerable.

Las organizaciones deben ejecutar tanto `escaneos no autenticados como autenticados` en un horario continuo para asegurar que los activos sean parchados a medida que se descubren nuevas vulnerabilidades y que cualquier nuevo activo agregado a la red no tenga parches faltantes u otros problemas de configuración/parcheo. El escaneo de vulnerabilidades debe integrarse en el [programa de gestión de parches](https://en.wikipedia.org/wiki/Patch_(computing)) de una organización.

`Nessus`, `Nexpose` y `Qualys` son plataformas de escaneo de vulnerabilidades bien conocidas que también proporcionan ediciones comunitarias gratuitas. También existen alternativas de código abierto como `OpenVAS`.

---

## Descripción General de Nessus

[Nessus Essentials](https://community.tenable.com/s/article/Nessus-Essentials) de Tenable es la versión gratuita del escáner de vulnerabilidades oficial Nessus. Los individuos pueden acceder a Nessus Essentials para comenzar a entender el escáner de vulnerabilidades de Tenable. La advertencia es que solo se puede usar para hasta 16 hosts. Las funciones en la versión gratuita son limitadas pero son perfectas para alguien que busca comenzar con Nessus. El escáner gratuito intentará identificar vulnerabilidades en un entorno.

![image](https://academy.hackthebox.com/storage/modules/108/Nessus_Essentials___Folders___View_Scan.png)

---

## Descripción General de OpenVAS

[OpenVAS](https://www.openvas.org/) de Greenbone Networks es un escáner de vulnerabilidades de código abierto disponible públicamente. OpenVAS puede realizar escaneos de red, incluyendo pruebas autenticadas y no autenticadas.

![image](https://academy.hackthebox.com/storage/modules/108/openvas/dashboard.png)

---

## Next Steps

Ahora que hemos definido términos clave, discutido tipos de evaluación, puntuación de vulnerabilidades y divulgación, y proporcionado una descripción general de las herramientas de escaneo de vulnerabilidades Nessus y OpenVAS, es hora de familiarizarnos con estas herramientas en acción. A continuación, exploraremos cómo configurar y ejecutar escaneos de vulnerabilidades utilizando Nessus y OpenVAS para identificar posibles riesgos y mejorar la seguridad de nuestros sistemas y redes.