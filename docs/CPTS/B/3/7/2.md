## Real World

Como Penetration Tester, se puede esperar que las tareas realizadas en este módulo sean tareas cotidianas asignadas durante nuestras funciones diarias. A veces bajo la guía y supervisión directa, a veces no, dependiendo de nuestro nivel de habilidad. Tener una comprensión profunda de `Pivoting`, `Tunneling`, `Port Forwarding`, `Lateral Movement` y las `herramientas/técnicas` necesarias para realizar estas acciones es esencial para cumplir nuestra misión. Nuestras acciones pueden y probablemente influirán en las acciones de nuestros compañeros de equipo y testers más experimentados, ya que pueden basar sus próximos pasos en nuestros resultados si estamos trabajando conjuntamente en una evaluación.

Esas acciones podrían incluir:

- Utilizar túneles y puntos de pivote que configuramos para realizar `exploitation` adicional y `lateral movement`.
- Implantar mecanismos de `persistence` en cada subred para asegurar el acceso continuo.
- `Command & Control` dentro y a través de entornos empresariales.
- Utilizar nuestros túneles para `security control bypass` al traer herramientas y exfiltrar datos.

Tener un firme conocimiento de los conceptos de red y cómo funcionan el pivoting y el tunneling es una habilidad central para cualquier pentester o defensor. Si alguno de los conceptos, la terminología o las acciones discutidas en este módulo fue un poco desafiante o confuso, considera volver y revisar el módulo [Introduction to Networking](https://academy.hackthebox.com/course/preview/introduction-to-networking). Proporciona una base sólida en conceptos de red como subnetting, tecnologías de capa 2-3, herramientas y mecanismos de direccionamiento comunes.

---

## What's Next?

Para comprender mejor Active Directory y cómo usar nuestras nuevas habilidades en pentesting empresarial, consulta los módulos [Introduction to Active Directory](https://academy.hackthebox.com/course/preview/introduction-to-active-directory) y [Active Directory Enumeration and Attacks](https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks). El módulo [Shells and Payloads](https://academy.hackthebox.com/course/preview/shells--payloads) puede ayudarnos a mejorar nuestras habilidades de explotación y darnos una mejor visión de las payloads que creamos y usamos en una red objetivo. Si las partes de shells y pivotes de servidor web en este módulo fueron difíciles, revisar los módulos [Introduction to Web Applications](https://academy.hackthebox.com/course/preview/introduction-to-web-applications) y [File Upload Attacks](https://academy.hackthebox.com/course/preview/file-upload-attacks) puede aclarar esos temas para nosotros. No descartes el fantástico desafío que es [Starting Point](https://app.hackthebox.com/starting-point). Estos pueden ser excelentes formas de practicar las habilidades que aprendes en este módulo y otros módulos en Academy con desafíos en la plataforma principal de Hack The Box.

![Scrolling Through Starting Point](https://academy.hackthebox.com/storage/modules/158/startingpoint.gif)

---

## Pivoting & Tunneling Into Other Learning Opportunities

La plataforma principal de Hack The Box tiene muchos objetivos para aprender y practicar las habilidades aprendidas en este módulo. La pista [Containers and Pivoting](https://app.hackthebox.com/tracks/Containers-and-Pivoting) puede proporcionarte un verdadero desafío para poner a prueba tus habilidades de pivoting. Las `Tracks` son listas curadas de máquinas y desafíos para que los usuarios trabajen y dominen un tema particular. Cada pista contiene cajas de diversas dificultades con varios vectores de ataque. Incluso si no puedes resolver estas cajas por tu cuenta, vale la pena trabajarlas con una guía o video o simplemente viendo un video de la caja por Ippsec. Cuanto más te expongas a estos temas, más cómodo te sentirás. Las cajas a continuación son excelentes para practicar las habilidades aprendidas en este módulo.

---

### Boxes To Pwn

- [Enterprise](https://app.hackthebox.com/machines/Enterprise) [IPPSec Walkthrough](https://youtube.com/watch?v=NWVJ2b0D1r8&t=2400)
- [Inception](https://app.hackthebox.com/machines/Inception) [IPPSec Walkthrough](https://youtube.com/watch?v=J2I-5xPgyXk&t=2330)
- [Reddish](https://app.hackthebox.com/machines/Reddish) [IPPSec Walkthrough](https://youtube.com/watch?v=Yp4oxoQIBAM&t=2466) Este host es un verdadero desafío.

![Scrolling Through HTB Boxes](https://academy.hackthebox.com/storage/modules/158/htbboxes.gif)

Ippsec ha grabado videos explicando las rutas a través de muchas de estas cajas. Como recurso, [el sitio de Ippsec](https://ippsec.rocks/?#) es una gran fuente para buscar videos y guías relacionadas con muchos temas diferentes. Consulta sus videos y guías si te quedas atascado o deseas una gran introducción al tratar con Active Directory y deseas ver cómo funcionan algunas de las herramientas.

---

### ProLabs

`Pro Labs` son grandes redes corporativas simuladas que enseñan habilidades aplicables a compromisos de penetration testing en la vida real. El Pro Lab `Dante` es un excelente lugar para practicar encadenar nuestras habilidades de pivoting junto con otros conocimientos de ataques empresariales. Los Pro Labs `Offshore` y `RastaLabs` son laboratorios de nivel intermedio que contienen una gran cantidad de oportunidades para practicar pivoting a través de redes.

- [RastaLabs](https://app.hackthebox.com/prolabs/overview/rastalabs) Pro Lab
- [Dante](https://app.hackthebox.com/prolabs/overview/dante) Pro Lab
- [Offshore](https://app.hackthebox.com/prolabs/overview/offshore) Pro Lab

Dirígete [AQUÍ](https://app.hackthebox.com/prolabs) para ver todos los Pro Labs que HTB tiene para ofrecer.

---

### Endgames

Para un desafío extremo que puede llevarte un tiempo superar, consulta los [Ascension](https://app.hackthebox.com/endgames/ascension) Endgames. Este endgame presenta dos dominios AD diferentes y tiene muchas oportunidades para practicar nuestras habilidades de enumeración y ataque de AD.

![text](https://academy.hackthebox.com/storage/modules/143/endgame.png)

---

### Writers/Educational Creators and Blogs To Follow

Entre el `Discord`, los `Foros` y los `blogs` de HTB, hay muchas guías sobresalientes para ayudar a avanzar tus habilidades en el camino. Uno a tener en cuenta sería [los walkthroughs de 0xdf](https://0xdf.gitlab.io/). Su blog es un gran recurso para ayudarnos a entender cómo las herramientas, tácticas y conceptos que estamos aprendiendo se combinan en un camino de ataque holístico. La lista a continuación contiene enlaces a otros autores y blogs que creemos que hacen un gran trabajo discutiendo temas de Seguridad de la Información.

[RastaMouse](https://rastamouse.me/) escribe contenido excelente sobre Red-Teaming, infraestructura C2, pivoting, payloads, etc. (¡Incluso creó un Pro Lab para mostrar esas cosas!)

[SpecterOps](https://posts.specterops.io/offensive-security-guide-to-ssh-tunnels-and-proxies-b525cbd4d4c6) ha escrito un excelente artículo que cubre el túnel SSH y el uso de proxies sobre una multitud de protocolos. Es una lectura obligada para cualquiera que quiera saber más sobre el tema y sería un recurso útil para tener durante un compromiso.

El [Blog de HTB](https://www.hackthebox.com/blog) es, por supuesto, un excelente lugar para leer sobre amenazas actuales, guías para TTPs populares y más.

[SANS](https://www.sans.org/webcasts/dodge-duck-dip-dive-dodge-making-the-pivot-cheat-sheet-119115/) publica mucha información relacionada con infosec y webcasts como el vinculado aquí son un gran ejemplo de eso. Esto cubrirá muchas herramientas y avenidas diferentes de Pivoting.

[Plaintext's Pivoting Workshop](https://youtu.be/B3GxYyGFYmQ) es un taller increíble que nuestro propio Academy Training Developer, Plaintext, armó para ayudar a preparar a los jugadores para el Cyber Apocalypse CTF 2022. El taller se presenta de manera atractiva y entretenida, y los espectadores se beneficiarán de él durante años. Consúltalo si tienes la oportunidad.

---

## Closing Thoughts

Felicitaciones por completar este módulo, y en HTB sabemos que has aprendido algunas nuevas habilidades para usar durante tu viaje en el mundo de la Ciberseguridad. `Pivoting, Tunneling y Port Forwarding` son conceptos fundamentales que deberían estar en la caja de herramientas de todo pentester.

Como defensor, saber cómo detectar cuando un host está comprometido y se está utilizando como punto de pivote o si el tráfico se está tunelizando a través de una ruta no estándar es crucial. Sigue practicando y mejorando tus habilidades. ¡Feliz hacking!