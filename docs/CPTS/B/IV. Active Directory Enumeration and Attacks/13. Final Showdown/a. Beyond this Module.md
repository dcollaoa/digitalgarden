## Status Update

Al final de las evaluaciones de habilidades, proporcionamos suficiente acceso y resultados de enumeración a nuestros pentesters senior para completar sus acciones de seguimiento y cumplir con todos los objetivos de evaluación. Demostrar nuestras habilidades ha mostrado al líder del equipo que ahora somos capaces de realizar acciones para más evaluaciones futuras relacionadas con entornos de Active Directory. Pronto nos estará proporcionando más tareas.

---

## Real World

Como Penetration Tester, uno podría esperar que las tareas proporcionadas en este módulo sean parte de nuestros deberes diarios. Tener una comprensión profunda de AD y lo que podemos obtener de él (en términos de acceso y enumeración) es esencial para cumplir con los deberes del rol. Nuestras acciones a menudo pueden influir en las acciones de nuestros compañeros de equipo y testers senior si estamos trabajando en una evaluación como equipo. Esas acciones podrían incluir:

- Aprovechar las confianzas entre dominios para infiltrarse en otros dominios
- Métodos de persistencia
- Command and Control dentro del dominio para evaluaciones que tienen ventanas de tiempo más largas

Con las empresas modernas moviéndose hacia entornos híbridos y en la nube, entender las bases dentro de AD y cómo abusar de ellas será extremadamente útil al intentar pivotar hacia estos nuevos tipos de redes. Si alguno de los conceptos, terminología o acciones discutidas en este módulo fue un poco desafiante o confuso, considera regresar y revisar el módulo [Introduction To Active Directory](https://academy.hackthebox.com/course/preview/introduction-to-active-directory). Contiene un análisis profundo de todo lo relacionado con AD y ayuda a establecer una base de conocimiento necesaria para entender Active Directory.

---

## What's Next?

Revisa el módulo [Active Directory BloodHound](https://academy.hackthebox.com/course/preview/active-directory-bloodhound) para entender mejor cómo funciona BloodHound. También revisa los módulos [Active Directory LDAP](https://academy.hackthebox.com/course/preview/active-directory-ldap) y [Active Directory PowerView](https://academy.hackthebox.com/course/preview/active-directory-powerview). El módulo [Cracking Passwords with Hashcat](https://academy.hackthebox.com/course/preview/cracking-passwords-with-hashcat) también puede ayudar a mejorar nuestra comprensión de las acciones que tomamos en las secciones de Kerberoasting y Password Spraying.

---

## More AD Learning Opportunities

La plataforma principal de Hack The Box tiene muchos objetivos para aprender y practicar la enumeración y ataques de AD. El [AD Track](https://www.hackthebox.com/home/tracks/4) en la plataforma principal de HTB es un excelente recurso para practicar. Los `Tracks` son listas seleccionadas de máquinas y desafíos para que los usuarios trabajen y dominen un tema en particular. El AD Track contiene cajas de diversas dificultades con varios vectores de ataque. Incluso si no puedes resolver estas cajas por tu cuenta, sigue siendo valioso trabajar con ellas utilizando una guía o video, o simplemente viendo el video de la caja por Ippsec. Cuanto más te expongas a estos temas, más cómodos y naturales se volverán la enumeración y muchos ataques. Las cajas a continuación son excelentes para practicar las habilidades aprendidas en este módulo.

### Boxes To Pwn

- [Forest](https://www.youtube.com/watch?v=H9FcE_FMZio)
- [Active](https://www.youtube.com/watch?v=jUc1J31DNdw)
- [Reel](https://youtu.be/ob9SgtFm6_g)
- [Mantis](https://youtu.be/VVZZgqIyD0Q)
- [Blackfield](https://youtu.be/IfCysW0Od8w)
- [Monteverde](https://youtu.be/HTJjPZvOtJ4)

Ippsec ha grabado videos explicando los caminos a través de muchas de estas cajas y más. Como recurso, [Ippsec's site](https://ippsec.rocks/?#) es un gran recurso para buscar videos y write-ups relacionados con muchos temas diferentes. Revisa sus videos y write-ups si te quedas atascado o quieres una excelente introducción sobre Active Directory y deseas ver cómo funcionan algunas de las herramientas.

---

### ProLabs

`Pro Labs` son grandes redes corporativas simuladas que enseñan habilidades aplicables a compromisos de pruebas de penetración en la vida real. El `Dante` Pro Lab es un excelente lugar para comenzar con varios vectores y algo de exposición a AD. El `Offshore` Pro Lab es un laboratorio de nivel avanzado que contiene una gran cantidad de oportunidades para practicar la enumeración y ataques de AD.

- [Dante](https://app.hackthebox.com/prolabs/overview/dante) Pro Lab
- [Offshore](https://app.hackthebox.com/prolabs/overview/offshore) Pro Lab

Dirígete [HERE](https://app.hackthebox.com/prolabs) para ver todos los Pro Labs que HTB tiene para ofrecer.

### Endgames

Para un desafío extremo que puede llevarte un tiempo superar, revisa el [Ascension](https://app.hackthebox.com/endgames/ascension) Endgame. Este endgame presenta dos dominios AD diferentes y tiene muchas oportunidades para practicar nuestras habilidades de enumeración y ataque de AD.

![text](https://academy.hackthebox.com/storage/modules/143/endgame.png)

### Great Videos to Check Out

[Six Degrees of Domain Admin](https://youtu.be/wP8ZCczC1OU) de `DEFCON 24` es una excelente introducción a BloodHound.  
[Designing AD DACL Backdoors](https://youtu.be/_nGpZ1ydzS8) por Will Schroeder y Andy Robbins es una joya si no lo has visto. [Kicking The Guard Dog of Hades](https://www.youtube.com/watch?v=PUyhlN-E5MU) es uno de los lanzamientos originales para Kerberoasting y es una gran vista. En [Kerberoasting 101](https://youtu.be/Jaa2LmZaNeU), Tim Medin hace un excelente trabajo desglosando el ataque de Kerberoasting y cómo realizarlo.

Hay muchos más, pero construir una lista aquí tomaría toda una sección adicional. Los videos anteriores son un excelente comienzo para avanzar en tu conocimiento de AD.

### Writers and Blogs To Follow

Entre el `Discord` de HTB, los foros y `blogs`, hay muchos write-ups sobresalientes para ayudar a avanzar tus habilidades en el camino. Uno a seguir sería [0xdf's walkthroughs](https://0xdf.gitlab.io/tags.html#active-directory). Estos también son un gran recurso para entender cómo puede verse un `attack path` de Active Directory en el mundo real. `0xdf` escribe sobre mucho más, y su blog es un excelente recurso. La lista a continuación contiene enlaces a otros autores y blogs que creemos que hacen un gran trabajo discutiendo temas de seguridad de AD y mucho más.

[SpecterOps](https://posts.specterops.io/) tiene un blog interesante donde hablan sobre AD, `BloodHound`, Command and Control, y mucho más.  
[Harmj0y](https://blog.harmj0y.net/category/activedirectory/) escribe bastante sobre AD, entre otras cosas también. Es alguien a quien deberías seguir si estás buscando trabajar en esta industria.  
[AD Security Blog](https://adsecurity.org/?author=2) por Sean Metcalf es una caja de tesoros llena de contenido impresionante, todo relacionado con AD y seguridad. Es una lectura obligada si te enfocas en Active Directory.  
[Shenaniganslabs](https://shenaniganslabs.io/) es un gran grupo de investigadores de seguridad que discuten muchos temas diferentes en el ámbito de la seguridad. Estos pueden incluir nuevas vulnerabilidades hasta TTPs de Threat Actors.  
[Dirk-jan Mollema](https://dirkjanm.io/) también tiene un gran blog documentando sus aventuras con la seguridad de AD, Azure, protocolos, vulnerabilidades, Python, etc.  
[The DFIR Report](https://thedfirreport.com/) es mantenido por un equipo talentoso de Blue Teamers/creadores de contenido de Infosec que comparten sus hallazgos de incidentes de intrusión recientes con un detalle increíble. Muchos de sus posts muestran ataques de AD y los artefactos que los atacantes dejan atrás.

---

## Closing Thoughts

Absorber todo lo que podamos sobre la seguridad de Active Directory y familiarizarnos con las TTPs utilizadas por diferentes equipos y actores de amenazas nos llevará lejos. [MITRE's Enterprise Attack Matrix](https://attack.mitre.org/matrices/enterprise/windows/) es un excelente lugar para investigar ataques y sus correspondientes herramientas y defensas. AD es un tema vasto y llevará tiempo dominarlo. Nuevos vectores de vulnerabilidad y ataques PoC se están lanzando frecuentemente. Este tema no va a desaparecer, así que utiliza los recursos disponibles para mantenerte a la vanguardia y mantener las redes activamente seguras. Una comprensión fundamental de AD y las herramientas en torno al campo, tanto como un penetration tester o defensor, nos mantendrá actualizados. Cuanto más entendamos la imagen completa, más poderosos seremos como atacantes y defensores, y más valor podremos proporcionar a nuestros clientes y las empresas para las que trabajamos. Mejorar la seguridad es nuestro enfoque, pero nada dice que no podamos divertirnos mientras lo hacemos.

Gracias por seguir esta aventura, ¡y sigue aprendiendo!

**TreyCraf7**